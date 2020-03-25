###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# daemon.py                                                                   #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2020  science + computing ag                             #
#                                                                             #
# This program is free software: you can redistribute it and/or modify        #
# it under the terms of the GNU General Public License as published by        #
# the Free Software Foundation, either version 3 of the License, or (at       #
# your option) any later version.                                             #
#                                                                             #
# This program is distributed in the hope that it will be useful, but         #
# WITHOUT ANY WARRANTY; without even the implied warranty of                  #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU           #
# General Public License for more details.                                    #
#                                                                             #
# You should have received a copy of the GNU General Public License           #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       #
#                                                                             #
###############################################################################

""" The main peekaboo module, starting up and managing all the various
components. """

import errno
import gettext
import os
import sys
import grp
import pwd
import logging
import signal
import socket
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from sqlalchemy.exc import SQLAlchemyError
from peekaboo import PEEKABOO_OWL, __version__
from peekaboo.config import PeekabooConfig, PeekabooConfigParser
from peekaboo.db import PeekabooDatabase
from peekaboo.queuing import JobQueue
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.sample import SampleFactory
from peekaboo.server import PeekabooServer
from peekaboo.exceptions import PeekabooDatabaseError, \
        PeekabooConfigException, PeekabooRulesetConfigError
from peekaboo.toolbox.cuckoo import CuckooEmbed, CuckooApi


logger = logging.getLogger(__name__)


class SignalHandler():
    """ Signal handler. """
    def __init__(self):
        """ register custom signal handler """
        self.listeners = []

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGCHLD, self.signal_handler)

    def register_listener(self, listener):
        """ Register a listener object which is expected to implement a very
        simple interface: Method shut_down() is called if SIGINT or SIGTERM
        arrive, reap_children() is called if SIGCHLD arrives. Both are expected
        to defer actual handling of the condition. """
        self.listeners.append(listener)

    def signal_handler(self, sig, frame):
        """ catch signal and call appropriate methods in registered listener
        classes """
        if sig == signal.SIGINT or sig == signal.SIGTERM:
            logger.debug("SIGINT/TERM")

            # these should take serious care about being called across threads
            for listener in self.listeners:
                listener.shut_down()

        if sig == signal.SIGCHLD:
            logger.debug("SIGCHLD")
            for listener in self.listeners:
                listener.reap_children()


class PeekabooDaemonInfrastructure(object):
    """ A class that manages typical daemon infrastructure such as PID file and
    privileges. """
    def __init__(self, pid_file, sock_file, user, group):
        self.pid_file = pid_file
        self.sock_file = sock_file
        self.user = user
        self.group = group

        self.pid_file_created = False

    def init(self):
        """ Initialize daemon infrastructure. """
        self.drop_privileges()
        self.create_pid_file()
        self.check_stale_socket()

    def drop_privileges(self):
        """ Check and potentially drop privileges. """
        if os.getuid() != 0:
            return

        if not self.user:
            logger.warning('Peekaboo should not run as root. Please '
                           'configure a user to run as.')
            sys.exit(1)

        # drop privileges to user
        try:
            userdata = pwd.getpwnam(self.user)
        except KeyError as notfound:
            logger.critical('Error looking up daemon user: %s', notfound)
            sys.exit(1)

        uid = userdata[2]
        gid = userdata[3]
        userhome = userdata[5]

        gid_log = ''
        if self.group:
            try:
                gid = grp.getgrnam(self.group)[2]
            except KeyError as notfound:
                logger.critical('Error looking up daemon group: %s', notfound)
                sys.exit(1)
            gid_log = ' and group %s' % self.group

        os.initgroups(self.user, gid)
        os.setgid(gid)
        os.setuid(uid)

        grouplist = []
        for gid in os.getgroups():
            groupdata = grp.getgrgid(gid)
            grouplist.append('%s(%d)' % (groupdata[0], groupdata[2]))

        logger.info('After dropping privileges to user %s%s now running as '
                    'user %s(%d) with primary group %s(%d) and supplementary '
                    'groups %s', self.user, gid_log,
                    pwd.getpwuid(os.getuid())[0], os.getuid(),
                    grp.getgrgid(os.getgid())[0], os.getgid(),
                    ', '.join(grouplist))

        # set $HOME to the users home directory
        # (VirtualBox must access the configs)
        os.environ['HOME'] = userhome
        logger.debug('$HOME is %s', os.environ['HOME'])

    def create_pid_file(self):
        """ Check for stale old and create a new PID file. Look at the socket
        as well. """
        pid = None
        if os.path.exists(self.pid_file):
            stale = False
            try:
                with open(self.pid_file, 'r') as pidfile:
                    pid = int(pidfile.read())
            except (OSError, IOError, ValueError) as error:
                stale = True
                logger.warning('PID file exists but cannot be read, '
                               'assuming it to be stale')

            if pid is not None:
                try:
                    # ping the process to see if it exists, sends no signal
                    os.kill(pid, 0)
                except OSError as oserror:
                    # ESRCH == no such process
                    if oserror.errno == errno.ESRCH:
                        stale = True

            if not stale:
                logger.critical('Another instance of Peekaboo seems to be '
                                'running as process %d. Please check PID '
                                'file %s.', pid, self.pid_file)
                sys.exit(1)

            logger.warning('Removing stale PID file of process %d', pid)
            try:
                os.remove(self.pid_file)
            except OSError as error:
                logger.critical('Error deleting stale PID file %s: %s',
                                self.pid_file, error)
                sys.exit(1)

        # write PID file
        pid = os.getpid()
        with open(self.pid_file, "w") as pidfile:
            pidfile.write("%d\n" % pid)

        # remember that the PID file is ours - important on shutdown
        self.pid_file_created = True
        logger.debug('PID %d written to %s', pid, self.pid_file)

    def check_stale_socket(self):
        """ Check if the socket file exists already/still and if it is stale or
        actively serviced. Remove it if stale. """
        # is the socket also stale?
        if not os.path.exists(self.sock_file):
            return

        stale = False
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(self.sock_file)
            logger.debug('Someone answered on existing socket')
        except socket.error as sockerr:
            logger.debug('Existing socket connection attempt failed: %s',
                         sockerr)
            if sockerr.errno == errno.ECONNREFUSED:
                stale = True

        if not stale:
            logger.critical('Socket %s exists and seems to be serviced. '
                            'Please check for another instance running.',
                            self.sock_file)
            sys.exit(1)

        logger.warning('Removing stale socket %s', self.sock_file)
        try:
            os.remove(self.sock_file)
        except OSError as oserror:
            logger.critical('Error removing stale socket %s: %s',
                            self.sock_file, oserror)
            sys.exit(1)

    def __del__(self):
        """ Clean up on shutdown, such as removing the PID file. """
        # only remove stuff if we created it. Otherwise we're bailing (but
        # still getting called) after realising that another instance is
        # running.
        if not self.pid_file_created:
            return

        logger.debug('Removing PID file %s', self.pid_file)
        try:
            os.remove(self.pid_file)
        except OSError as oserror:
            logger.warning('Removal of PID file %s failed: %s',
                           self.pid_file, oserror)


def run():
    """ Runs the Peekaboo daemon. """
    arg_parser = ArgumentParser(
        description='Peekaboo Extended Email Attachment Behavior Observation Owl'
    )
    arg_parser.add_argument(
        '-c', '--config',
        action='store',
        help='The configuration file for Peekaboo.'
    )
    arg_parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help="Run Peekaboo in debug mode regardless of what's specified in the configuration."
    )
    arg_parser.add_argument(
        '-D', '--daemon',
        action='store_true',
        help='Run Peekaboo in daemon mode (suppresses the logo to be written to STDOUT).'
    )
    args = arg_parser.parse_args()

    print('Starting Peekaboo %s.' % __version__)
    if not args.daemon:
        print(PEEKABOO_OWL)

    # Check if CLI arguments override the configuration
    log_level = None
    if args.debug:
        log_level = logging.DEBUG

    try:
        config = PeekabooConfig(config_file=args.config, log_level=log_level)
        logger.debug(config)
    except PeekabooConfigException as error:
        logging.critical(error)
        sys.exit(1)

    if sys.version_info[0] < 3:
        logger.warning(
            "Python 2 support is deprecated and will be removed in a future "
            "release. Please switch to python 3.")

    # find localisation in our package directory
    locale_domain = 'peekaboo'
    locale_dir = os.path.join(os.path.dirname(__file__), 'locale')
    languages = None
    if config.report_locale:
        logger.debug('Looking for translations for preconfigured locale "%s"',
                     config.report_locale)
        languages = [config.report_locale]
        if not gettext.find(locale_domain, locale_dir, languages):
            logger.warning('Translation file not found - falling back to '
                           'system configuration.')
            languages = None

    logger.debug('Installing report message translations')
    translation = gettext.translation(locale_domain, locale_dir, languages,
                                      fallback=True)
    # python2's gettext needs to be told explicitly to return unicode strings
    loc_kwargs = {}
    if sys.version_info[0] < 3:
        loc_kwargs = {'unicode': True}
    translation.install(loc_kwargs)

    # establish a connection to the database
    try:
        db_con = PeekabooDatabase(
            db_url=config.db_url, instance_id=config.cluster_instance_id,
            stale_in_flight_threshold=config.cluster_stale_in_flight_threshold,
            log_level=config.db_log_level)
    except PeekabooDatabaseError as error:
        logging.critical(error)
        sys.exit(1)
    except SQLAlchemyError as dberr:
        logger.critical('Failed to establish a connection to the database '
                        'at %s: %s', config.db_url, dberr)
        sys.exit(1)

    # initialize the daemon infrastructure such as PID file and dropping
    # privileges, automatically cleans up after itself when going out of scope
    daemon_infrastructure = PeekabooDaemonInfrastructure(
        config.pid_file, config.sock_file, config.user, config.group)
    daemon_infrastructure.init()

    systemd = SystemdNotifier()

    # clear all our in flight samples and all instances' stale in flight
    # samples
    db_con.clear_in_flight_samples()
    db_con.clear_stale_in_flight_samples()

    # a cluster duplicate interval of 0 disables the handler thread which is
    # what we want if we don't have an instance_id and therefore are alone
    cldup_check_interval = 0
    if config.cluster_instance_id > 0:
        cldup_check_interval = config.cluster_duplicate_check_interval
        if cldup_check_interval < 5:
            cldup_check_interval = 5
            logger.warning("Raising excessively low cluster duplicate check "
                           "interval to %d seconds.",
                           cldup_check_interval)

    # read in the ruleset configuration
    try:
        ruleset_config = PeekabooConfigParser(config.ruleset_config)
    except PeekabooConfigException as error:
        logging.critical(error)
        sys.exit(1)

    # create a single ruleset engine for all workers, instantiates all the
    # rules based on the ruleset configuration, is otherwise stateless to avoid
    # concurrent use by multiple worker threads
    try:
        engine = RulesetEngine(ruleset_config, db_con)
    except (KeyError, ValueError, PeekabooConfigException) as error:
        logging.critical('Ruleset configuration error: %s', error)
        sys.exit(1)
    except PeekabooRulesetConfigError as error:
        logging.critical(error)
        sys.exit(1)

    job_queue = JobQueue(
        worker_count=config.worker_count, ruleset_engine=engine,
        db_con=db_con,
        cluster_duplicate_check_interval=cldup_check_interval)

    if config.cuckoo_mode == "embed":
        logger.warning(
            "Embedded mode for Cuckoo is deprecated and will be removed in "
            "a future release. Please switch to REST API mode.")

        cuckoo = CuckooEmbed(job_queue, config.cuckoo_exec,
                             config.cuckoo_submit, config.cuckoo_storage,
                             config.interpreter)
    # otherwise it's the new API method and default
    else:
        cuckoo = CuckooApi(job_queue, config.cuckoo_url,
                           config.cuckoo_api_token,
                           config.cuckoo_poll_interval,
                           config.cuckoo_submit_original_filename,
                           config.cuckoo_maximum_job_age)

    sig_handler = SignalHandler()
    sig_handler.register_listener(cuckoo)

    # Factory producing almost identical samples providing them with global
    # config values and references to other objects they need, such as cuckoo,
    # database connection and connection map.
    sample_factory = SampleFactory(
        cuckoo, config.sample_base_dir, config.job_hash_regex,
        config.keep_mail_data, config.processing_info_dir)

    # We only want to accept 2 * worker_count connections.
    try:
        server = PeekabooServer(
            sock_file=config.sock_file, job_queue=job_queue,
            sample_factory=sample_factory,
            request_queue_size=config.worker_count * 2,
            sock_group=config.sock_group,
            sock_mode=config.sock_mode)
    except Exception as error:
        logger.critical('Failed to start Peekaboo Server: %s', error)
        job_queue.shut_down()
        sys.exit(1)

    exit_code = 1
    try:
        systemd.notify("READY=1")
        # If this dies Peekaboo dies, since this is the main thread. (legacy)
        exit_code = cuckoo.do()
    except Exception as error:
        logger.critical('Main thread aborted: %s', error)
    finally:
        server.shutdown()
        job_queue.shut_down()
        try:
            db_con.clear_in_flight_samples()
            db_con.clear_stale_in_flight_samples()
        except PeekabooDatabaseError as dberr:
            logger.error(dberr)

    sys.exit(exit_code)

if __name__ == '__main__':
    run()
