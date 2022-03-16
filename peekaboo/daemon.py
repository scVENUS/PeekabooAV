###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# daemon.py                                                                   #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2022 science + computing ag                              #
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

import asyncio
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
from peekaboo.config import (
    PeekabooConfig, PeekabooConfigParser, PeekabooAnalyzerConfig)
from peekaboo.db import PeekabooDatabase
from peekaboo.queuing import JobQueue
from peekaboo.sample import SampleFactory
from peekaboo.server import PeekabooServer
from peekaboo.exceptions import (
    PeekabooDatabaseError, PeekabooConfigException)


logger = logging.getLogger(__name__)

class SignalHandler:
    """ Signal handler. """
    def __init__(self, loop):
        """ register custom signal handler """
        self.listeners = []

        loop.add_signal_handler(
            signal.SIGINT, self.signal_handler, signal.SIGINT)
        loop.add_signal_handler(
            signal.SIGTERM, self.signal_handler, signal.SIGTERM)

        self.shutdown_requested = False

    def register_listener(self, listener):
        """ Register a listener object which is expected to implement a very
        simple interface: Method shut_down() is called if SIGINT or SIGTERM
        arrive. It is expected to defer actual handling of the condition.
        """
        self.listeners.append(listener)

    def signal_handler(self, sig):
        """ catch signal and call appropriate methods in registered listener
        classes """
        if sig in [signal.SIGINT, signal.SIGTERM]:
            logger.debug("SIGINT/TERM")
            self.shutdown_requested = True

            # these should take serious care about being called across threads
            for listener in self.listeners:
                listener.shut_down()


class PeekabooDaemonInfrastructure:
    """ A class that manages typical daemon infrastructure such as PID file and
    privileges. """
    def __init__(self, pid_file, user, group):
        self.pid_file = pid_file
        self.user = user
        self.group = group

        self.pid_file_created = False

    def init(self):
        """ Initialize daemon infrastructure. """
        self.drop_privileges()
        self.create_pid_file()

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
        if not self.pid_file:
            logger.debug("Creation of PID file is disabled.")
            return

        ourpid = os.getpid()
        if os.path.exists(self.pid_file):
            oldpid = None
            stale = False
            try:
                with open(self.pid_file, 'r') as pidfile:
                    oldpid = int(pidfile.read())
            except (OSError, IOError, ValueError) as error:
                stale = True
                logger.warning('PID file exists but cannot be read, '
                               'assuming it to be stale')

            if oldpid == ourpid:
                # pidfile contains our pid. There cannot be a process with the
                # same PID in the same PID namespace. So either we're sharing
                # PID files across namespaces/hosts or there's been PID re-use
                # and collision, e.g. through container restart. The former is
                # misconfiguration, the latter just a case of stale PID file.
                logger.debug("Treating PID file with our PID in it as stale")
                stale = True
            elif oldpid is not None:
                try:
                    # ping the process to see if it exists, sends no signal
                    os.kill(oldpid, 0)
                except OSError as oserror:
                    # ESRCH == no such process
                    if oserror.errno == errno.ESRCH:
                        stale = True

            if not stale:
                logger.critical('Another instance of Peekaboo seems to be '
                                'running as process %d. Please check PID '
                                'file %s.', oldpid, self.pid_file)
                sys.exit(1)

            logger.warning('Removing stale PID file of process %d', oldpid)
            try:
                os.remove(self.pid_file)
            except OSError as error:
                logger.critical('Error deleting stale PID file %s: %s',
                                self.pid_file, error)
                sys.exit(1)

        # write PID file
        with open(self.pid_file, "w") as pidfile:
            pidfile.write("%d\n" % ourpid)

        # remember that the PID file is ours - important on shutdown
        self.pid_file_created = True
        logger.debug('PID %d written to %s', ourpid, self.pid_file)

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
    translation.install()

    # establish a connection to the database
    try:
        db_con = PeekabooDatabase(
            db_url=config.db_url, instance_id=config.cluster_instance_id,
            stale_in_flight_threshold=config.cluster_stale_in_flight_threshold,
            log_level=config.db_log_level, async_driver=config.db_async_driver)
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
        config.pid_file, config.user, config.group)
    daemon_infrastructure.init()

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

    loop = asyncio.get_event_loop()
    sig_handler = SignalHandler(loop)

    # read in the analyzer and ruleset configuration and start the job queue
    try:
        ruleset_config = PeekabooConfigParser(config.ruleset_config)
        analyzer_config = PeekabooAnalyzerConfig(config.analyzer_config)
        job_queue = JobQueue(
            worker_count=config.worker_count, ruleset_config=ruleset_config,
            db_con=db_con, analyzer_config=analyzer_config,
            cluster_duplicate_check_interval=cldup_check_interval)
        sig_handler.register_listener(job_queue)
        job_queue.start()
    except PeekabooConfigException as error:
        logging.critical(error)
        sys.exit(1)

    # Factory producing almost identical samples providing them with global
    # config values and references to other objects they need, such as database
    # connection and connection map.
    sample_factory = SampleFactory(
        config.processing_info_dir)

    try:
        server = PeekabooServer(
            host=config.host, port=config.port,
            job_queue=job_queue,
            sample_factory=sample_factory,
            request_queue_size=100,
            db_con=db_con)
    except Exception as error:
        logger.critical('Failed to start Peekaboo Server: %s', error)
        job_queue.shut_down()
        job_queue.close_down()
        sys.exit(1)

    # abort startup if shutdown was requested meanwhile
    if sig_handler.shutdown_requested:
        sys.exit(0)

    sig_handler.register_listener(server)
    SystemdNotifier().notify("READY=1")
    server.serve()

    # trigger shutdowns of other components (if not already ongoing triggered
    # by e.g. the signal handler), server will already be shut down at this
    # point signaled by the fact that serve() above returned
    job_queue.shut_down()

    # close down components after they've shut down
    job_queue.close_down()

    # do a final cleanup pass through the database
    try:
        db_con.clear_in_flight_samples()
        db_con.clear_stale_in_flight_samples()
    except PeekabooDatabaseError as dberr:
        logger.error(dberr)

    sys.exit(0)

if __name__ == '__main__':
    run()
