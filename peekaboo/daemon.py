###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# daemon.py                                                                   #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2018  science + computing ag                             #
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


import os
import sys
import grp
import pwd
import stat
import logging
import SocketServer
import socket
import signal
from time import sleep
import json
from threading import Thread
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from peekaboo import _owl, __version__
from peekaboo.config import PeekabooConfig, PeekabooRulesetConfiguration
from peekaboo.db import PeekabooDatabase
from peekaboo.toolbox.sampletools import ConnectionMap
from peekaboo.queuing import JobQueue
from peekaboo.sample import SampleFactory
from peekaboo.exceptions import PeekabooDatabaseError
from peekaboo.toolbox.cuckoo import Cuckoo, CuckooEmbed, CuckooApi


logger = logging.getLogger(__name__)


class SignalHandler():
    """
    Signal handler.
    
    @author: Felix Bauer
    """
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


class PeekabooStreamServer(SocketServer.ThreadingUnixStreamServer):
    """
    Asynchronous server.

    @author: Sebastian Deiss
    """
    def __init__(self, server_address, request_handler_cls, job_queue,
            sample_factory, bind_and_activate = True, request_queue_size = 10):
        self.server_address = server_address
        self.__job_queue = job_queue
        self.__sample_factory = sample_factory
        self.request_queue_size = request_queue_size
        self.allow_reuse_address = True
        
        SocketServer.ThreadingUnixStreamServer.__init__(self, server_address,
                                                        request_handler_cls,
                                                        bind_and_activate=bind_and_activate)

    @property
    def job_queue(self):
        return self.__job_queue

    @property
    def sample_factory(self):
        return self.__sample_factory

    def shutdown_request(self, request):
        """ Keep the connection alive until Cuckoo reports back, so the results can be send to the client. """
        # TODO: Find a better solution.
        pass

    def server_close(self):
        # no new connections from this point on
        os.remove(self.server_address)
        return SocketServer.ThreadingUnixStreamServer.server_close(self)


class PeekabooStreamRequestHandler(SocketServer.StreamRequestHandler):
    """
    Request handler used by PeekabooStreamServer to handle analysis requests.

    @author: Sebastian Deiss
    """
    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.job_queue = self.server.job_queue
        self.sample_factory = self.server.sample_factory

    def handle(self):
        """
        Handles an analysis request. This is expected to be a JSON structure
        containing the path of the directory / file to analyse. Structure:

        [ { "full_name": "<path>",
            "name_declared": ...,
            ... },
          { ... },
          ... ]

        The maximum buffer size is 16 KiB, because JSON incurs some bloat.
        """
        self.request.sendall('Hallo das ist Peekaboo\n\n')
        request = self.request.recv(1024 * 16).rstrip()

        try:
            parts = json.loads(request)
        except:
            self.request.sendall('FEHLER: Ungueltiges JSON.')
            logger.error('Invalid JSON in request.')
            return

        if type(parts) not in (list, tuple):
            self.request.sendall('FEHLER: Ungueltiges Datenformat.')
            logger.error('Invalid data structure.')
            return

        for_analysis = []
        for part in parts:
            if not part.has_key('full_name'):
                self.request.sendall('FEHLER: Unvollstaendige Datenstruktur.')
                logger.error('Incomplete data structure.')
                return

            path = part['full_name']
            logger.info("Got run_analysis request for %s" % path)
            if not os.path.exists(path):
                self.request.sendall('FEHLER: Pfad existiert nicht oder '
                        'Zugriff verweigert.')
                logger.error('Path does not exist or no permission '
                        'to access it.')
                return

            if not os.path.isfile(path):
                self.request.sendall('FEHLER: Eingabe ist keine Datei.')
                logger.error('Input is not a file')
                return

            sample = self.sample_factory.make_sample(path, metainfo = part,
                    socket = self.request)
            for_analysis.append(sample)
            logger.debug('Created sample %s' % sample)

        # introduced after an issue where results were reported
        # before all files could be added.
        for sample in for_analysis:
            self.job_queue.submit(sample, self.__class__)


def run():
    """ Runs the Peekaboo daemon. """
    arg_parser = ArgumentParser(
        description='Peekaboo Extended Email Attachment Behavior Observation Owl'
    )
    arg_parser.add_argument(
        '-c', '--config',
        action='store',
        required=False,
        default=os.path.join('./peekaboo.conf'),
        help='The configuration file for Peekaboo.'
    )
    arg_parser.add_argument(
        '-d', '--debug',
        action='store_true',
        required=False,
        default=False,
        help="Run Peekaboo in debug mode regardless of what's specified in the configuration."
    )
    arg_parser.add_argument(
        '-D', '--daemon',
        action='store_true',
        required=False,
        default=False,
        help='Run Peekaboo in daemon mode (suppresses the logo to be written to STDOUT).'
    )
    args = arg_parser.parse_args()

    if not args.daemon:
        print(_owl)
    else:
        print('Starting Peekaboo %s.' % __version__)

    # read configuration
    if not os.path.isfile(args.config):
        print('Failed to read config, files does not exist.') # logger doesn't exist here
        sys.exit(1)

    config = PeekabooConfig(args.config)

    # Check if CLI arguments override the configuration
    if args.debug:
        config.change_log_level('DEBUG')

    # Log the configuration options if we are in debug mode
    if config.log_level == logging.DEBUG:
        logger.debug(config.__str__())

    # establish a connection to the database
    try:
        db_con = PeekabooDatabase(config.db_url)
    except PeekabooDatabaseError as e:
        logging.exception(e)
        sys.exit(1)
    except Exception as e:
        logger.critical('Failed to establish a connection to the database.')
        logger.exception(e)
        sys.exit(1)

    # Import debug module if we are in debug mode
    debugger = None
    if config.use_debug_module:
        from peekaboo.debug import PeekabooDebugger
        debugger = PeekabooDebugger()
        debugger.start()

    if os.getuid() == 0:
        logger.warning('Peekaboo should not run as root.')
        # drop privileges to user
        os.setgid(grp.getgrnam(config.group)[2])
        os.setuid(pwd.getpwnam(config.user)[2])
        # set $HOME to the users home directory
        # (VirtualBox must access the configs)
        os.environ['HOME'] = pwd.getpwnam(config.user)[5]
        logger.info("Dropped privileges to user %s and group %s"
                    % (config.user, config.group))
        logger.debug('$HOME is ' + os.environ['HOME'])

    # write PID file
    pid = str(os.getpid())
    with open(config.pid_file, "w") as pidfile:
        pidfile.write("%s\n" % pid)

    systemd = SystemdNotifier()

    # workers of the job queue need the ruleset configuration to create the
    # ruleset engine with it
    ruleset_config = PeekabooRulesetConfiguration(config.ruleset_config)
    job_queue = JobQueue(worker_count = config.worker_count,
            ruleset_config = ruleset_config)
    connection_map = ConnectionMap()

    if config.cuckoo_mode == "embed":
        cuckoo = CuckooEmbed(job_queue, connection_map, config.interpreter,
                config.cuckoo_exec, config.cuckoo_submit,
                config.cuckoo_storage)
    # otherwise it's the new API method and default
    else:
        cuckoo = CuckooApi(job_queue, connection_map, config.cuckoo_url,
                config.cuckoo_poll_interval)

    sig_handler = SignalHandler()
    sig_handler.register_listener(cuckoo)

    # Factory producing almost identical samples providing them with global
    # config values and references to other objects they need, such as cuckoo,
    # database connection and connection map.
    sample_factory = SampleFactory(cuckoo, db_con, connection_map,
                config.sample_base_dir, config.job_hash_regex,
                config.keep_mail_data)

    # Try three times to start SocketServer
    for i in range(0, 3):
        try:
            # We only want to accept 2 * worker_count connections.
            server = PeekabooStreamServer(config.sock_file,
                    PeekabooStreamRequestHandler,
                    job_queue = job_queue,
                    sample_factory = sample_factory,
                    request_queue_size = config.worker_count * 2)
            break
        except socket.error, msg:
            logger.warning("SocketServer couldn't start (%i): %s" % (i, msg))
    if not server:
        logger.error('Fatal: Couldn\'t initialise Peekaboo Server')
        sys.exit(1)

    runner = Thread(target=server.serve_forever)
    runner.daemon = True

    rc = 1
    try:
        runner.start()
        logger.info('Peekaboo server is listening on %s' % server.server_address)

        os.chmod(config.sock_file, stat.S_IWOTH | stat.S_IREAD |
                                   stat.S_IWRITE | stat.S_IRGRP |
                                   stat.S_IWGRP | stat.S_IWOTH)

        systemd.notify("READY=1")
        # If this dies Peekaboo dies, since this is the main thread. (legacy)
        rc = cuckoo.do()
    except Exception as e:
        logger.exception(e)
    finally:
        server.shutdown()
        server.server_close()
        job_queue.shut_down()
        if debugger is not None:
            debugger.shut_down()

    sys.exit(rc)

if __name__ == '__main__':
    run()
