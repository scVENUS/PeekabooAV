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
from threading import Thread
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from twisted.internet import reactor
from peekaboo import _owl, __version__
from peekaboo.config import parse_config, get_config
from peekaboo.db import PeekabooDatabase
from peekaboo.toolbox.cuckoo import CuckooServer
from peekaboo.toolbox.sampletools import ConnectionMap
from peekaboo.queuing import JobQueue, create_workers
from peekaboo.sample import make_sample


logger = logging.getLogger(__name__)


class PeekabooStreamServer(SocketServer.ThreadingUnixStreamServer):
    """
    Asynchronous server.

    @author: Sebastian Deiss
    """
    def __init__(self, server_address, request_handler_cls, bind_and_activate=True):
        self.config = get_config()
        create_workers(self.config.worker_count)
        # We can only accept 2 * worker_count connections.
        self.request_queue_size = self.config.worker_count * 2
        self.allow_reuse_address = True
        SocketServer.ThreadingUnixStreamServer.__init__(self, server_address,
                                                        request_handler_cls,
                                                        bind_and_activate=bind_and_activate)

    def shutdown_request(self, request):
        """ Keep the connection alive until Cuckoo reports back, so the results can be send to the client. """
        # TODO: Find a better solution.
        pass

    def server_close(self):
        os.remove(self.config.sock_file)
        return SocketServer.ThreadingUnixStreamServer.server_close(self)


class PeekabooStreamRequestHandler(SocketServer.StreamRequestHandler):
    """
    Request handler used by PeekabooStreamServer to handle analysis requests.

    @author: Sebastian Deiss
    """
    def handle(self):
        """
        Handles a analysis request. The path of the directory / file to analyse must
        be written to the corresponding socket.
        The maximum buffer size is 1024 bytes.
        """
        self.request.sendall('Hallo das ist Peekaboo\n\n')
        path = self.request.recv(1024).rstrip()
        logger.info("Got run_analysis request for %s" % path)

        if not os.path.exists(path):
            self.request.sendall(
                'FEHLER: Pfad existiert nicht oder Zugriff verweigert.'
            )
            logger.error("ERROR: Path does not exist or no permission to access it.")
        else:
            for_analysis = []
            if os.path.isfile(path):
                sample = make_sample(path, self.request)
                if sample:
                    for_analysis.append(sample)
            else:
                # walk recursively through entries in the given directory.
                for dirname, __, filenames in os.walk(path):
                    for filename in filenames:
                        logger.debug("Found file %s" % filename)
                        f = os.path.join(dirname, filename)
                        sample = make_sample(f, self.request)
                        if sample:
                            for_analysis.append(sample)

            # introduced after an issue where results were reported
            # before all files could be added.
            for sample in for_analysis:
                ConnectionMap.add(self.request, sample)
                JobQueue.submit(sample, self.__class__)


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
    config = parse_config(args.config)

    # Check if CLI arguments override the configuration
    if args.debug:
        config.change_log_level('DEBUG')

    # Log the configuration options if we are in debug mode
    if config.log_level == logging.DEBUG:
        logger.debug(config.__str__())

    # establish a connection to the database
    try:
        db_con = PeekabooDatabase(config.db_url)
        config.add_db_con(db_con)
    except Exception as e:
        logger.critical('Failed to establish a connection to the database.')
        logger.exception(e)
        sys.exit(1)

    # Import debug module if we are in debug mode
    if config.use_debug_module:
        from peekaboo.debug import peekaboo_debugger
        peekaboo_debugger()

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
    server = PeekabooStreamServer(config.sock_file, PeekabooStreamRequestHandler)
    runner = Thread(target=server.serve_forever)
    runner.daemon = True

    try:
        runner.start()
        logger.info('Peekaboo server is listening on %s' % server.server_address)

        os.chmod(config.sock_file, stat.S_IWOTH | stat.S_IREAD |
                                   stat.S_IWRITE | stat.S_IRGRP |
                                   stat.S_IWGRP | stat.S_IWOTH)

        # Run Cuckoo sandbox, parse log output, and report back of Peekaboo.
        # If this dies Peekaboo dies, since this is the main thread.
        srv = CuckooServer()
        reactor.spawnProcess(srv, config.interpreter, [config.interpreter, '-u',
                                                       config.cuckoo_exec])
        systemd.notify("READY=1")
        reactor.run()
    except Exception as e:
        logger.exception(e)
    finally:
        server.shutdown()


if __name__ == '__main__':
    run()
