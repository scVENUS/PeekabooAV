###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# daemon.py                                                                   #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2017  science + computing ag                             #
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


from threading import Thread
import SocketServer
import os
import sys
import grp
import pwd
import stat
import logging
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from twisted.internet import reactor
from peekaboo import _owl, __version__, logger
from peekaboo.config import PeekabooConfig
from peekaboo.db import PeekabooDBHandler
from peekaboo.cuckoo_wrapper import CuckooManager
import peekaboo.pjobs as pjobs
import peekaboo.sample as sample


class PeekabooStreamServer(SocketServer.ThreadingUnixStreamServer):
    """
    Asynchronous server.

    @author: Sebastian Deiss
    """
    def __init__(self, server_address, request_handler_cls, bind_and_activate=True,
                 config=None):
        self.config = config
        self.workers = pjobs.Workers(config.worker_count)
        # We can only accept 2 * worker_count connections.
        self.request_queue_size = config.worker_count * 2
        self.allow_reuse_address = True
        SocketServer.ThreadingUnixStreamServer.__init__(self, server_address,
                                                        request_handler_cls,
                                                        bind_and_activate=bind_and_activate)

    def finish_request(self, request, client_address):
        # TODO: Put client connection in Jobs here?
        return SocketServer.ThreadingUnixStreamServer.finish_request(self, request, client_address)

    def shutdown_request(self, request):
        """ Keep the connection alive until Cuckoo reports back, so the results can be send to the client. """
        # TODO: Find a better solution.
        pass

    def server_close(self):
        os.remove(self.config.sock_file)
        return SocketServer.ThreadingUnixStreamServer.server_close(self)


class PeekabooStreamRequestHandler(SocketServer.StreamRequestHandler):
    def __init__(self, request, client_address, server):
        self.config = server.config
        self.workers = server.workers
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
        self.request.sendall('Hallo das ist Peekaboo\n\n')
        # receive directory path
        path = self.request.recv(1024).rstrip()
        logger.info("Received %s" % path)

        if not os.path.exists(path):
            self.request.sendall("ERROR: path from amavis doesn't exist or no "
                                 "permission to access it")
            logger.error('Path from amavis doesn\'t exist or no '
                         'permission to access it')
        else:
            # close connection if there is nothing to analyze
            for_analysis = []
            if os.path.isfile(path):
                sample = self._make_sample(path, self.request)
                if sample:
                    for_analysis.append(sample)
            else:
                # walk recursively through entries in directory
                for dirname, __, filenames in os.walk(path):
                    for filename in filenames:
                        logger.debug("Found file %s" % filename)
                        p = os.path.join(dirname, filename)
                        sample = self._make_sample(p, self.request)
                        if sample:
                            for_analysis.append(sample)

            # introduced after issue where results were reported
            # before all file could be added
            for s in for_analysis:
                pjobs.Jobs.add_job(self.request, s)
                self.workers.submit_job(s, self.__class__)

    # TODO: do cleanup work here in finish()

    def _make_sample(self, p, conn):
        logger.debug("Looking at file %s" % p)
        if not os.path.isfile(p):
            logger.debug('%s is not a file' % p)
            return None
        s = sample.Sample(self.config, conn, p)
        logger.debug('Created sample %s' % s)

        return s


def run():
    """ Runs the daemon. """
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-c', '--config', action='store', required=False,
                            default=os.path.join('./peekaboo.conf'),
                            help='The configuration file for Peekaboo.')
    arg_parser.add_argument('-d', '--debug', action='store_true', required=False,
                            help="Run Peekaboo in debug mode regardless of what's "
                                 "specified in the configuration.",
                            default=False)
    arg_parser.add_argument('-D', '--daemon', action='store_true', required=False,
                            help='Run Peekaboo in daemon mode (suppresses the logo to be written to STDOUT).',
                            default=False)
    args = arg_parser.parse_args()

    if not args.daemon:
        print(_owl)
    else:
        print('Starting Peekaboo %s.' % __version__)

    # read configuration
    config = PeekabooConfig(args.config)

    # Check if CLI arguments override the configuration
    if args.debug:
        config.change_log_level('DEBUG')

    # Log the configuration options if we are in debug mode
    if config.log_level == logging.DEBUG:
        logger.debug(config.__str__())

    # establish a connection to the database
    try:
        db_con = PeekabooDBHandler(config.db_url)
        config.add_db_con(db_con)
    except Exception as e:
        logger.critical('Failed to establish a connection to the database.')
        sys.exit(1)

    # Import debug module if we are in debug mode
    if config.use_debug_module:
        from peekaboo.debug import peekaboo_debugger
        peekaboo_debugger()

    if os.getuid() == 0:
        logger.warning('Peekaboo should not run as root')
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
    server = PeekabooStreamServer(config.sock_file, PeekabooStreamRequestHandler, config=config)
    runner = Thread(target=server.serve_forever)
    runner.daemon = True

    try:
        runner.start()
        systemd.notify("READY=1")
        logger.debug('Peekaboo server is listening on %s' % server.server_address)

        os.chmod(config.sock_file, stat.S_IWOTH | stat.S_IREAD |
                                   stat.S_IWRITE | stat.S_IRGRP |
                                   stat.S_IWGRP | stat.S_IWOTH)

        # Run Cuckoo sandbox, parse log output, and report back of Peekaboo.
        # If this dies Peekaboo dies, since this is the main thread.
        mgr = CuckooManager()
        reactor.spawnProcess(mgr, config.interpreter, [config.interpreter, '-u',
                                                       config.cuckoo_exec])
        reactor.run()
    finally:
        server.shutdown()


if __name__ == '__main__':
    run()
