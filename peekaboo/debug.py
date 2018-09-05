###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# debug.py                                                                    #
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


import socket
import select
import errno
import os
import fileinput
import sys
from threading import Thread, Event
import logging


logger = logging.getLogger(__name__)


class PeekabooDebugger(Thread):
    def __init__(self):
        self.shutdown_requested = Event()
        self.shutdown_requested.clear()
        self.socket = None
        self.poll_interval = 5
        self.bufsize = 4096
        Thread.__init__(self)

    def wait_for_input(self, socket, timeout):
        r = []
        while len(r) == 0 and not self.shutdown_requested.is_set():
            try:
                r, w, e = select.select([socket], [], [], timeout)
            except (OSError, select.error) as e:
                if e.args[0] != errno.EINTR:
                    raise

        # will only be empty if shutdown requested
        return len(r)

    def run(self):
        """
        Create a file socket to execute (by line) python code.
        All input / output is redirected to the socket connection.
        DO NOT USE THIS MODULE IN PRODUCTION!

        Usage:
          socket /path/to/debug.sock
        """
        sockfile = os.path.abspath('./debug.sock')
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # attempt to remove an earlier socket file
            os.remove(sockfile)
        except OSError:
            # doesn't matter :-)
            pass

        s.bind(sockfile)
        s.listen(5)

        logger.debug('Peekaboo debugging socket %s created.' % sockfile)
        logger.debug('DO NOT USE THIS MODULE IN PRODUCTION!')
        logger.debug('You may now connect to the socket with:')
        logger.debug('    socket %s' % sockfile)
        logger.debug('Once connected to the socket, you can execute Python code.')

        logger.debug("Accepting connections")
        while self.wait_for_input(s, self.poll_interval):
            logger.debug("New connection")
            conn, __ = s.accept()

            stdout = os.dup(1)
            stderr = os.dup(2)
            os.dup2(conn.fileno(), 1)
            os.dup2(conn.fileno(), 2)

            sys.stdout.write('> ')
            sys.stdout.flush()
            buf = ''
            while self.wait_for_input(conn, self.poll_interval):
                input = conn.recv(self.bufsize)
                if len(input) == 0:
                    break

                buf += input
                for part in buf.splitlines(True):
                    # does it end in a newline?
                    line = part.rstrip('\r\n')
                    if line == part:
                        # remember this bit for the next iteration to append
                        # the remainder of that line
                        buf = line
                        break

                    try:
                        exec line
                    except Exception as e:
                        logger.exception(e)

                sys.stdout.write('> ')
                sys.stdout.flush()

            os.dup2(stdout, 1)
            os.close(stdout)
            os.dup2(stderr, 2)
            os.close(stderr)
            conn.close()
            logger.debug("Connection closed: %d, %d" %(stdout, stderr))

        s.close()
        os.remove(sockfile)
        logger.debug("Shut down")

    def shut_down(self):
        self.shutdown_requested.set()
