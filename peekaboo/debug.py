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
import os
import fileinput
import sys
import threading
import logging


logger = logging.getLogger(__name__)


def debug():
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

    while True:
        conn, __ = s.accept()

        stdin = sys.stdin
        stdout = sys.stdout
        stderr = sys.stderr

        # sys.stdin  = conn.fileno()
        # sys.stdout = conn.fileno()
        # sys.stderr = conn.fileno()

        os.dup2(conn.fileno(), 0)
        os.dup2(conn.fileno(), 1)
        os.dup2(conn.fileno(), 2)

        sys.stdout.write('> ')
        for line in fileinput.input():
            try:
                exec line
            except Exception as e:
                logger.exception(e)
            sys.stdout.write('> ')

        sys.stdin = stdin
        sys.stdout = stdout
        sys.stderr = stderr


def peekaboo_debugger():
    threading.Thread(target=debug).start()
