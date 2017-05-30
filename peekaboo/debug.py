###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# peekabood.py                                                                #
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


# DO NOT USE IN PRODUCTION!!
#
# import this to your project and connect to debug2.sock
#  socket $(pwd)/debug2.sock
# execute (by line) python code
# redirects all input/output to socket connection
#
#
# import threading; print threading.activeCount()
#
# import pjobs
# for W in pjobs.Workers.w: print W.isAlive()
# print pjobs.Workers.q.qsize()
# print pjobs.Jobs.jobs


from __future__ import print_function
from __future__ import absolute_import
import socket
import os
import fileinput
import sys
import threading
from . import logger
from peekaboo.util import log_exception


def debug():
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
                log_exception(e)
            sys.stdout.write('> ')

        sys.stdin = stdin
        sys.stdout = stdout
        sys.stderr = stderr


def peekaboo_debugger():
    threading.Thread(target=debug).start()