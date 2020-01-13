#!/usr/bin/env python
# encoding: utf-8

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# peekaboo-util.py                                                            #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2019  science + computing ag                             #
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


from __future__ import print_function
from os import path
from argparse import ArgumentParser
import socket
import re
import logging
import sys


logging.basicConfig()
logger = logging.getLogger(__name__)


class PeekabooUtil(object):
    """ Utility fo interface with Peekaboo API over the socket connection """
    def __init__(self, socket_file):
        logger.debug('Initialising PeekabooUtil')
        self.peekaboo = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        logger.debug('Opening socket %s', socket_file)
        self.peekaboo.connect(socket_file)

    def send_receive(self, request, output=False):
        """ Send request to peekaboo and return its answer """
        logger.debug('Sending request: %s', request)

        self.peekaboo.send(request.encode('utf-8'))
        print ('Waiting for response...')

        buf = ''
        while True:
            data = self.peekaboo.recv(1024)
            if data:
                buf += data.decode('utf-8')
                if output:
                    print(data, end='')
            else:
                self.peekaboo.close()
                break
        logger.debug('Received from peekaboo: %s', buf)
        return buf

    def scan_file(self, filenames):
        """ Scan the supplied filenames with peekaboo and output result """
        result_regex = re.compile(r'has been categorized',
                                  re.MULTILINE + re.DOTALL + re.UNICODE)
        file_snippets = []
        for filename in filenames:
            file_snippets.append('{ "full_name": "%s" }' % path.abspath(filename))
        request = '[ %s ]' % ', '.join(file_snippets)

        buf = self.send_receive(request)

        exit_code = 0
        for result in buf.splitlines():
            output = result_regex.search(result)
            if output:
                if 'bad' in result:
                    print(result)
                    exit_code = 1
                logger.info(result)

        return exit_code

def main():
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(help='commands')

    parser.add_argument('-v', '--verbose', action='store_true', required=False,
                        help='List results of all files not only bad ones')
    parser.add_argument('-vv', '--verbose2', action='store_true', required=False,
                        help='List detailed analysis results of every rule')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Output additional diagnostics')
    parser.add_argument('-s', '--socket-file', action='store', required=True,
                        help='Path to Peekaboo\'s socket file')

    scan_file_parser = subparsers.add_parser('scan-file',
                                             help='Scan a file and report it')
    scan_file_parser.add_argument('-f', '--filename', action='append', required=True,
                                  help='Path to the file to scan. Can be given more '
                                       'than once to scan multiple files.')
    scan_file_parser.set_defaults(func=command_scan_file)

    args = parser.parse_args()

    logger.setLevel(logging.ERROR)
    if args.verbose:
        logger.setLevel(logging.INFO)
    if args.verbose2 or args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        util = PeekabooUtil(args.socket_file)
    except socket.error as error:
        logger.error("Error connecting to peekaboo socket: %s", error)
        return 2

    return args.func(util, args)


def command_scan_file(util, args):
    """ Handler for command scan_file """
    return util.scan_file(args.filename)

if __name__ == "__main__":
    sys.exit(main())
