#!/usr/bin/env python
# encoding: utf-8

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# scan_file.py                                                                #
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

"""
@author:     Felix Bauer, Sebastian Deiss
@copyright:  2016-2019 science + computing ag. All rights reserved.
@license:    GPLv3
"""


from __future__ import print_function
from os import path, linesep
from argparse import ArgumentParser
import socket
import re


def main():
    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true', required=False,
                        help='List results of all files not only bad ones')
    parser.add_argument('-vv', '--verbose2', action='store_true', required=False,
                        help='List detailed analysis results of every rule')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Output additional diagnostics')
    parser.add_argument('-s', '--socket_file', action='store', required=True,
                        help='Path to Peekaboo\'s socket file')
    parser.add_argument('-f', '--filename', action='append', required=True,
                        help='Path to the file to scan. Can be given more '
                        'than once to scan multiple files.')
    args = parser.parse_args()

    result_regex = re.compile(r'.*wurde als',
                              re.MULTILINE + re.DOTALL + re.UNICODE)
    peekaboo = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peekaboo.connect(args.socket_file)

    file_snippets = []
    for filename in args.filename:
        file_snippets.append('{ "full_name": "%s" }' % path.abspath(filename))
    request = '[ %s ]' % ', '.join(file_snippets)

    if args.debug:
        print ('Sending request: %s' % request)

    peekaboo.send(request)
    print ('Waiting for response...')

    if args.verbose2:
        args.verbose = True

    while True:
        result = peekaboo.recv(1024)
        result = result.rstrip(linesep)
        if result == '':
            peekaboo.close()
            break
        output = result_regex.search(result)
        if output:
            if 'bad' in result:
                print(result)
            elif args.verbose:
                print(result)
        elif args.verbose2:
            print(result)


if __name__ == "__main__":
    main()
