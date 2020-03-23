#!/usr/bin/env python
# encoding: utf-8

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# peekaboo-util.py                                                            #
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


from __future__ import print_function
from os import path
from argparse import ArgumentParser
import json
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

    def send_receive(self, request):
        """ Send request to peekaboo and return its answer """
        logger.debug('Sending request: %s', request)

        self.peekaboo.send(request.encode('utf-8'))
        logger.info('Waiting for response...')

        buf = ''
        while True:
            data = self.peekaboo.recv(1024)
            if data:
                buf += data.decode('utf-8')
            else:
                self.peekaboo.close()
                break
        logger.debug('Received from peekaboo: %s', buf)
        return buf

    def send_receive_json(self, data):
        """ Send and receive data in JSON format. """
        request = json.dumps(data)
        response = self.send_receive(request)
        outdata = None
        for line in response.splitlines():
            try:
                # try to parse and stop at first thing that parses
                outdata = json.loads(line)
                break
            except ValueError as error:
                # FIXME: daemon talks a mix of plain text and JSON. So for now
                # we must ignore everything that doesn't parse. This includes
                # errors.  We can't even employ a heuristic since all of those
                # can be translated.
                pass

        return outdata

    def ping(self):
        """ Send ping request to daemon and optionally print response. """
        logger.debug("Sending ping...")
        try:
            pong = self.send_receive_json([{"request": "ping"}])
        except socket.error as error:
            logger.error("Error communicating with daemon: %s", error)
            return 2

        if not isinstance(pong, dict):
            logger.error("Invalid response from daemon: %s", pong)
            return 2

        reqtype = pong.get('request')
        response = pong.get('response')
        if reqtype is None or response is None:
            logger.error("Incomplete response from daemon: %s", pong)
            return 2

        if reqtype != 'ping' and response != 'pong':
            logger.error("Response is not a pong")
            return 2

        logger.info('Pong received.')
        return 0

    def raw(self, raw):
        """ Send raw data to the daemon and display response. """
        logger.debug("Sending raw...")
        try:
            response = self.send_receive(raw)
        except socket.error as error:
            logger.error("Error communicating with daemon: %s", error)
            return 2

        print(response)
        return 0

    def scan_file(self, filenames):
        """ Scan the supplied filenames with peekaboo and output result """
        result_regex = re.compile(r'has been categorized',
                                  re.MULTILINE + re.DOTALL + re.UNICODE)
        requests = []
        for filename in filenames:
            requests.append({"request": "scan-file",
                             "full_name": path.abspath(filename)})

        buf = self.send_receive(json.dumps(requests))

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
    parser.add_argument('-t', '--timeout', type=float, required=False,
                        default=None, help='Communications timeout')
    parser.add_argument('-s', '--socket-file', action='store', required=True,
                        help='Path to Peekaboo\'s socket file')

    scan_file_parser = subparsers.add_parser('scan-file',
                                             help='Scan a file and report it')
    scan_file_parser.add_argument('-f', '--filename', action='append', required=True,
                                  help='Path to the file to scan. Can be given more '
                                       'than once to scan multiple files.')
    scan_file_parser.set_defaults(func=command_scan_file)

    ping_parser = subparsers.add_parser('ping', help='Ping the daemon')
    ping_parser.set_defaults(func=command_ping)

    raw_parser = subparsers.add_parser('raw',
                                       help='Send raw input to the daemon')
    raw_parser.add_argument('-j', '--json', action='store', required=True,
                            help='Raw JSON to send to daemon')
    raw_parser.set_defaults(func=command_raw)

    args = parser.parse_args()

    logger.setLevel(logging.ERROR)
    if args.verbose:
        logger.setLevel(logging.INFO)
    if args.verbose2 or args.debug:
        logger.setLevel(logging.DEBUG)

    if args.timeout:
        socket.setdefaulttimeout(args.timeout)

    try:
        util = PeekabooUtil(args.socket_file)
    except socket.error as error:
        logger.error("Error connecting to peekaboo socket: %s", error)
        return 2

    return args.func(util, args)


def command_scan_file(util, args):
    """ Handler for command scan_file """
    return util.scan_file(args.filename)


def command_ping(util, _):
    """ Handler for command ping """
    return util.ping()


def command_raw(util, args):
    """ Handler for command raw """
    return util.raw(args.json)


if __name__ == "__main__":
    sys.exit(main())
