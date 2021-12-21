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

""" The peekaboo-util command line interface. """

import argparse
import json
import logging
import os
import re
import socket
import sys
import time
import urllib.parse
import requests


logging.basicConfig()
logger = logging.getLogger(__name__)


class PeekabooUtil:
    """ Utility fo interface with Peekaboo API over the socket connection """
    def __init__(self, url, polling_interval):
        logger.debug('Initialising PeekabooUtil')
        self.peekaboo = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug('Opening connection %s', url)
        self.url = url
        self.polling_interval = polling_interval
        o = urllib.parse.urlparse(url)
        self.peekaboo.connect((o.hostname, o.port))

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
            except ValueError:
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
            r = requests.get(urllib.parse.urljoin(self.url, "/ping"))
            pong = r.json()
        except socket.error as error:
            logger.error("Error communicating with daemon: %s", error)
            return 2
        except json.decoder.JSONDecodeError as error:
            logger.error("Error decoding the response: %s", error)
            return 2

        if not isinstance(pong, dict):
            logger.error("Invalid response from daemon: %s", pong)
            return 2

        reqtype = r.request
        response = pong.get('answer')
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

    def scan_file(self, filenames, content_types, content_dispositions):
        """ Scan the supplied filenames with peekaboo and output result """
        jobs = []
        for filename in filenames:
            logger.debug('Submitting file %s', filename)

            content_type = None
            if content_types:
                ct_popped = content_types.pop(0)
                # empty string is treated as no selection to allow specificaion
                # for later file arguments still
                if ct_popped:
                    content_type = ct_popped
                    logger.debug('Using content type %s', content_type)

            content_disposition = None
            if content_dispositions:
                cd_popped = content_dispositions.pop(0)
                if cd_popped:
                    content_disposition = cd_popped
                    logger.debug(
                        'Using content disposition %s', content_disposition)

            with open(filename, 'rb') as upload_file:
                submit_name = os.path.basename(filename)
                files = {'file': (submit_name, upload_file, content_type)}
                headers = {'x-content-disposition': content_disposition}

                response = requests.post(urllib.parse.urljoin(
                    self.url, '/v1/scan'), files=files, headers=headers)

            json_resp = response.json()
            job_id = json_resp['job_id']
            logger.debug('File %s submitted as job %d', filename, job_id)

            jobs.append(job_id)

        exit_code = 0
        while True:
            jobs_left = []
            for job in jobs:
                response = requests.get(urllib.parse.urljoin(
                    self.url, f'/v1/report/{job}'))

                if response.status_code == 404:
                    jobs_left.append(job)
                    continue

                json_resp = response.json()
                if json_resp['result'] == 6:
                    print("The file has been categorized 'bad'")
                    exit_code = 1

                logger.info(json_resp['report'])

            if not jobs_left:
                break

            jobs = jobs_left
            time.sleep(self.polling_interval)

        return exit_code

def main():
    """ The peekaboo-util main program. """
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='commands')

    parser.add_argument('-v', '--verbose', action='store_true', required=False,
                        help='List results of all files not only bad ones')
    parser.add_argument('-vv', '--verbose2', action='store_true', required=False,
                        help='List detailed analysis results of every rule')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Output additional diagnostics')
    parser.add_argument('-t', '--timeout', type=float, required=False,
                        default=None, help='Communications timeout')
    parser.add_argument('-i', '--polling-interval', type=int, required=False,
                        default=5, help='Polling interval')
    parser.add_argument('-r', '--remote-url', action='store', required=False,
                        default='http://127.0.0.1:8100/v1/',
                        help='URL to Peekaboo instance e.g. http://127.0.0.1:8100/v1/')

    scan_file_parser = subparsers.add_parser('scan-file',
                                             help='Scan a file and report it')
    scan_file_parser.add_argument('-f', '--filename', action='append', required=True,
                                  help='Path to the file to scan. Can be given more '
                                       'than once to scan multiple files.')
    scan_file_parser.add_argument(
        '-c', '--content-type', action='append', required=False,
        help='Content type of file to scan. Can be given more than once and '
        'has to match the file list in order.')
    scan_file_parser.add_argument(
        '-o', '--content-disposition', action='append', required=False,
        help='Content disposition of file to scan. Can be given more than '
        'once and has to match the file list in order.')

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
        util = PeekabooUtil(args.remote_url, args.polling_interval)
    except socket.error as error:
        logger.error("Error connecting to peekaboo: %s", error)
        return 2

    return args.func(util, args)


def command_scan_file(util, args):
    """ Handler for command scan_file """
    return util.scan_file(
        args.filename, args.content_type, args.content_disposition)


def command_ping(util, _):
    """ Handler for command ping """
    return util.ping()


def command_raw(util, args):
    """ Handler for command raw """
    return util.raw(args.json)


if __name__ == "__main__":
    sys.exit(main())
