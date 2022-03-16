#!/usr/bin/env python
# encoding: utf-8

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# peekaboo-util.py                                                            #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2022 science + computing ag                              #
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
    def __init__(self, url, polling_interval, timeout):
        logger.debug('Initialising PeekabooUtil')
        logger.debug('Opening connection %s', url)
        self.url = url
        self.polling_interval = polling_interval
        self.timeout = timeout

    def ping(self, _):
        """ Send ping request to daemon and optionally print response. """
        logger.debug("Sending ping...")
        try:
            r = requests.get(
                urllib.parse.urljoin(self.url, "/ping"),
                timeout=self.timeout)
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

    def scan_file(self, args):
        """ Scan the supplied filenames with peekaboo and output result """
        jobs = []
        for filename in args.filename:
            logger.debug('Submitting file %s', filename)

            content_type = None
            if args.content_type:
                ct_popped = args.content_type.pop(0)
                # empty string is treated as no selection to allow specificaion
                # for later file arguments still
                if ct_popped:
                    content_type = ct_popped
                    logger.debug('Using content type %s', content_type)

            content_disposition = None
            if args.content_disposition:
                cd_popped = args.content_disposition.pop(0)
                if cd_popped:
                    content_disposition = cd_popped
                    logger.debug(
                        'Using content disposition %s', content_disposition)

            with open(filename, 'rb') as upload_file:
                submit_name = os.path.basename(filename)
                files = {'file': (submit_name, upload_file, content_type)}
                headers = {'x-content-disposition': content_disposition}

                # NOTE: As of this writing, requests via urllib3 1.26.x encodes
                # filenames according to a WHATWG HTML5 spec draft using
                # percent encoding and backslash escaping. Peekaboo via sanic
                # only supports part of the current WHATWG HTML5 spec (no
                # longer draft) by reverting double quote escaping (%22 -> ").
                # We cannot (without serious hacking) switch requests to use
                # RFC2231 encoding from here. Therefore filenames containing
                # special characters can not currently be correctly transferred
                # using this command. urllib3 has already been adjusted to
                # default to the current version of the HTML5 escaping scheme.
                # So sanic hopefully doing the same there's a chance this will
                # sort itself out by itself eventually.
                response = requests.post(urllib.parse.urljoin(
                    self.url, '/v1/scan'), files=files, headers=headers,
                    timeout=self.timeout)

            json_resp = response.json()
            job_id = json_resp.get('job_id')
            if job_id is None:
                logger.error('Job submission failed: %s', json_resp.get(
                    'message', 'No explanation given by Peekaboo'))
                continue

            logger.debug('File %s submitted as job %d', filename, job_id)

            jobs.append(job_id)

        exit_code = 0
        while True:
            jobs_left = []
            for job in jobs:
                response = requests.get(urllib.parse.urljoin(
                    self.url, f'/v1/report/{job}'), timeout=self.timeout)

                if response.status_code == 404:
                    jobs_left.append(job)
                    continue

                json_resp = response.json()
                if json_resp['result'] == 'bad':
                    print(f"{job}: The file has been categorized 'bad'")
                    exit_code = 1

                logger.info("%d: %s", job, json_resp['reason'])

            if not jobs_left:
                break

            jobs = jobs_left
            time.sleep(self.polling_interval)

        return exit_code

def main():
    """ The peekaboo-util main program. """
    # do not use store_true and store_false because it initializes the dest to
    # its opposite instead of None which interferes with our merging-down of
    # global parser values if not specified per command
    common_args = [
        {
            'args': ['-v', '--verbose'],
            'kwargs': {
                'action': 'store_const', 'const': True, 'required': False,
                'help': 'List results of all files not only bad ones'},
        }, {
            'args': ['-vv', '--verbose2'],
            'kwargs': {
                'action': 'store_const', 'const': True, 'required': False,
                'help': 'List detailed analysis results of every rule'},
        }, {
            'args': ['-d', '--debug'],
            'kwargs': {
                'action': 'store_const', 'const': True, 'required': False,
                'help': 'Output additional diagnostics'},
        }, {
            'args': ['-t', '--timeout'],
            'kwargs': {
                'type': float, 'required': False, 'default': None,
                'help': 'Communications timeout'},
        }, {
            'args': ['-i', '--polling-interval'],
            'kwargs': {
                'type': int, 'required': False, 'default': 5,
                'help': 'Polling interval'},
        }, {
            'args': ['-r', '--remote-url'],
            'kwargs': {
                'action': 'store', 'required': False,
                'default': 'http://127.0.0.1:8100/v1/',
                'help': 'URL to Peekaboo instance e.g. '
                        'http://127.0.0.1:8100/v1/'},
        }
    ]

    # using the common parser as parent to the command parser does not work as
    # the subcommand arguments will completely replace the command parser
    # defaults and values even if not specified on the command line
    common_parser = argparse.ArgumentParser(add_help=False)
    command_parser = argparse.ArgumentParser()
    for common_arg in common_args:
        args, kwargs = common_arg['args'], common_arg['kwargs']
        global_kwargs = kwargs.copy()

        # subcommands args must not have defaults for the global args and
        # potentially their defaults to be queried
        kwargs.pop('default', None)
        common_parser.add_argument(*args, **kwargs)

        # again, dest can not be the same because the subparser arguments will
        # completely replace the command parser value and defaults even if not
        # specified on the command line
        dest = kwargs.get('dest')
        if dest is None:
            dest = args[1].lstrip('-').replace('-', '_')
        common_arg['dest'] = dest
        global_kwargs['dest'] = "global_%s" % dest
        command_parser.add_argument(*args, **global_kwargs)

    command_parser.set_defaults(func=PeekabooUtil.ping)

    subparsers = command_parser.add_subparsers(help='commands')
    scan_file_parser = subparsers.add_parser(
        'scan-file', help='Scan a file and report it', parents=[common_parser])
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

    scan_file_parser.set_defaults(func=PeekabooUtil.scan_file)

    ping_parser = subparsers.add_parser(
        'ping', help='Ping the daemon', parents=[common_parser])
    ping_parser.set_defaults(func=PeekabooUtil.ping)

    args = command_parser.parse_args()

    # merge down global values or defaults
    for common_arg in common_args:
        dest = common_arg['dest']

        # dest is not present if no subcommand was specified, so check with
        # hasattr as well
        if not hasattr(args, dest) or getattr(args, dest) is None:
            global_value = getattr(args, "global_%s" % dest)
            setattr(args, dest, global_value)

    logger.setLevel(logging.ERROR)
    if args.verbose:
        logger.setLevel(logging.INFO)
    if args.verbose2 or args.debug:
        logger.setLevel(logging.DEBUG)

    try:
        util = PeekabooUtil(
            args.remote_url, args.polling_interval, args.timeout)
    except socket.error as error:
        logger.error("Error connecting to peekaboo: %s", error)
        return 2

    return args.func(util, args)


if __name__ == "__main__":
    sys.exit(main())
