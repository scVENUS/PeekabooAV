###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# server.py                                                                   #
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

""" This module implements the Peekaboo server, i.e. the frontend to the
client. """

import errno
import grp
import json
import logging
import os
import stat
import socket
import socketserver
from threading import Thread, Event, current_thread
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


class PeekabooStreamServer(socketserver.ThreadingUnixStreamServer):
    """ Asynchronous server. """
    def __init__(self, server_address, request_handler_cls, job_queue,
                 sample_factory, bind_and_activate=True,
                 request_queue_size=10, status_change_timeout=60):
        self.server_address = server_address
        self.__job_queue = job_queue
        self.__sample_factory = sample_factory
        self.request_queue_size = request_queue_size
        self.allow_reuse_address = True
        self.status_change_timeout = status_change_timeout
        self.__shutdown_requested = False
        self.__request_triggers = {}

        # no super() since old-style classes
        logger.debug('Starting up server.')
        socketserver.ThreadingUnixStreamServer.__init__(
            self, server_address, request_handler_cls,
            bind_and_activate=bind_and_activate)

    @property
    def job_queue(self):
        """ Return this server's reference to the job queue. Used by handler
        threads to get access to it for submission of samples for processing.
        """
        return self.__job_queue

    @property
    def sample_factory(self):
        """ Return this server's reference to a factory that can create
        pre-configured sample objects. Used by handler threads to get access to
        it for creation of samples prior to submission for processing. """
        return self.__sample_factory

    @property
    def shutting_down(self):
        """ Return True if we've received a shutdown request. """
        return self.__shutdown_requested

    def register_request(self, thread, event):
        """ Register an event for a request being handled to trigger if we want
        it to shut down. """
        self.__request_triggers[thread] = event
        logger.debug('Request registered with server.')

    def deregister_request(self, thread):
        """ Deregister a request which has finished handling and does no logner
        need to be made aware that we want it to shut down. """
        logger.debug('Request deregistered from server.')
        del self.__request_triggers[thread]

    def shutdown(self):
        """ Shut down the server. In our case, notify requests which are
        currently being handled to shut down as well. """
        logger.debug('Server shutting down.')
        self.__shutdown_requested = True
        for thread in self.__request_triggers:
            # wake up the thread so it can see that we're shutting down
            self.__request_triggers[thread].set()

        socketserver.ThreadingUnixStreamServer.shutdown(self)

    def server_close(self):
        """ Finally completely close down the server. """
        # no new connections from this point on
        logger.debug('Removing connection socket %s', self.server_address)
        try:
            os.remove(self.server_address)
        except OSError as oserror:
            logger.warning('Removal of socket %s failed: %s',
                           self.server_address, oserror)

        logger.debug('Closing down server.')
        return socketserver.ThreadingUnixStreamServer.server_close(self)


class PeekabooStreamRequestHandler(socketserver.StreamRequestHandler):
    """ Request handler used by PeekabooStreamServer to handle analysis
    requests. """
    def setup(self):
        # rename thread for higher log message clarity
        thread = current_thread()
        # keep trailing thread number by replacing just the base name
        thread.name = thread.name.replace('Thread-', 'Request-')

        socketserver.StreamRequestHandler.setup(self)
        self.job_queue = self.server.job_queue
        self.sample_factory = self.server.sample_factory
        self.status_change_timeout = self.server.status_change_timeout

        # create an event we will give to all the samples and our server to
        # wake us if they need out attention
        self.status_change = Event()
        self.status_change.clear()

    def handle(self):
        """ Handles an analysis request. """
        # catch wavering clients early on
        logger.debug('New connection incoming.')
        if not self.talk_back([_('Hello, this is Peekaboo.'), '']):
            return

        # parse client input and see if it's valid and whether there are any
        # requests to us in there
        requests = self.parse()
        if not requests:
            return

        # handle client requests. Sample submissions are special in that they
        # submit into our work queue and we need to wait for them to finish. So
        # see if handling the requests did submit something.
        submitted = self.handle_requests(requests)
        if not submitted:
            return

        # wait for jobs submitted by request handling
        if not self.wait(submitted):
            # something went wrong while waiting, i.e. client closed connection
            # or we're shutting down
            return

        # here we know that all samples have reported back
        self.report(submitted)

    def submit_sample(self, api_data):
        """ Submit API supplied file as Sample """
        path = api_data['full_name']
        logger.info("Got run_analysis request for %s", path)
        if not os.path.exists(path):
            self.talk_back(_('ERROR: Path does not exist or no '
                             'permission to access it.'))
            logger.error('Path does not exist or no permission '
                         'to access it.')
            return None

        if not os.path.isfile(path):
            self.talk_back(_('ERRROR: Input is not a file'))
            logger.error('Input is not a file')
            return None

        sample = self.sample_factory.make_sample(
            path, status_change=self.status_change, metainfo=api_data)
        if not self.job_queue.submit(sample, self.__class__):
            self.talk_back(_('Error submitting sample to job queue'))
            # submit will have logged an error
            return None
        return sample

    def parse(self):
        """ Reads and parses an analysis request. This is expected to be a JSON
        structure::

            [ { "full_name": "<path>",
                "name_declared": ...,
                ... },
              { "request": "scan-file",
                "full_name": ... },
              { "request": "ping" },
              ... ]

        The request field is optional with a default of "scan-file".
        Valid requests are:
        * scan-file
        * ping

        scan-file: requires the path of the directory / file to analyse
        in "full_name".

        The maximum buffer size is 16 KiB, because JSON incurs some bloat.
        """
        try:
            client_input = self.request.recv(1024 * 16).rstrip()
        except IOError as ioerror:
            logger.error('Request receive failed: %s', ioerror)
            return None

        try:
            requests = json.loads(client_input)
        except ValueError as error:
            self.talk_back(_('Error: Invalid JSON in request.'))
            logger.error('Invalid JSON in request: %s', error)
            return None

        # do some generic input validation
        if not isinstance(requests, (list, tuple)):
            self.talk_back(_('ERROR: Invalid data structure.'))
            logger.error('Invalid data structure.')
            return None

        for request in requests:
            if not isinstance(request, dict):
                self.talk_back(_('ERROR: Invalid request structure.'))
                logger.error('Invalid request structure.')
                return None

            # default request type is scan-file
            reqtype = request.get('request', 'scan-file')
            if reqtype not in ['scan-file', 'ping']:
                self.talk_back(_('ERROR: Unsupported request %s') % reqtype)
                logger.error('Unsupported request %s', reqtype)
                return None

            if reqtype == 'scan-file' and 'full_name' not in request:
                self.talk_back(_('ERROR: Incomplete data structure.'))
                logger.error('Incomplete data structure.')
                return None

        return requests

    def handle_requests(self, requests):
        """ Handle requests.

        @param requests: list/tuple of dicts describing requests
        @returns: list of submitted samples or None on error
        """
        submitted = []
        for request in requests:
            reqtype = request.get('request', 'scan-file')
            if reqtype == 'scan-file':
                sample = self.submit_sample(request)
                if sample is None:
                    # here we abort the whole batch of requests which is
                    # somewhat excessive since the others might just be pings
                    # or complete successfully. But since we can't fulfill all
                    # the requested analyses and have no way of communicating
                    # that fact individually to the client it's the only option
                    # for now.
                    return None

                submitted.append(sample)
                logger.debug('Created and submitted sample %s', sample)
            elif reqtype == 'ping':
                self.talk_back(json.dumps({'request': 'ping',
                                           'response': 'pong'}))
                logger.debug('ping request received and answered')
            else:
                # paranoia
                logger.error('Unknown request "%s" got through input '
                             'validation', reqtype)
                self.talk_back(_('ERROR: Unsupported request %s') % reqtype)
                return None

        return submitted

    def wait(self, to_be_analysed):
        """ Wait for submitted analysis jobs to finished.

        @param to_be_analysed: samples that have been submitted for analysis
                               and which will report back to us when they're
                               finished.
        @type to_be_analysed: List of Sample objects
        """
        # register with our server so it can notify us if it wants us to shut
        # down
        # NOTE: Every exit point from this routine needs to deregister this
        # request from the server to avoid memory leaks. Unfortunately, the
        # server cannot do this iteself on shutdown_request() because it does
        # not have any thread ID available there.
        self.server.register_request(self, self.status_change)

        # wait for results to come in
        while to_be_analysed:
            # wait for an event to signal that its status has changed or
            # timeout expires
            if not self.status_change.wait(self.status_change_timeout):
                # keep our client engaged
                # TODO: Impose maximum processing time of our own?
                if not self.talk_back(_('Files are being analyzed...')):
                    # Abort handling this request since no-one's interested
                    # any more. We could dequeue the samples here to avoid
                    # unnecessary work. Instead we'll have them run their
                    # course, assuming that we'll be much quicker
                    # responding if the client decides to resubmit them.
                    self.server.deregister_request(self)
                    return False

                logger.debug('Client updated that samples are still '
                             'processing.')

                # Fall through here and evaluate all samples for paranoia's
                # sake in case our status change event has a race condition.
                # It shouldn't though, because we wait for it, then first clear
                # it and then look at all samples that might have set it. If
                # while doing that another sample sets it and we don't catch it
                # because we've already looked at it, the next wait will
                # immediately return and send us back into checking all samples
                # for status change.

            # see if our server is shutting down and follow it if so
            if self.server.shutting_down:
                self.talk_back(_('Peekaboo is shutting down.'))
                logger.debug('Request shutting down with server.')
                self.server.deregister_request(self)
                return False

            self.status_change.clear()

            # see which samples are done and which are still processing
            still_analysing = []
            for sample in to_be_analysed:
                # remove samples that are done
                if sample.done:
                    continue

                still_analysing.append(sample)

            to_be_analysed = still_analysing

        # deregister notification from server since we've exited our wait loop
        self.server.deregister_request(self)
        return True

    def report(self, done):
        """ Report individual files' and overall verdict to client.

        @param done: List of samples that are done processing and need
                     reporting.
        @type done: List of Sample objects.
        """
        # evaluate results into an overall result: We want to present the
        # client with an overall result instead of confusing them with
        # assertions about individual files. Particularly in the case of
        # AMaViS, this would otherwise lead to messages being passed on as
        # clean where a single attachment evaluated to "good" but analysis of
        # all the others failed.
        result = Result.unchecked
        logger.debug('Determining final verdict to report to client.')
        for sample in done:
            # check if result of this rule is worse than what we know so far
            sample_result = sample.result
            logger.debug('Current overall result: %s, Sample result: %s',
                         result.name, sample_result.name)
            if sample_result >= result:
                result = sample_result

            # and unconditionally send out its report to the client (plus an
            # empty line)
            if not self.talk_back(sample.peekaboo_report + ['']):
                return

        # report overall result.
        logger.debug('Reporting batch as "%s" to client', result.name)
        loc_verdict = _('The file collection has been categorized "%s"')
        overall = [loc_verdict % result.name]

        # Add untranslated verdict (if the above actually got translated) for
        # potential pattern matching of the client to reliably latch on to.
        # Need to duplicate strings here for pygettext and pybabel extract to
        # find the translatable one in the above _().
        verdict = 'The file collection has been categorized "%s"'
        if verdict != loc_verdict:
            overall.append(verdict % result.name)

        # append newline and send
        overall.append('')
        if not self.talk_back(overall):
            return

        # shut down connection
        logger.debug('Results reported back to client - closing connection.')

    def talk_back(self, msgs):
        """ Send message(s) back to the client. Automatically appends newline
        to each message.

        @param msgs: message(s) to send to client.
        @type msgs: string or (list or tuple of strings)

        @returns: True on successful sending of all messages, False on error of
                  sending and None specifically if sending failed because the
                  client closed the connection. """
        if not isinstance(msgs, (list, tuple)):
            msgs = (msgs, )

        for msg in msgs:
            try:
                # FIXME: Hard-coded, arbitrary encoding since we have no
                # clearly defined protocol here.
                self.request.sendall(('%s\n' % msg).encode('utf-8'))
            except IOError as ioerror:
                if ioerror.errno == errno.EPIPE:
                    logger.warning('Client closed connection on us: %s',
                                   ioerror)
                    return None

                logger.warning('Error talking back to client: %s', ioerror)
                return False

        return True


class PeekabooServer(object):
    """ A class wrapping the server components of Peekaboo. """
    def __init__(self, sock_file, job_queue, sample_factory, request_queue_size,
                 sock_group = None,
                 sock_mode = stat.S_IREAD | stat.S_IWRITE |
                             stat.S_IRGRP | stat.S_IWGRP |
                             stat.S_IROTH | stat.S_IWOTH):

        """ Initialise a new server and start it. All error conditions are
        returned as exceptions.

        @param sock_file: The path of the socket file.
        @type sock_file: String
        @param job_queue: A reference to the job queue for submission of
                          samples.
        @type job_queue: JobQueue
        @param sample_factory: A reference to a sample factory for creating new
                               samples.
        @type sample_factory: SampleFactory
        @param request_queue_size: Number of requests that may be pending on
                                   the socket.
        @type request_queue_size: int
        @param sock_group: An optional name of a group that shall own the
                           socket.
        @type sock_group: String
        @param sock_mode: The permission bits of the socket.
        @type sock_mode: Integer (bitmask)
        """
        self.server = None
        self.runner = None

        self.server = PeekabooStreamServer(
            sock_file,
            PeekabooStreamRequestHandler,
            job_queue=job_queue,
            sample_factory=sample_factory,
            request_queue_size=request_queue_size)

        self.runner = Thread(target=self.server.serve_forever, name="Server")
        self.runner.start()

        try:
            if sock_mode is not None:
                os.chmod(sock_file, sock_mode)

            if sock_group is not None:
                gid = grp.getgrnam(sock_group)[2]
                os.chown(sock_file, -1, gid)
        except:
            self.shutdown()
            raise

        logger.info('Peekaboo server is now listening on %s',
                    self.server.server_address)

    def shutdown(self):
        """ Shuts down the server. """
        self.server.shutdown()
        self.server.server_close()
        self.runner.join()
