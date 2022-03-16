###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# server.py                                                                   #
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

""" This module implements the Peekaboo server, i.e. the frontend to the
client. """

import asyncio
import email.utils
import logging
import urllib.parse

import sanic
import sanic.headers
import sanic.response

from peekaboo.db import PeekabooDatabaseError

logger = logging.getLogger(__name__)

class PeekabooServer:
    """ A class wrapping the server components of Peekaboo. """
    def __init__(self, host, port, job_queue, sample_factory,
                 request_queue_size, db_con):
        """ Initialise a new server and start it. All error conditions are
        returned as exceptions.

        @param host: The local address to bind the socket to.
        @type host: String
        @param port: The local port to listen on for client connections.
        @type port: int
        @param job_queue: A reference to the job queue for submission of
                          samples.
        @type job_queue: JobQueue
        @param sample_factory: A reference to a sample factory for creating new
                               samples.
        @type sample_factory: SampleFactory
        @param request_queue_size: Number of requests that may be pending on
                                   the socket.
        @type request_queue_size: int
        """
        logger.debug('Starting up server.')
        self.app = sanic.Sanic("PeekabooAV", configure_logging=False)
        self.app.config.FALLBACK_ERROR_FORMAT = "json"

        # silence sanic to a reasonable amount
        logging.getLogger('sanic.root').setLevel(logging.WARNING)
        logging.getLogger('sanic.access').setLevel(logging.WARNING)

        self.loop = asyncio.get_event_loop()
        self.server_coroutine = self.app.create_server(
            host=host, port=port, return_asyncio_server=True,
            backlog=request_queue_size,
            asyncio_server_kwargs=dict(start_serving=False))
        self.server = None
        self.job_queue = job_queue
        self.sample_factory = sample_factory
        self.db_con = db_con
        # remember for diagnostics
        self.host = host
        self.port = port

        self.app.add_route(self.hello, '/')
        self.app.add_route(self.ping, '/ping')
        self.app.add_route(self.scan, "/v1/scan", methods=['POST'])
        self.app.add_route(
            self.report, '/v1/report/<job_id:int>', methods=['GET'])

    async def hello(self, _):
        """ hello endpoint as fallback and catch all

        @returns: hello world json response
        """
        return sanic.response.json({'hello': 'PeekabooAV'})

    async def ping(self, _):
        """ ping endpoint for diagnostics

        @returns: pong json response
        """
        return sanic.response.json({'answer': 'pong'})

    async def scan(self, request):
        """ scan endpoint for job submission

        @param request: sanic request object
        @type request: sanic.Request
        @returns: json response containing ID of newly created job
        """
        # this is sanic's multipart/form-data parser in a version that knows
        # that our file field contains binary data. This allows transferring
        # files without a filename. The generic parser would treat those as
        # text fields and try to decode them using the form charset or UTF-8 as
        # a fallback and cause errors such as: UnicodeDecodeError: 'utf-8'
        # codec can't decode byte 0xc0 in position 1: invalid start byte
        content_type, parameters = sanic.headers.parse_content_header(
            request.content_type)

        # application/x-www-form-urlencoded is inefficient at transporting
        # binary data. Also it needs a separate field to transfer the filename.
        # Make clear here that we do not support that format (yet).
        if content_type != 'multipart/form-data':
            logger.error('Invalid content type %s', content_type)
            return sanic.response.json(
                {'message': 'Invalid content type, use multipart/form-data'},
                400)

        boundary = parameters["boundary"].encode("utf-8")
        form_parts = request.body.split(boundary)
        # split above leaves preamble in form_parts[0] and epilogue in
        # form_parts[2]
        num_fields = len(form_parts) - 2
        if num_fields <= 0:
            logger.error('Invalid MIME structure in request, no fields '
                         'or preamble or epilogue missing')
            return sanic.response.json(
                {'message': 'Invalid MIME structure in request'}, 400)

        if num_fields != 1:
            logger.error('Invalid number of fields in form: %d', num_fields)
            return sanic.response.json(
                {'message': 'Invalid number of fields in form, we accept '
                    'only one field "file"'}, 400)

        form_part = form_parts[1]
        file_name = None
        content_type = None
        field_name = None
        line_index = 2
        line_end_index = 0
        while line_end_index != -1:
            line_end_index = form_part.find(b'\r\n', line_index)
            # this constitutes a hard requirement for the multipart headers
            # (and filenames therein) to be UTF-8-encoded. There are some
            # obscure provisions for transferring an encoding in RFC7578
            # section 5.1.2 for HTML forms which don't apply here so its
            # fallback to UTF-8 applies. This is no problem for our field name
            # (ASCII) and file names in RFC2231 encoding. For HTML5-style
            # percent-encoded filenames it means that whatever isn't
            # percent-encoded needs to be UTF-8 encoded. There are no rules in
            # HTML5 currently to percent-encode any UTF-8 byte sequences.
            form_line = form_part[line_index:line_end_index].decode('utf-8')
            line_index = line_end_index + 2

            if not form_line:
                break

            colon_index = form_line.index(':')
            idx = colon_index + 2
            form_header_field = form_line[0:colon_index].lower()

            # parse_content_header() reverts some of the percent encoding as
            # per HTML5 WHATWG spec. As it is a "living standard" (i.e. moving
            # target), it has changed over the years. There used to be
            # backslash doubling and explicit control sequence encoding. As of
            # this writing this has been changed to escaping only newline,
            # linefeed and double quote. Sanic only supports the double quote
            # part of that: %22 are reverted back to %. Luckily this interacts
            # reasonably well with RFC2231 decoding below since that would do
            # the same.
            #
            # There is no way to tell what version of the standard (or draft
            # thereof) the client was following when encoding. It seems accepted
            # practice in the browser world to just require current versions of
            # everything so their behaviour hopefully converges eventually.
            # This is also the reason why we do not try to improve upon it here
            # because it's bound to become outdated.
            #
            # NOTE: Since we fork the sanic code here we need to keep track of
            # its changes, particularly how it interacts with RFC2231 encoding
            # if escaping of the escape character %25 is ever added to the
            # HTML5 WHATWG spec. In that case parse_content_header() would
            # start breaking the RFC2231 encoding which would explain why its
            # use is forbidden in RFC7578 section 4.2 via RFC5987.
            form_header_value, form_parameters = sanic.headers.parse_content_header(
                form_line[idx:]
            )

            if form_header_field == 'content-disposition':
                field_name = form_parameters.get('name')
                file_name = form_parameters.get('filename')

                # non-ASCII filenames in RFC2231, "filename*" format
                if file_name is None and form_parameters.get('filename*'):
                    encoding, _, value = email.utils.decode_rfc2231(
                        form_parameters['filename*']
                    )
                    file_name = urllib.parse.unquote(value, encoding=encoding)
            elif form_header_field == 'content-type':
                content_type = form_header_value

        if field_name != 'file':
            logger.error('Field file missing from request')
            return sanic.response.json(
                {'message': 'Field "file" missing from request'}, 400)

        file_content = form_part[line_index:-4]
        content_disposition = request.headers.get('x-content-disposition')
        sample = self.sample_factory.make_sample(
            file_content, file_name,
            content_type, content_disposition)

        try:
            await self.db_con.analysis_add(sample)
        except PeekabooDatabaseError as dberr:
            logger.error('Failed to add analysis to database: %s', dberr)
            return sanic.response.json(
                {'message': 'Failed to add analysis to database'}, 500)

        if not self.job_queue.submit(sample):
            logger.error('Error submitting sample to job queue')
            return sanic.response.json(
                {'message': 'Error submitting sample to job queue'}, 500)

        # send answer to client
        return sanic.response.json({'job_id': sample.id}, 200)

    async def report(self, _, job_id):
        """ report endpoint for report retrieval by job ID

        @param request: sanic request object
        @type request: sanic.Request
        @param job_id: job ID extracted from endpoint path
        @type job_id: int
        @returns: report json response
        """
        if not job_id:
            return sanic.response.json(
                {'message': 'job ID missing from request'}, 400)

        try:
            job_info = await self.db_con.analysis_retrieve(job_id)
        except PeekabooDatabaseError as dberr:
            logger.error('Failed to retrieve analysis result from '
                         'database: %s', dberr)
            return sanic.response.json(
                {'message': 'Failed to retrieve analysis result '
                            'from database'}, 500)

        if job_info is None:
            logger.debug('No analysis result yet for job %d', job_id)
            return sanic.response.json(
                {'message': 'No analysis result yet for job %d' % job_id}, 404)

        reason, result = job_info
        return sanic.response.json({
            'result': result.name,
            'reason': reason,
            # FIXME: depends on saving the report to the database
            # 'report': report,
            }, 200)

    def serve(self):
        """ Serves requests until shutdown is requested from the outside. """
        self.server = self.loop.run_until_complete(self.server_coroutine)

        # sanic 21.9 introduced an explicit startup that finalizes the app,
        # particularly the request routing. So we need to run it if present.
        if hasattr(self.server, 'startup'):
            self.loop.run_until_complete(self.server.startup())

        self.loop.run_until_complete(self.server.start_serving())
        logger.info('Peekaboo server is now listening on %s:%d',
                    self.host, self.port)
        self.loop.run_until_complete(self.server.wait_closed())
        logger.debug('Server shut down.')

    def shut_down(self):
        """ Triggers a shutdown of the server, used by the signal handler and
        potentially other components to cause the main loop to exit. """
        logger.debug('Server shutdown requested.')
        if self.server is not None:
            self.server.close()
