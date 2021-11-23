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

import asyncio
import logging

import sanic
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
        self.app = sanic.Sanic("PeekabooAV")
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
        self.app.add_route(self.report, '/v1/report/<job_id>', methods=['GET'])

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
        sample_file = request.files.get('file')
        if sample_file is None:
            logger.error('File missing from request')
            return sanic.response.json(
                {'message': 'file missing from request'}, 400)

        content_disposition = request.headers.get('x-content-disposition')
        sample = self.sample_factory.make_sample(
            sample_file.body, sample_file.name,
            sample_file.type, content_disposition)

        try:
            self.db_con.analysis_add(sample)
        except PeekabooDatabaseError as dberr:
            logger.error('Failed to add analysis to database: %s', dberr)
            return sanic.response.json(
                {'message': 'Failed to add analysis to database'}, 500)

        if not self.job_queue.submit(sample, self.__class__):
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
        @type job_id: String
        @returns: report json response
        """
        if not job_id:
            return sanic.response.json(
                {'message': 'job ID missing from request'}, 400)

        try:
            job_info = self.db_con.analysis_retrieve(job_id)
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
        return sanic.response.json(
            {'report': [reason], 'result': result.value}, 200)

    def serve(self):
        """ Serves requests until shutdown is requested from the outside. """
        self.server = self.loop.run_until_complete(self.server_coroutine)
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
