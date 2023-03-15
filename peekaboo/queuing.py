###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# queuing.py                                                                  #
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

""" The main job queue with workers. """


import asyncio
import logging

from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.exceptions import (
    PeekabooAnalysisDeferred, PeekabooDatabaseError, PeekabooConfigException,
    PeekabooRulesetConfigError)

logger = logging.getLogger(__name__)


class JobQueue:
    """ Peekaboo's queuing system. """
    def __init__(self, ruleset_config, db_con, analyzer_config,
                 worker_count=4, cluster_duplicate_check_interval=5,
                 threadpool=None):
        """ Initialise job queue by creating n Peekaboo workers to process
        samples.

        @param ruleset_config: the ruleset configuration
        @type ruleset_config: PeekabooConfigParser
        @param db_con: Database connection object for cluster instance
                       coordination, i.e. saving sample info.
        @type db_con: PeekabooDatabase
        @param worker_count: The number of workers to create. Defaults to 4.
        @type worker_count: int
        @param cluster_duplicate_check_interval: How long to wait inbetween
                                                 checks for stale cluster
                                                 duplicate locks.
        @type cluster_duplicate_check_interval: int
        @raises PeekabooConfigException: if an error occured in configuration.
        """
        self.db_con = db_con
        self.jobs = asyncio.Queue()
        self.workers = []
        self.worker_count = worker_count
        self.threadpool = threadpool

        self.ruleset_engine = RulesetEngine(
            ruleset_config, self, db_con, analyzer_config,
            cluster_duplicate_check_interval, threadpool)

        # we start these here because they do no lengthy init and starting can
        # not fail. We need this here to avoid races in startup vs. shutdown by
        # signal to avoid continuing running in a half-inited/half-shutdown
        # state.
        for wno in range(0, self.worker_count):
            logger.debug("Create Worker %d", wno)
            worker = Worker(wno, self, self.ruleset_engine, db_con)
            self.workers.append(worker)

        logger.info('Created %d Workers.', self.worker_count)

    async def start(self):
        """ Start up the job queue including resource initialisation. """
        awaitables = []
        for worker in self.workers:
            awaitables.append(await worker.start())

        # create a single ruleset engine for all workers, instantiates all the
        # rules based on the ruleset configuration, may start up long-lived
        # analyzer instances which are shared as well, is otherwise stateless
        # to allow concurrent use by multiple worker
        try:
            awaitables.extend(await self.ruleset_engine.start())
        except (KeyError, ValueError, PeekabooConfigException) as error:
            self.shut_down()
            await self.close_down()
            raise PeekabooConfigException(
                'Ruleset configuration error: %s' % error)
        except PeekabooRulesetConfigError as error:
            self.shut_down()
            await self.close_down()
            raise PeekabooConfigException(error)

        return awaitables

    async def submit(self, sample):
        """
        Adds a Sample object to the job queue.
        If the queue is full, we block for 300 seconds and then throw an
        exception.

        @param sample: The Sample object to add to the queue.
        """
        await self.jobs.put(sample)
        logger.debug("%d: New sample submitted to job queue", sample.id)

    async def dequeue(self):
        """ Remove a sample from the queue. Used by the workers to get their
        work. Blocks indefinitely until some work is available. """
        return await self.jobs.get()

    def shut_down(self):
        """ Trigger a shutdown of the queue including the workers. """
        logger.info("Queue shutdown requested. Signalling workers.")

        if self.ruleset_engine is not None:
            self.ruleset_engine.shut_down()

        # tell all workers to shut down
        for worker in self.workers:
            worker.shut_down()

    async def close_down(self):
        """ Wait for workers to stop and free up resources. """
        for worker in self.workers:
            await worker.close_down()

        if self.ruleset_engine is not None:
            await self.ruleset_engine.close_down()

        logger.info("Queue shut down.")


class Worker:
    """ A Worker to process a sample. """
    def __init__(self, wid, job_queue, ruleset_engine, db_con):
        # whether we should run
        self.task = None
        self.worker_id = wid
        self.worker_name = "Worker-%d" % wid
        self.job_queue = job_queue
        self.ruleset_engine = ruleset_engine
        self.db_con = db_con

    async def start(self):
        self.task = asyncio.ensure_future(self.run())
        if hasattr(self.task, "set_name"):
            self.task.set_name(self.worker_name)
        return self.task

    async def run(self):
        while True:
            logger.debug('Worker %d: Ready', self.worker_id)

            # wait blocking for next job
            sample = await self.job_queue.dequeue()

            logger.info('%d: Worker %d: Processing sample',
                        sample.id, self.worker_id)

            # The following used to be one big try/except block catching any
            # exception. This got complicated because in the case of
            # CuckooReportPending we use exceptions for control flow as well
            # (which might be questionable in itself). Instead of catching,
            # logging and ignoring errors here if workers start to die again
            # because of uncaught exceptions we should improve error handling
            # in the subroutines causing it.

            try:
                await self.ruleset_engine.run(sample)
            except PeekabooAnalysisDeferred:
                logger.debug('%d: Report still pending', sample.id)
                continue

            if sample.result >= Result.failed:
                await sample.dump_processing_info()

            sample.mark_done()

            logger.debug('%d: Saving results to database', sample.id)
            try:
                await self.db_con.analysis_update(sample)
            except PeekabooDatabaseError as dberr:
                logger.error('%d: Failed to save analysis result to '
                             'database: %s', sample.id, dberr)
                # no showstopper, we can limp on without caching in DB

            # now is the time to submit any potential duplicates of this sample
            # whose processing was deferred by rules
            await self.ruleset_engine.submit_duplicates(sample)

    def shut_down(self):
        """ Asynchronously initiate worker shutdown. """
        logger.info("Worker %d: shutdown requested.", self.worker_id)
        if self.task is not None:
            self.task.cancel()

    async def close_down(self):
        """ Wait for the worker to close down and retrieve any exceptions
        thrown. """
        if self.task is not None:
            try:
                await self.task
            # we cancelled the task so a CancelledError is expected
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception(
                    "Unexpected exception in worker %d", self.worker_id)

        logger.info('Worker %d: Stopped', self.worker_id)
