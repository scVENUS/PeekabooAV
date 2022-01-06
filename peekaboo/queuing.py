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

""" The main job queue with workers and a cluster duplicate handler. """


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

        # keep a backlog of samples with hashes identical to samples currently
        # in analysis to avoid analysing multiple identical samples
        # simultaneously. Once one analysis has finished, we can submit the
        # others and the ruleset will notice that we already know the result.
        self.duplicates = {}
        self.duplock = asyncio.Lock()

        # keep a similar backlog of samples currently being processed by
        # other instances so we can regularly try to resubmit them and re-use
        # the other instances' cached results from the database
        self.cluster_duplicates = {}

        self.ruleset_engine = RulesetEngine(
            ruleset_config, self, db_con, analyzer_config, threadpool)

        # we start these here because they do no lengthy init and starting can
        # not fail. We need this here to avoid races in startup vs. shutdown by
        # signal to avoid continuing running in a half-inited/half-shutdown
        # state.
        for wno in range(0, self.worker_count):
            logger.debug("Create Worker %d", wno)
            worker = Worker(wno, self, self.ruleset_engine, db_con)
            self.workers.append(worker)

        logger.info('Created %d Workers.', self.worker_count)

        self.cluster_duplicate_handler = None
        if cluster_duplicate_check_interval:
            logger.debug(
                "Creating cluster duplicate handler with check "
                "interval %d.", cluster_duplicate_check_interval)
            self.cluster_duplicate_handler = ClusterDuplicateHandler(
                self, cluster_duplicate_check_interval)
        else:
            logger.debug("Disabling cluster duplicate handler.")

    async def start(self):
        """ Start up the job queue including resource initialisation. """
        for worker in self.workers:
            await worker.start()

        if self.cluster_duplicate_handler:
            await self.cluster_duplicate_handler.start()

        # create a single ruleset engine for all workers, instantiates all the
        # rules based on the ruleset configuration, may start up long-lived
        # analyzer instances which are shared as well, is otherwise stateless
        # to allow concurrent use by multiple worker
        try:
            await self.ruleset_engine.start()
        except (KeyError, ValueError, PeekabooConfigException) as error:
            self.shut_down()
            await self.close_down()
            raise PeekabooConfigException(
                'Ruleset configuration error: %s' % error)
        except PeekabooRulesetConfigError as error:
            self.shut_down()
            await self.close_down()
            raise PeekabooConfigException(error)

    async def submit(self, sample):
        """
        Adds a Sample object to the job queue.
        If the queue is full, we block for 300 seconds and then throw an
        exception.

        @param sample: The Sample object to add to the queue.
        @raises Full: if the queue is full.
        """
        sample_hash = await sample.sha256sum
        duplicate = None
        cluster_duplicate = None
        resubmit = None

        # we have to lock this down because async routines called from here may
        # allow us to be called again concurrently from the event loop
        async with self.duplock:
            # check if a sample with same hash is currently in flight
            duplicates = self.duplicates.get(sample_hash)
            if duplicates is not None:
                # we are regularly resubmitting samples, e.g. after we've
                # noticed that cuckoo is finished analysing them. This
                # obviously isn't a duplicate but continued processing of the
                # same sample.
                if duplicates['master'] == sample:
                    resubmit = sample.id
                    await self.jobs.put(sample)
                else:
                    # record the to-be-submitted sample as duplicate and do
                    # nothing
                    duplicate = sample.id
                    duplicates['duplicates'].append(sample)
            else:
                # are we the first of potentially multiple instances working on
                # this sample?
                try:
                    locked = await self.db_con.mark_sample_in_flight(sample)
                except PeekabooDatabaseError as dberr:
                    logger.error(dberr)
                    return False

                if locked:
                    # initialise a per-duplicate backlog for this sample which
                    # also serves as in-flight marker and submit to queue
                    self.duplicates[sample_hash] = {
                        'master': sample,
                        'duplicates': [],
                    }
                    await self.jobs.put(sample)
                else:
                    # another instance is working on this
                    if self.cluster_duplicates.get(sample_hash) is None:
                        self.cluster_duplicates[sample_hash] = []

                    cluster_duplicate = sample.id
                    self.cluster_duplicates[sample_hash].append(sample)

        if duplicate is not None:
            logger.debug(
                "%d: Sample is duplicate and waiting for running analysis "
                "to finish", duplicate)
        elif cluster_duplicate is not None:
            logger.debug(
                "%d: Sample is concurrently processed by another instance "
                "and held", cluster_duplicate)
        elif resubmit is not None:
            logger.debug("%d: Resubmitted sample to job queue", resubmit)
        else:
            logger.debug("%d: New sample submitted to job queue", sample.id)

        return True

    async def submit_cluster_duplicates(self):
        """ Submit samples held while being processed by another cluster
        instance back into the job queue if they have finished processing. """
        if not self.cluster_duplicates.keys():
            return True

        submitted_cluster_duplicates = []

        async with self.duplock:
            # try to submit *all* samples which have been marked as being
            # processed by another instance concurrently
            # get the items view on a copy of the cluster duplicate backlog
            # because we will change it by removing entries which would raise a
            # RuntimeException
            cluster_duplicates = self.cluster_duplicates.copy().items()
            for sample_hash, sample_duplicates in cluster_duplicates:
                # try to mark as in-flight
                try:
                    locked = await self.db_con.mark_sample_in_flight(
                        sample_duplicates[0])
                except PeekabooDatabaseError as dberr:
                    logger.error(dberr)
                    return False

                if locked:
                    if self.duplicates.get(sample_hash) is not None:
                        logger.error(
                            "Possible backlog corruption for sample %d! "
                            "Please file a bug report. Trying to continue...",
                            sample.id)
                        continue

                    # submit one of the held-back samples as a new master
                    # analysis in case the analysis on the other instance
                    # failed and we have no result in the database yet. If all
                    # is well, this master should finish analysis very quickly
                    # using the stored result, causing all the duplicates to be
                    # submitted and finish quickly as well.
                    sample = sample_duplicates.pop()
                    self.duplicates[sample_hash] = {
                        'master': sample,
                        'duplicates': sample_duplicates,
                    }
                    submitted_cluster_duplicates.append(sample.id)
                    await self.jobs.put(sample)
                    del self.cluster_duplicates[sample_hash]

        if len(submitted_cluster_duplicates) > 0:
            logger.debug(
                "Submitted cluster duplicates (and potentially their "
                "duplicates) from backlog: %s", submitted_cluster_duplicates)

        return True

    async def clear_stale_in_flight_samples(self):
        """ Clear any stale in-flight sample logs from the database. """
        try:
            cleared = await self.db_con.clear_stale_in_flight_samples()
        except PeekabooDatabaseError as dberr:
            logger.error(dberr)
            cleared = False

        return cleared

    async def submit_duplicates(self, sample_hash):
        """ Check if any samples have been held from processing as duplicates
        and submit them now. Clear the original sample whose duplicates have
        been submitted from the in-flight list.

        @param sample_hash: Hash of sample to check for duplicates
        """
        submitted_duplicates = []

        async with self.duplock:
            # duplicates which have been submitted from the backlog still
            # report done but do not get registered as potentially having
            # duplicates because we expect the ruleset to identify them as
            # already known and process them quickly now that the first
            # instance has gone through full analysis. Therefore we can ignore
            # them here.
            if sample_hash not in self.duplicates:
                return

            # submit all samples which have accumulated in the backlog
            for sample in self.duplicates[sample_hash]['duplicates']:
                submitted_duplicates.append(sample.id)
                await self.jobs.put(sample)

            sample = self.duplicates[sample_hash]['master']
            try:
                await self.db_con.clear_sample_in_flight(sample)
            except PeekabooDatabaseError as dberr:
                logger.error(dberr)

            del self.duplicates[sample_hash]

        logger.debug("%d: Cleared sample from in-flight list", sample.id)
        if len(submitted_duplicates) > 0:
            logger.debug(
                "Submitted duplicates from backlog: %s", submitted_duplicates)

    async def done(self, sample):
        """ Perform cleanup actions after sample processing is done:
        1. Submit held duplicates and
        2. notify request handler that sample processing is done.

        @param sample: The Sample object to post-process. """
        await self.submit_duplicates(await sample.sha256sum)

    async def dequeue(self):
        """ Remove a sample from the queue. Used by the workers to get their
        work. Blocks indefinitely until some work is available. """
        return await self.jobs.get()

    def shut_down(self):
        """ Trigger a shutdown of the queue including the workers. """
        logger.info("Queue shutdown requested. Signalling workers.")

        if self.ruleset_engine is not None:
            self.ruleset_engine.shut_down()

        if self.cluster_duplicate_handler is not None:
            self.cluster_duplicate_handler.shut_down()

        # tell all workers to shut down
        for worker in self.workers:
            worker.shut_down()

    async def close_down(self):
        """ Wait for workers to stop and free up resources. """
        logger.info("Closing down.")

        for worker in self.workers:
            await worker.close_down()

        if self.cluster_duplicate_handler is not None:
            await self.cluster_duplicate_handler.close_down()

        if self.ruleset_engine is not None:
            await self.ruleset_engine.close_down()

class ClusterDuplicateHandler:
    """ A housekeeper handling submission and cleanup of cluster duplicates.
    """
    def __init__(self, job_queue, interval=5):
        self.job_queue = job_queue
        self.interval = interval
        self.task = None
        self.task_name = "ClusterDuplicateHandler"

    async def start(self):
        self.task = asyncio.ensure_future(self.run())
        self.task.set_name(self.task_name)

    async def run(self):
        logger.debug("Cluster duplicate handler started.")

        while True:
            await asyncio.sleep(self.interval)

            logger.debug("Checking for samples in processing by other "
                         "instances to submit")

            # TODO: Error handling: How do we cause Peekaboo to exit with an
            # error from here? For now just keep trying and hope (database)
            # failure is transient.
            await self.job_queue.clear_stale_in_flight_samples()
            await self.job_queue.submit_cluster_duplicates()

        logger.debug("Cluster duplicate handler shut down.")

    def shut_down(self):
        """ Asynchronously initiate cluster duplicate handler shutdown. """
        logger.debug("Cluster duplicate handler shutdown requested.")
        if self.task is not None:
            self.task.cancel()

    async def close_down(self):
        """ Wait for the cluster duplicate handler to close down and retrieve
        any exceptions thrown. """
        if self.task is not None:
            try:
                await self.task
            # we cancelled the task so a CancelledError is expected
            except asyncio.CancelledError:
                pass


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
        self.task.set_name(self.worker_name)

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

            await self.job_queue.done(sample)

        logger.info('Worker %d: Stopped', self.worker_id)

    def shut_down(self):
        """ Asynchronously initiate worker shutdown. """
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
