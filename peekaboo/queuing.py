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

""" The main job queue and worker threads. """


import logging
import queue
import threading
import time

from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.exceptions import (
    PeekabooAnalysisDeferred, PeekabooDatabaseError, PeekabooConfigException,
    PeekabooRulesetConfigError)

logger = logging.getLogger(__name__)


class JobQueue:
    """ Peekaboo's queuing system. """
    def __init__(self, ruleset_config, db_con, analyzer_config, worker_count=4,
                 queue_timeout=300, shutdown_timeout=60,
                 cluster_duplicate_check_interval=5):
        """ Initialise job queue by creating n Peekaboo worker threads to
        process samples.

        @param ruleset_config: the ruleset configuration
        @type ruleset_config: PeekabooConfigParser
        @param db_con: Database connection object for cluster instance
                       coordination, i.e. saving sample info.
        @type db_con: PeekabooDatabase
        @param worker_count: The amount of worker threads to create. Defaults
                             to 4.
        @type worker_count: int
        @param queue_timeout: How long to block before considering queueing
                              failed.
        @type queue_timeout: int
        @param shutdown_timeout: How long to block before considering shutdown
                                 failed.
        @type shutdown_timeout: int
        @param cluster_duplicate_check_interval: How long to wait inbetween
                                                 checks for stale cluster
                                                 duplicate locks.
        @type cluster_duplicate_check_interval: int
        @raises PeekabooConfigException: if an error occured in configuration.
        """
        self.db_con = db_con
        self.jobs = queue.Queue()
        self.workers = []
        self.worker_count = worker_count
        self.queue_timeout = queue_timeout
        self.shutdown_timeout = shutdown_timeout

        # keep a backlog of samples with hashes identical to samples currently
        # in analysis to avoid analysing multiple identical samples
        # simultaneously. Once one analysis has finished, we can submit the
        # others and the ruleset will notice that we already know the result.
        self.duplicates = {}
        self.duplock = threading.Lock()

        # keep a similar backlog of samples currently being processed by
        # other instances so we can regularly try to resubmit them and re-use
        # the other instances' cached results from the database
        self.cluster_duplicates = {}

        self.ruleset_engine = RulesetEngine(
            ruleset_config, self, db_con, analyzer_config)

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
                "Starting cluster duplicate handler thread with check "
                "interval %d.", cluster_duplicate_check_interval)
            self.cluster_duplicate_handler = ClusterDuplicateHandler(
                self, cluster_duplicate_check_interval)
        else:
            logger.debug("Disabling cluster duplicate handler thread.")

    def start(self):
        """ Start up the job queue including resource initialisation. """
        for worker in self.workers:
            worker.start()

        if self.cluster_duplicate_handler:
            self.cluster_duplicate_handler.start()

        # create a single ruleset engine for all workers, instantiates all the
        # rules based on the ruleset configuration, may start up long-lived
        # analyzer instances which are shared as well, is otherwise stateless
        # to allow concurrent use by multiple worker threads
        try:
            self.ruleset_engine.start()
        except (KeyError, ValueError, PeekabooConfigException) as error:
            self.shut_down()
            self.close_down()
            raise PeekabooConfigException(
                'Ruleset configuration error: %s' % error)
        except PeekabooRulesetConfigError as error:
            self.shut_down()
            self.close_down()
            raise PeekabooConfigException(error)

    def submit(self, sample):
        """
        Adds a Sample object to the job queue.
        If the queue is full, we block for 300 seconds and then throw an
        exception.

        @param sample: The Sample object to add to the queue.
        @raises Full: if the queue is full.
        """
        sample_hash = sample.sha256sum
        duplicate = None
        cluster_duplicate = None
        resubmit = None
        # we have to lock this down because apart from callbacks from our
        # Workers we're also called from the ThreadingUnixStreamServer
        with self.duplock:
            # check if a sample with same hash is currently in flight
            duplicates = self.duplicates.get(sample_hash)
            if duplicates is not None:
                # we are regularly resubmitting samples, e.g. after we've
                # noticed that cuckoo is finished analysing them. This
                # obviously isn't a duplicate but continued processing of the
                # same sample.
                if duplicates['master'] == sample:
                    resubmit = sample.id
                    self.jobs.put(sample, True, self.queue_timeout)
                else:
                    # record the to-be-submitted sample as duplicate and do
                    # nothing
                    duplicate = sample.id
                    duplicates['duplicates'].append(sample)
            else:
                # are we the first of potentially multiple instances working on
                # this sample?
                try:
                    locked = self.db_con.mark_sample_in_flight(sample)
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
                    self.jobs.put(sample, True, self.queue_timeout)
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

    def submit_cluster_duplicates(self):
        """ Submit samples held while being processed by another cluster
        instance back into the job queue if they have finished processing. """
        if not self.cluster_duplicates.keys():
            return True

        submitted_cluster_duplicates = []

        with self.duplock:
            # try to submit *all* samples which have been marked as being
            # processed by another instance concurrently
            # get the items view on a copy of the cluster duplicate backlog
            # because we will change it by removing entries which would raise a
            # RuntimeException
            cluster_duplicates = self.cluster_duplicates.copy().items()
            for sample_hash, sample_duplicates in cluster_duplicates:
                # try to mark as in-flight
                try:
                    locked = self.db_con.mark_sample_in_flight(
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
                    self.jobs.put(sample, True, self.queue_timeout)
                    del self.cluster_duplicates[sample_hash]

        if len(submitted_cluster_duplicates) > 0:
            logger.debug(
                "Submitted cluster duplicates (and potentially their "
                "duplicates) from backlog: %s", submitted_cluster_duplicates)

        return True

    def clear_stale_in_flight_samples(self):
        """ Clear any stale in-flight sample logs from the database. """
        try:
            cleared = self.db_con.clear_stale_in_flight_samples()
        except PeekabooDatabaseError as dberr:
            logger.error(dberr)
            cleared = False

        return cleared

    def submit_duplicates(self, sample_hash):
        """ Check if any samples have been held from processing as duplicates
        and submit them now. Clear the original sample whose duplicates have
        been submitted from the in-flight list.

        @param sample_hash: Hash of sample to check for duplicates
        """
        submitted_duplicates = []
        with self.duplock:
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
                self.jobs.put(sample, True, self.queue_timeout)

            sample = self.duplicates[sample_hash]['master']
            try:
                self.db_con.clear_sample_in_flight(sample)
            except PeekabooDatabaseError as dberr:
                logger.error(dberr)

            del self.duplicates[sample_hash]

        logger.debug("%d: Cleared sample from in-flight list", sample.id)
        if len(submitted_duplicates) > 0:
            logger.debug(
                "Submitted duplicates from backlog: %s", submitted_duplicates)

    def done(self, sample):
        """ Perform cleanup actions after sample processing is done:
        1. Submit held duplicates and
        2. notify request handler thread that sample processing is done.

        @param sample: The Sample object to post-process. """
        self.submit_duplicates(sample.sha256sum)

    def dequeue(self):
        """ Remove a sample from the queue. Used by the workers to get their
        work. Blocks indefinitely until some work is available. If we want to
        wake the workers for some other reason, we send them a None item as
        ping. """
        return self.jobs.get(True)

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

        # put a ping for each worker on the queue. Since they already all know
        # that they're supposed to shut down, each of them will only remove
        # one item from the queue and then exit, leaving the others for their
        # colleagues. For this reason this loop can't be folded into the above!
        for worker in self.workers:
            self.jobs.put(None)

    def close_down(self, timeout=None):
        """ Wait for workers to stop and free up resources. """
        if not timeout:
            timeout = self.shutdown_timeout

        logger.info("Closing down. Giving workers %d seconds to stop", timeout)

        # wait for workers to end
        interval = 1
        for attempt in range(1, timeout // interval + 1):
            still_running = []
            for worker in self.workers:
                if worker.is_alive():
                    still_running.append(worker)

            self.workers = still_running
            if len(self.workers) == 0:
                break

            time.sleep(interval)
            logger.debug('%d: %d workers still running', attempt,
                         len(self.workers))

        if len(self.workers) > 0:
            logger.error("Some workers refused to stop.")

        if self.cluster_duplicate_handler is not None:
            self.cluster_duplicate_handler.join()
        if self.ruleset_engine is not None:
            self.ruleset_engine.close_down()


class ClusterDuplicateHandler(threading.Thread):
    """ A housekeeping thread handling submission and cleanup cluster
    duplicates. """
    def __init__(self, job_queue, interval=5):
        self.shutdown_requested = threading.Event()
        self.shutdown_requested.clear()
        self.job_queue = job_queue
        self.interval = interval
        super().__init__(name="ClusterDuplicateHandler")

    def run(self):
        logger.debug("Cluster duplicate handler started.")

        while not self.shutdown_requested.wait(self.interval):
            logger.debug("Checking for samples in processing by other "
                         "instances to submit")
            # TODO: Error handling: How do we cause Peekaboo to exit with an
            # error from here? For now just keep trying and hope (database)
            # failure is transient.
            self.job_queue.clear_stale_in_flight_samples()
            self.job_queue.submit_cluster_duplicates()

        logger.debug("Cluster duplicate handler shut down.")

    def shut_down(self):
        """ Asynchronously initiate cluster duplicate handler shutdown. """
        self.shutdown_requested.set()


class Worker(threading.Thread):
    """ A Worker thread to process a sample. """
    def __init__(self, wid, job_queue, ruleset_engine, db_con):
        # whether we should run
        self.shutdown_requested = threading.Event()
        self.shutdown_requested.clear()
        self.worker_id = wid
        self.job_queue = job_queue
        self.ruleset_engine = ruleset_engine
        self.db_con = db_con
        super().__init__(name="Worker-%d" % wid)

    def run(self):
        while not self.shutdown_requested.is_set():
            logger.debug('Worker %d: Ready', self.worker_id)

            try:
                # wait blocking for next job (thread safe) with timeout
                sample = self.job_queue.dequeue()
            except queue.Empty:
                continue

            if sample is None:
                # we just got pinged
                continue

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
                self.ruleset_engine.run(sample)
            except PeekabooAnalysisDeferred:
                logger.debug('%d: Report still pending', sample.id)
                continue

            if sample.result >= Result.failed:
                sample.dump_processing_info()

            sample.mark_done()

            logger.debug('%d: Saving results to database', sample.id)
            try:
                self.db_con.analysis_update(sample)
            except PeekabooDatabaseError as dberr:
                logger.error('%d: Failed to save analysis result to '
                             'database: %s', sample.id, dberr)
                # no showstopper, we can limp on without caching in DB

            self.job_queue.done(sample)

        logger.info('Worker %d: Stopped', self.worker_id)

    def shut_down(self):
        """ Asynchronously initiate worker shutdown. """
        self.shutdown_requested.set()
