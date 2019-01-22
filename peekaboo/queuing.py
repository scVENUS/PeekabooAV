###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# queuing.py                                                                  #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2018  science + computing ag                             #
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


import logging
from threading import Thread, Event, Lock
from Queue import Queue, Empty
from time import sleep
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.exceptions import CuckooReportPendingException


logger = logging.getLogger(__name__)


class JobQueue:
    """
    Peekaboo's queuing system.

    @author: Sebastian Deiss
    """
    def __init__(self, ruleset_config, db_con, worker_count = 4,
            queue_timeout = 300, dequeue_timeout = 5, shutdown_timeout = 600,
            cluster_duplicate_interval = 5):
        """ Initialise job queue by creating n Peekaboo worker threads to
        process samples.

        :param db_con: Database connection object for cluster instance
                       coordination, i.e. saving sample info.
        :param worker_count: The amount of worker threads to create. Defaults to 4.
        """
        self.db_con = db_con
        self.jobs = Queue()
        self.workers = []
        self.worker_count = worker_count
        self.queue_timeout = queue_timeout
        self.dequeue_timeout = dequeue_timeout
        self.shutdown_timeout = shutdown_timeout

        # keep a backlog of samples with hashes identical to samples currently
        # in analysis to avoid analysing multiple identical samples
        # simultaneously. Once one analysis has finished, we can submit the
        # others and the ruleset will notice that we already know the result.
        self.duplicates = {}
        self.duplock = Lock()

        # keep a similar backlog of samples currently being processed by
        # other instances so we can regularly try to resubmit them and re-use
        # the other instances' cached results from the database
        self.cluster_duplicates = {}

        for i in range(0, self.worker_count):
            logger.debug("Create Worker %d" % i)
            w = Worker(i, self, ruleset_config, db_con)
            self.workers.append(w)
            w.start()

        logger.info('Created %d Workers.' % self.worker_count)

        self.cluster_duplicate_handler = ClusterDuplicateHandler(
                self, cluster_duplicate_interval)
        self.cluster_duplicate_handler.start();

    def submit(self, sample, submitter):
        """
        Adds a Sample object to the job queue.
        If the queue is full, we block for 300 seconds and then throw an exception.

        :param sample: The Sample object to add to the queue.
        :param submitter: The name of the class / module that wants to submit the sample.
        :param timeout: Block until timeout is reached and then trow an exception
                        if the job has not been submitted.
        :raises Full: if the queue is full.
        """
        sample_hash = sample.sha256sum
        sample_str = str(sample)
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
                    resubmit = sample_str
                    self.jobs.put(sample, True, self.queue_timeout)
                else:
                    # record the to-be-submitted sample as duplicate and do nothing
                    duplicate = sample_str
                    duplicates['duplicates'].append(sample)
            else:
                # are we the first of potentially multiple instances working on
                # this sample?
                if self.db_con.mark_sample_in_flight(sample):
                    # initialise a per-duplicate backlog for this sample which
                    # also serves as in-flight marker and submit to queue
                    self.duplicates[sample_hash] = {
                            'master': sample,
                            'duplicates': [] }
                    self.jobs.put(sample, True, self.queue_timeout)
                else:
                    # another instance is working on this
                    if self.cluster_duplicates.get(sample_hash) is None:
                        self.cluster_duplicates[sample_hash] = []

                    cluster_duplicate = sample_str
                    self.cluster_duplicates[sample_hash].append(sample)

        if duplicate:
            logger.debug("Sample from %s is duplicate and waiting for "
                    "running analysis to finish: %s" % (submitter, duplicate))
        elif cluster_duplicate:
            logger.debug("Sample from %s is concurrently processed by "
                    "another instance and held: %s" % (submitter,
                        cluster_duplicate))
        elif resubmit:
            logger.debug("Resubmitted sample to job queue for %s: %s" %
                    (submitter, resubmit))
        else:
            logger.debug("New sample submitted to job queue by %s. %s" %
                    (submitter, sample_str))

    def submit_cluster_duplicates(self):
        if not self.cluster_duplicates.keys():
            return

        submitted_cluster_duplicates = []

        with self.duplock:
            # try to submit *all* samples which have been marked as being
            # processed by another instance concurrently
            for sample_hash, sample_duplicates in self.cluster_duplicates.items():
                # try to mark as in-flight
                if self.db_con.mark_sample_in_flight(sample_duplicates[0]):
                    sample_str = str(sample_duplicates[0])
                    if self.duplicates.get(sample_hash) is not None:
                        logger.error("Possible backlog corruption for sample "
                                "%s! Please file a bug report. Trying to "
                                "continue..." % sample_str)
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
                            'duplicates': sample_duplicates }
                    submitted_cluster_duplicates.append(sample_str)
                    self.jobs.put(sample, True, self.queue_timeout)
                    del self.cluster_duplicates[sample_hash]

        if len(submitted_cluster_duplicates) > 0:
            logger.debug("Submitted cluster duplicates (and potentially "
                    "their duplicates) from backlog: %s" %
                    submitted_cluster_duplicates)

    def clear_stale_in_flight_samples(self):
        return self.db_con.clear_stale_in_flight_samples()

    def done(self, sample_hash):
        submitted_duplicates = []
        with self.duplock:
            # duplicates which have been submitted from the backlog still
            # report done but do not get registered as potentially having
            # duplicates because we expect the ruleset to identify them as
            # already known and process them quickly now that the first
            # instance has gone through full analysis
            if not self.duplicates.has_key(sample_hash):
                return

            # submit all samples which have accumulated in the backlog
            for s in self.duplicates[sample_hash]['duplicates']:
                submitted_duplicates.append(str(s))
                self.jobs.put(s, True, self.queue_timeout)

            sample = self.duplicates[sample_hash]['master']
            self.db_con.clear_sample_in_flight(sample)
            sample_str = str(sample)
            del self.duplicates[sample_hash]

        logger.debug("Cleared sample %s from in-flight list" % sample_str)
        if len(submitted_duplicates) > 0:
            logger.debug("Submitted duplicates from backlog: %s" % submitted_duplicates)

    def dequeue(self, timeout):
        return self.jobs.get(True, timeout)

    def shut_down(self, timeout = None):
        if not timeout:
            timeout = self.shutdown_timeout

        logger.info("Shutting down. Giving workers %d seconds to stop" % timeout)

        self.cluster_duplicate_handler.shut_down()
        for w in self.workers:
            w.shut_down()

        # wait for workers to end
        for t in range(0, timeout):
            still_running = []
            for w in self.workers:
                if w.running:
                    still_running.append(w)

            self.workers = still_running
            if len(self.workers) == 0:
                break

            sleep(1)

        if len(self.workers) > 0:
            logger.error("Some workers refused to stop.")

class ClusterDuplicateHandler(Thread):
    def __init__(self, job_queue, interval=5):
        self.shutdown_requested = Event()
        self.shutdown_requested.clear()
        self.job_queue = job_queue
        self.interval = interval
        Thread.__init__(self)

    def run(self):
        logger.debug("Cluster duplicate handler started.")

        while not self.shutdown_requested.wait(self.interval):
            logger.debug("Checking for samples in processing by other "
                         "instances to submit")
            self.job_queue.clear_stale_in_flight_samples()
            self.job_queue.submit_cluster_duplicates()

        logger.debug("Cluster duplicate handler shut down.")

    def shut_down(self):
        self.shutdown_requested.set()


class Worker(Thread):
    """
    A Worker thread to process a sample.

    @author: Sebastian Deiss
    """
    def __init__(self, wid, job_queue, ruleset_config, db_con, dequeue_timeout = 5):
        # whether we should run
        self.shutdown_requested = Event()
        self.shutdown_requested.clear()
        # whether we are actually running
        self.running_flag = Event()
        self.running_flag.clear()
        self.worker_id = wid
        self.job_queue = job_queue
        self.ruleset_config = ruleset_config
        self.db_con = db_con
        self.dequeue_timeout = dequeue_timeout
        Thread.__init__(self)

    def run(self):
        self.running_flag.set()
        while not self.shutdown_requested.is_set():
            try:
                # wait blocking for next job (thread safe) with timeout
                sample = self.job_queue.dequeue(self.dequeue_timeout)
            except Empty:
                continue
            logger.info('Worker %d: Processing sample %s' % (self.worker_id, sample))

            sample.init()

            try:
                engine = RulesetEngine(sample, self.ruleset_config)
                engine.run()
                engine.report()

                logger.debug('Saving results to database')
                self.db_con.analysis_save(sample)
                sample.remove_from_connection_map()

                self.job_queue.done(sample.sha256sum)
            except CuckooReportPendingException:
                logger.debug("Report for sample %s still pending" % sample)
                pass
            except Exception as e:
                logger.exception(e)
                # it's no longer in-flight even though processing seems to have
                # failed
                self.job_queue.done(sample.sha256sum)

            logger.debug('Worker is ready')

        logger.info('Worker %d: Stopped' % self.worker_id)
        self.running_flag.clear()

    def shut_down(self):
        self.shutdown_requested.set()

    @property
    def running(self):
        return self.running_flag.is_set()
