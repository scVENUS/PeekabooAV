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
    def __init__(self, ruleset_config, worker_count = 4, queue_timeout = 300,
            dequeue_timeout = 5, shutdown_timeout = 600):
        """ Initialise job queue by creating n Peekaboo worker threads to
        process samples.

        :param worker_count: The amount of worker threads to create. Defaults to 4.
        """
        self.jobs = Queue()
        self.workers = []
        self.worker_count = worker_count
        self.queue_timeout = queue_timeout
        self.dequeue_timeout = dequeue_timeout
        self.shutdown_timeout = shutdown_timeout

        # keep a backlog of samples with hashes identical to samples currently
        # in analysis to avoid analysis multiple identical samples
        # simultaneously. Once one analysis has finished, we can submit the
        # others and the ruleset will notice that we already know the result.
        self.duplicates = {}
        self.duplock = Lock()

        for i in range(0, self.worker_count):
            logger.debug("Create Worker %d" % i)
            w = Worker(i, self, ruleset_config)
            self.workers.append(w)
            w.start()

        logger.info('Created %d Workers.' % self.worker_count)

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
                # initialise a per-duplicate backlog for this sample which also
                # serves as in-flight marker and submit to queue
                self.duplicates[sample_hash] = { 'master': sample, 'duplicates': [] }
                self.jobs.put(sample, True, self.queue_timeout)

        if duplicate:
            logger.debug("Sample from %s is duplicate and waiting for "
                    "running analysis to finish: %s" % (submitter, duplicate))
        elif resubmit:
            logger.debug("Resubmitted sample to job queue for %s: %s" %
                    (submitter, resubmit))
        else:
            logger.debug("New sample submitted to job queue by %s. %s" %
                    (submitter, sample_str))

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

            sample_str = str(self.duplicates[sample_hash]['master'])
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


class Worker(Thread):
    """
    A Worker thread to process a sample.

    @author: Sebastian Deiss
    """
    def __init__(self, wid, job_queue, ruleset_config, dequeue_timeout = 5):
        # whether we should run
        self.shutdown_requested = Event()
        self.shutdown_requested.clear()
        # whether we are actually running
        self.running_flag = Event()
        self.running_flag.clear()
        self.worker_id = wid
        self.job_queue = job_queue
        self.ruleset_config = ruleset_config
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
