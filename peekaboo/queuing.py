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
from threading import Thread
from Queue import Queue
from peekaboo import Singleton
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.exceptions import CuckooReportPendingException


logger = logging.getLogger(__name__)


def create_workers(worker_count=4):
    """
    Create n Peekaboo worker threads to process samples.

    :param worker_count: The amount of worker threads to create. Defaults to 4.
    """
    for i in range(0, worker_count):
        logger.debug("Create Worker %d" % i)
        w = Worker(i)
        JobQueue.workers.append(w)
        w.start()
    logger.info('Created %d Workers.' % worker_count)


class JobQueue(Singleton):
    """
    Peekaboo's queuing system.

    @author: Sebastian Deiss
    """
    workers = []
    jobs = Queue()

    @staticmethod
    def submit(sample, submitter, timeout=300):
        """
        Adds a Sample object to the job queue.
        If the queue is full, we block for 300 seconds and then throw an exception.

        :param sample: The Sample object to add to the queue.
        :param submitter: The name of the class / module that wants to submit the sample.
        :param timeout: Block until timeout is reached and then trow an exception
                        if the job has not been submitted.
        :raises Full: if the queue is full.
        """
        logger.debug("New sample submitted to job queue by %s. %s" % (submitter, sample))
        # thread safe most likely no race condition possible
        JobQueue.jobs.put(sample, True, timeout)


class Worker(Thread):
    """
    A Worker thread to process a sample.

    @author: Sebastian Deiss
    """
    def __init__(self, wid):
        self.active = True
        self.worker_id = wid
        Thread.__init__(self)

    def run(self):
        while self.active:
            logger.debug('Worker is ready')
            sample = JobQueue.jobs.get(True)  # wait blocking for next job (thread safe)
            logger.info('Worker %d: Processing sample %s' % (self.worker_id, sample))

            sample.init()

            try:
                engine = RulesetEngine(sample)
                engine.run()
                engine.report()
            except CuckooReportPendingException:
                pass
            except Exception as e:
                logger.exception(e)

    def __exit__(self, exc_type, exc_value, traceback):
        self.active = False
