###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# pjobs.py                                                                   #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2017  science + computing ag                             #
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


import threading
import logging
from Queue import Queue
from peekaboo.ruleset import Result
from peekaboo.ruleset.processor import evaluate
from peekaboo.exceptions import CuckooReportPendingException


logger = logging.getLogger(__name__)


class Jobs(object):
    """
    Data structure to share connection->queue information between threads
    (peekaboo.py and cuckooWrapper.py)associates socket connection with jobIDs.

    Jobs.queue looks similar to
    {<socket._socketobject at 0x7fa68f447360>: [280],
    <socket._socketobject at 0x7fa68f447440>: [281, 282, 283]}

    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    __in_use = threading.Lock()
    __queue = {}

    @staticmethod
    def add_job(socket_con, sample):
        Jobs.__in_use.acquire()
        logger.debug('Added job to queue for connection %s'
                     % str(socket_con))
        if socket_con in Jobs.__queue.keys():
            Jobs.__queue[socket_con].append(sample)
        else:
            Jobs.__queue[socket_con] = [sample]
        Jobs.__in_use.release()
        return len(Jobs.__queue)

    @staticmethod
    def remove_job(socket_con, sample):
        Jobs.__in_use.acquire()
        q_length = 0
        logger.debug('Removing job for connection %s' % str(socket_con))
        if socket_con in Jobs.__queue:
            Jobs.__queue[socket_con].remove(sample)

            if len(Jobs.__queue[socket_con]) <= 0:
                Jobs.__queue.pop(socket_con)
                logger.debug("Job popped %s %s" % (str(sample),
                                                   str(Jobs.__queue)))
                Jobs.__in_use.release()
            else:
                logger.debug("Sample not in list %s %s %s"
                             % (str(socket_con), str(sample),
                                str(Jobs.__queue)))
                Jobs.__in_use.release()
                q_length = len(Jobs.__queue)
        else:
            logger.debug("socket_con doesn't exist %s %s %s"
                         % (str(socket_con), str(sample),
                            str(Jobs.__queue)))
            Jobs.__in_use.release()
        return q_length

    @staticmethod
    def length():
        return len(Jobs.__queue)

    @staticmethod
    def get_sample_by_job_id(job_id):
        Jobs.__in_use.acquire()
        logger.debug("Getting sample for job ID %d" % job_id)
        requested_sample = None

        for __, samples in Jobs.__queue.iteritems():
            if samples:
                logger.debug('Samples for this connection %s' % samples)
                for sample in samples:
                    if job_id == sample.job_id:
                        # make sample result read cuckoo report
                        logger.debug('Found %s for job ID %d' % (sample, job_id))
                        requested_sample = sample
        Jobs.__in_use.release()
        return requested_sample

    @staticmethod
    def get_sample_by_sha256(sha256sum):
        Jobs.__in_use.acquire()
        logger.debug('Getting sample with SHA-256 checksum %s' % sha256sum)
        requested_sample = None

        for __, samples in Jobs.__queue.iteritems():
            if samples:
                logger.debug('Samples for this connection %s' % samples)
                for sample in samples:
                    if sha256sum == sample.sha256sum:
                        logger.debug('Found %s for SHA-256 hash %s'
                                     % (sample, sha256sum))
                        requested_sample = sample
        Jobs.__in_use.release()
        return requested_sample

    @staticmethod
    def get_samples_by_sha256(sha256sum):
        Jobs.__in_use.acquire()
        matching_samples = []
        for __, samples in Jobs.__queue.iteritems():
            for sample in samples:
                if sha256sum == sample.sha256sum:
                    matching_samples.append(sample)
        Jobs.__in_use.release()
        return matching_samples

    @staticmethod
    def get_samples_for_conn(sock_con):
        Jobs.__in_use.acquire()
        matching_samples = []
        for con in Jobs.__queue.iteritems():
            if con == sock_con:
                matching_samples = Jobs.__queue[con]
        Jobs.__in_use.release()
        return matching_samples

    @staticmethod
    def in_progress(sha256sum):
        sample = Jobs.get_sample_by_sha256(sha256sum)
        if sample is not None and sample.get_result() == Result.inProgress:
            return True
        return False


class Workers(object):
    """
    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    count = None        # number of workers (set by constructor)
    run = True          # makes things end
    q = Queue()         # to queue Sample objects that need action
    w = []              # list of workers

    @staticmethod
    def __init__(count=4):
        """ Initialize a worker """
        Workers.count = count
        for i in range(0, count):
            logger.debug("Create Worker %d" % i)
            Workers.w.append(threading.Thread(target=Workers.threaded_loop))
            Workers.w[i].start()

    @staticmethod
    def submit_job(s, submitter):
        """
        Adds s to queue. If queue is full will block for 300s and
        throw exception.
        """
        logger.debug("New job submitted by %s to queue: %s" % (submitter, str(s)))
        # thread safe most likely no race condition possible
        Workers.q.put(s, True, 300)

    @staticmethod
    def __exit__(exc_type, exc_value, traceback):
        Workers.run = False

    @staticmethod
    def threaded_loop():
        """ infinite loop that waits for jobs. """
        while Workers.run:
            logger.debug('Worker is ready')

            s = Workers.q.get(True)  # wait blocking for next job (thread safe)
            logger.debug('Received sample %s' % str(s))

            s.init()

            try:
                evaluate(s)

                for s in Jobs.get_samples_by_sha256(s.sha256sum):
                    logger.debug('Processing queued sample %s' % s)
                    Workers.submit_job(s, Workers.__class__)
            except CuckooReportPendingException as e:
                pass
            except Exception as e:
                # catch 'cuckooReport not yet available. Sample submitted for
                # analysis' exception
                logger.exception(e)

            # TODO: do checks here
            #   e.g. - check if there is dead inProgress entries in DB
            #        - number of running workers
            #        - check for dead connections and cleanup queue
            #        - ...
