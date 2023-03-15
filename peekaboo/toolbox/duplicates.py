###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         duplicates.py                                                       #
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

""" A local and cluster duplicate handler. """

import asyncio
import logging

from peekaboo.exceptions import PeekabooDatabaseError


logger = logging.getLogger(__name__)


class DuplicateHandler:
    """ A class to handle duplicate local analyses by deferring them. """
    def __init__(self, job_queue):
        """ Initialize the object. """
        # keep a backlog of samples with identities identical to samples
        # currently in analysis to avoid analysing multiple identical samples
        # simultaneously. Once one analysis has finished, we can submit the
        # others and the ruleset will notice that we already know the result.
        self.duplicates = {}
        self.duplock = asyncio.Lock()

        self.job_queue = job_queue

    async def is_duplicate(self, sample):
        """ Check if another sample with the same identity is already being
        analysed locally. If so, signal that processing of this new sample
        should be deferred and remember it in a list of duplicates.

        @param sample: sample to check for duplicates
        @type sample: Sample
        """
        identity = await sample.identity
        duplicate = False
        resubmit = False

        # we have to lock this down because async routines called from here may
        # allow us to be called again concurrently from the event loop
        async with self.duplock:
            # check if a sample with same identity is currently in flight
            # locally
            duplicates = self.duplicates.get(identity)
            if duplicates is None:
                # initialise a per-duplicate backlog for this sample which
                # also serves as in-flight marker and submit to queue
                self.duplicates[identity] = []
            else:
                # record the to-be-submitted sample as duplicate
                duplicate = True
                duplicates.append(sample)

        if duplicate:
            logger.debug(
                "%d: Sample is local duplicate and should wait for running "
                "analysis to finish", sample.id)
            return True

        if resubmit:
            logger.debug(
                "%d: Sample has been resubmitted to job queue", sample.id)
            return False

        logger.debug("%d: Sample is not a local duplicate", sample.id)
        return False

    async def submit_duplicates(self, sample):
        """ Check if any samples have been held from processing as duplicates
        and submit them now. Clear the original sample whose duplicates have
        been submitted from the in-flight list.

        @param sample: sample to check for duplicates
        @type sample: Sample
        """
        if not self.duplicates.keys():
            return

        identity = await sample.identity
        submitted_duplicates = []

        async with self.duplock:
            # this sample simply might not have had any duplicates
            if identity not in self.duplicates:
                return

            # submit all samples which have accumulated in the backlog. The
            # idea here it that they'll not reach any rule again which uses the
            # duplicate handler because some kind of cached result is now
            # available. If that's not the case then they'll be put in the
            # backlog again and a single one will be allowed to go on,
            # essentially serialising their processing in hopes that a final
            # verdict will be reached and cached eventually.
            for duplicate in self.duplicates[identity]:
                submitted_duplicates.append(duplicate.id)
                await self.job_queue.submit(duplicate)

            del self.duplicates[identity]

        logger.debug("%d: Cleared sample from local in-flight list", sample.id)
        if len(submitted_duplicates) > 0:
            logger.debug(
                "Submitted duplicates from local backlog: %s",
                submitted_duplicates)


class ClusterDuplicateHandler:
    """ A housekeeper handling submission and cleanup of cluster duplicates.
    """
    def __init__(self, job_queue, db_con, interval=5):
        self.job_queue = job_queue
        self.db_con = db_con
        self.interval = interval
        self.task = None
        self.task_name = "ClusterDuplicateHandler"

        # keep a log of samples we've locked for processing ourselves
        self.in_flight_locks = {}

        # keep a backlog of samples currently being processed by other
        # instances so we can regularly try to resubmit them and re-use the
        # other instances' cached results from the database
        self.cluster_duplicates = {}
        self.cluster_duplock = asyncio.Lock()

    async def is_cluster_duplicate(self, sample):
        """ Check if a given sample is already being processed by another
        instance in a cluster.

        @param sample: the sample to check for concurrent processing
        @type sample: Sample
        @returns: Return True if being processed concurrently, False otherwise.
        """
        identity = await sample.identity

        # if we already hold a lock on this identity, whether it's this exact
        # same sample or another, this is not a cluster duplicate. This ensures
        # parallel processing of identical samples which have been held as
        # cluster duplicates and have now been resubmitted in batch. The local
        # duplicate handler might still serialise them though.
        if self.in_flight_locks.get(identity) is not None:
            return False

        cluster_duplicate = False
        submitted_cluster_duplicates = []

        # we have to lock this down because async routines called from here may
        # allow us to be called again concurrently from the event loop
        async with self.cluster_duplock:
            # are we the first of potentially multiple instances working on
            # this sample?
            try:
                locked = await self.db_con.mark_sample_in_flight(sample)
            except PeekabooDatabaseError as dberr:
                # on database error we weren't able to confirm it's a
                # duplicate. So we potentially limp on with reduced throughput
                # and duplicate analysis but we give it our best shot.
                logger.error(dberr)
                return False

            cluster_duplicates = self.cluster_duplicates.get(identity)
            if locked:
                self.in_flight_locks[identity] = True

                if cluster_duplicates:
                    # apparently we've delayed some samples before because they
                    # were in processing on another instance. Now we've
                    # received the same sample again and successfully locked
                    # it. So we can bounce these back to the queue where they
                    # will be held as local duplicates.
                    for duplicate in cluster_duplicates:
                        submitted_cluster_duplicates.append(duplicate.id)
                        await self.job_queue.submit(duplicate)

                    del self.cluster_duplicates[identity]
            else:
                if cluster_duplicates is None:
                    self.cluster_duplicates[identity] = []

                # another instance is working on this
                cluster_duplicate = True
                self.cluster_duplicates[identity].append(sample)

        if cluster_duplicate:
            logger.debug(
                "%d: Sample is concurrently processed by another instance "
                "and held", sample.id)
            return True

        if len(submitted_cluster_duplicates) > 0:
            logger.debug(
                "Submitted old cluster duplicates from backlog: %s",
                submitted_cluster_duplicates)

        logger.debug("%d: Sample is not a cluster duplicate", sample.id)
        return False

    async def clear_sample_in_flight(self, sample):
        """ Clear in-flight lock on a sample.

        @param sample: the sample to check for finished processing
        @type sample: Sample """
        identity = await sample.identity

        # nothing to do if we do not hold an in-flight lock on this sample
        locked = self.in_flight_locks.get(identity)
        if not locked:
            return

        del self.in_flight_locks[identity]

        try:
            await self.db_con.clear_sample_in_flight(sample)
        except PeekabooDatabaseError as dberr:
            logger.error(dberr)

        logger.debug(
            "%d: Cleared sample from cluster in-flight list", sample.id)

    async def submit_cluster_duplicates(self):
        """ Submit samples held while being processed by another cluster
        instance back into the job queue if they have finished processing. """
        if not self.cluster_duplicates.keys():
            return

        submitted_cluster_duplicates = []

        async with self.cluster_duplock:
            # try to submit *all* samples which have been marked as being
            # processed by another instance concurrently
            # get the items view on a copy of the cluster duplicate backlog
            # because we will change it by removing entries which would raise a
            # RuntimeException
            cluster_duplicates = self.cluster_duplicates.copy().items()
            for identity, sample_duplicates in cluster_duplicates:
                # try to mark as in-flight
                try:
                    locked = await self.db_con.mark_sample_in_flight(
                        sample_duplicates[0])
                except PeekabooDatabaseError as dberr:
                    logger.error(dberr)
                    return False

                if locked:
                    self.in_flight_locks[identity] = True

                    # submit all of the held-back samples at once. The local
                    # duplicate handler should kick in when processing it and
                    # delay all but one as local duplicates. This is sensible
                    # in case the analysis on the other instance failed and we
                    # have no result in the database yet. If all is well, this
                    # local canary analysis should finish analysis very quickly
                    # using the stored result, causing all the duplicates to be
                    # submitted and finish quickly as well.
                    for sample in sample_duplicates:
                        submitted_cluster_duplicates.append(sample.id)
                        await self.job_queue.submit(sample)

                    del self.cluster_duplicates[identity]

        if len(submitted_cluster_duplicates) > 0:
            logger.debug(
                "Submitted cluster duplicates from backlog: %s",
                submitted_cluster_duplicates)

    async def clear_stale_in_flight_samples(self):
        """ Clear any stale in-flight sample logs from the database. """
        try:
            cleared = await self.db_con.clear_stale_in_flight_samples()
        except PeekabooDatabaseError as dberr:
            logger.error(dberr)
            cleared = False

        return cleared

    async def start(self):
        """ Start the cluster duplicare handler. """
        self.task = asyncio.ensure_future(self.run())
        if hasattr(self.task, "set_name"):
            self.task.set_name(self.task_name)
        return self.task

    async def run(self):
        """ Regularly check for withheld cluster duplicates, potentially
        resubmit them to the queue and clean up stale lock entries. """
        logger.debug("Cluster duplicate handler started.")

        while True:
            await asyncio.sleep(self.interval)

            logger.debug("Checking for samples in processing by other "
                         "instances to submit")

            await self.clear_stale_in_flight_samples()
            await self.submit_cluster_duplicates()

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
            except Exception:
                logger.exception(
                    "Unexpected exception in cluster duplicate handler")

        logger.debug("Cluster duplicate handler shut down.")
