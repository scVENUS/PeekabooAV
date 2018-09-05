###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         sampletools.py                                                      #
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
import string
import threading
from random import choice
from datetime import datetime
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


class ConnectionMap:
    """
    Maps socket objects with one or more samples.
    This is required for the reporting, so we know which
    Sample objects belong to which socket connection.

    @author: Sebastian Deiss
    """
    def __init__(self):
        self.__lock = threading.RLock()
        self.__map = {}

    def add(self, socket, sample):
        """
        Add an entry to the connection map. An entry consists of a
        socket object and a list of Sample objects.

        :param socket: The socket object to add.
        :param sample: The corresponding Samples objects for the socket.
        :return:The length of the connection map.
        """
        with self.__lock:
            logger.debug('Registered sample for connection %s' % socket)
            if self.has_connection(socket):
                self.__map[socket].append(sample)
            else:
                self.__map[socket] = [sample]
            return self.size()

    def remove(self, socket, sample):
        """
        Remove a Sample or an entry from the connection map. First, we
        remove the given Sample object from the list of Sample objects of
        the given socket. If the sample list is empty, we remove the
        entire entry from the map.

        :param socket: A socket object, which is related to the sample.
        :param sample: The sample to remove.
        :return: The length of the connection map.
        """
        with self.__lock:
            if self.has_connection(socket):
                logger.debug(
                    'Removing sample for connection %s, Sample: %s' % (socket, sample)
                )
                self.__map[socket].remove(sample)
                if len(self.__map[socket]) == 0:
                    self.__map.pop(socket)
                    logger.debug('Removing connection: %s' % socket)
            else:
                logger.debug(
                    'Connection does not exist.'
                    'Connection: %s, Sample: %s, Map: %s'
                    % (socket, sample, self.__map)
                )
            return self.size()

    def size(self):
        """ Gets the length of the connection map. """
        return len(self.__map)

    def _dump(self):
        """ Get the connection map. This method might be useful for debugging. """
        return self.__map

    def has_connection(self, socket):
        """
        Check if the given socket object exists in the map.

        :param socket: A socket object to search for in the map.
        :return: True if the map contains the given socket object, otherwise False.
        """
        if socket in self.__map.keys():
            return True
        return False

    def get_sample_by_job_id(self, job_id):
        """
        Get a Sample object from the map by its job ID.

        :param job_id: The job ID of the Sample object to fetch.
        :return:The Sample object with the given job ID or None.
        """
        with self.__lock:
            logger.debug("Searching for a sample with job ID %d" % job_id)
            for __, samples in self.__map.iteritems():
                logger.debug('Samples for this connection: %s' % samples)
                for sample in samples:
                    if job_id == sample.job_id:
                        logger.debug('Found %s for job ID %d' % (sample, job_id))
                        return sample


def next_job_hash(size=8):
    """
    Generates a job hash (default: 8 characters).

    :param size The amount of random characters to use for a job hash.
                Defaults to 8.
    :return Returns a job hash consisting of a static prefix, a timestamp
            representing the time when the method was invoked, and random characters.
    """
    job_hash = 'peekaboo-run_analysis-'
    job_hash += '%s-' % datetime.now().strftime('%Y%m%dT%H%M%S')
    job_hash += ''.join(
        choice(string.digits + string.ascii_lowercase + string.ascii_uppercase)
        for _ in range(size)
    )
    return job_hash
