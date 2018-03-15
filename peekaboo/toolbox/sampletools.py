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
from ConfigParser import SafeConfigParser
from peekaboo import Singleton
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


class SampleMetaInfo(object):
    """
    Additional meta information about a Sample.

    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    def __init__(self, meta_info_file):
        self.__meta_info_file = meta_info_file
        self.meta_info = None
        self._parse()

    def _parse(self):
        """
        Parse a meta information file.

        @see: SafeConfigParser
        """
        logger.debug('Parsing sample metadata from %s' % self.__meta_info_file)
        self.meta_info = SafeConfigParser()
        self.meta_info.read(self.__meta_info_file)

    def get_all(self):
        """
        Gets the parsed meta info file.

        :return: A ConfigParser instance for the parsed meta info file.
        """
        return self.meta_info

    def get_mime_type(self):
        """
        Gets the MIME type parsed from the meta info file field 'type_declared'.

        :return: The MIME type from the meta info file field 'type_declared'.
        """
        return self.meta_info.get('attachment', 'type_declared')

    def __str__(self):
        return '<SampleMetaInfo(%s)>' % str(self.meta_info)


class ConnectionMap(Singleton):
    """
    Maps socket objects with one or more samples.
    This is required for the reporting, so we know which
    Sample objects belong to which socket connection.

    @author: Sebastian Deiss
    """
    __lock = threading.RLock()
    __map = {}

    @staticmethod
    def add(socket, sample):
        """
        Add an entry to the connection map. An entry consists of a
        socket object and a list of Sample objects.

        :param socket: The socket object to add.
        :param sample: The corresponding Samples objects for the socket.
        :return:The length of the connection map.
        """
        with ConnectionMap.__lock:
            logger.debug('Registered sample for connection %s' % socket)
            if ConnectionMap.has_connection(socket):
                ConnectionMap.__map[socket].append(sample)
            else:
                ConnectionMap.__map[socket] = [sample]
            return ConnectionMap.size()

    @staticmethod
    def remove(socket, sample):
        """
        Remove a Sample or an entry from the connection map. First, we
        remove the given Sample object from the list of Sample objects of
        the given socket. If the sample list is empty, we remove the
        entire entry from the map.

        :param socket: A socket object, which is related to the sample.
        :param sample: The sample to remove.
        :return: The length of the connection map.
        """
        with ConnectionMap.__lock:
            if ConnectionMap.has_connection(socket):
                logger.debug(
                    'Removing sample for connection %s, Sample: %s' % (socket, sample)
                )
                ConnectionMap.__map[socket].remove(sample)
                if len(ConnectionMap.__map[socket]) == 0:
                    ConnectionMap.__map.pop(socket)
                    logger.debug('Removing connection: %s' % socket)
            else:
                logger.debug(
                    'Connection does not exist.'
                    'Connection: %s, Sample: %s, Map: %s'
                    % (socket, sample, ConnectionMap.__map)
                )
            return ConnectionMap.size()

    @staticmethod
    def size():
        """ Gets the length of the connection map. """
        return len(ConnectionMap.__map)

    @staticmethod
    def _dump():
        """ Get the connection map. This method might be useful for debugging. """
        return ConnectionMap.__map

    @staticmethod
    def has_connection(socket):
        """
        Check if the given socket object exists in the map.

        :param socket: A socket object to search for in the map.
        :return: True if the map contains the given socket object, otherwise False.
        """
        if socket in ConnectionMap.__map.keys():
            return True
        return False

    @staticmethod
    def get_sample_by_job_id(job_id):
        """
        Get a Sample object from the map by its job ID.

        :param job_id: The job ID of the Sample object to fetch.
        :return:The Sample object with the given job ID or None.
        """
        with ConnectionMap.__lock:
            logger.debug("Searching for a sample with job ID %d" % job_id)
            for __, samples in ConnectionMap.__map.iteritems():
                logger.debug('Samples for this connection: %s' % samples)
                for sample in samples:
                    if job_id == sample.job_id:
                        logger.debug('Found %s for job ID %d' % (sample, job_id))
                        return sample

    @staticmethod
    def get_sample_by_sha256(sha256sum):
        """
        Get a Sample object from the map by its SHA-256 checksum.

        :param sha256sum: The SHA-256 checksum of the file represented by a Sample object.
        :return: The Sample object with the given SHA-256 checksum or None.
        """
        with ConnectionMap.__lock:
            logger.debug(
                'Searching for a sample with SHA-256 checksum %s' % sha256sum
            )
            for __, samples in ConnectionMap.__map.iteritems():
                logger.debug('Samples for this connection: %s' % samples)
                for sample in samples:
                    if sha256sum == sample.sha256sum:
                        logger.debug(
                            'Found %s for SHA-256 hash %s' % (sample, sha256sum)
                        )
                        return sample

    @staticmethod
    def get_samples_by_sha256(sha256sum):
        """
        Get all Sample objects from the map with the same SHA-256 checksum.

        :param sha256sum: A SHA-256 checksum to search for.
        :return: The Sample objects with the given SHA-256 checksum or None.
        """
        with ConnectionMap.__lock:
            logger.debug('Searching for all samples with SHA-256 checksum %s' % sha256sum)
            matching_samples = []
            for __, samples in ConnectionMap.__map.iteritems():
                logger.debug('Samples for this connection: %s' % samples)
                for sample in samples:
                    if sha256sum == sample.sha256sum:
                        logger.debug('Found %s for SHA-256 hash %s' % (sample, sha256sum))
                        matching_samples.append(sample)
            return matching_samples

    @staticmethod
    def get_samples_by_connection(socket):
        """
        Get all Sample objects for a specific socket connection.

        :param socket: The socket object to get all Samples objects for.
        :return: A list of all Sample objects for the given socket.
        """
        with ConnectionMap.__lock:
            matching_samples = []
            for sock in ConnectionMap.__map.iteritems():
                if sock == socket:
                    matching_samples = ConnectionMap.__map[sock]
            return matching_samples

    @staticmethod
    def in_progress(sha256sum):
        """
        Check if a Sample object in the map has the state 'inProgress'.

        :param sha256sum: The SHA-256 checksum of the file represented by a Sample object.
        :return: True if the Sample object with the given SHA-256 checksum is
                 'inProgress' otherwise False.
        """
        sample = ConnectionMap.get_sample_by_sha256(sha256sum)
        if sample is not None and sample.get_result() == Result.inProgress:
            return True
        return False


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
