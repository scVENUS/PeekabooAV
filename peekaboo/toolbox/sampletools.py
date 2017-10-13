###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         sampletools.py                                                      #
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


import logging
import string
import subprocess
import mimetypes
import magic
from random import choice
from datetime import datetime
from ConfigParser import SafeConfigParser
from peekaboo.config import get_config


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
        return self.meta_info

    def get_mime_type(self):
        return self.meta_info.get('attachment', 'type_declared')

    def __str__(self):
        return '<SampleMetaInfo(%s)>' % str(self.meta_info)


def next_job_hash(size=8):
    """
    Generates a job hash (default: 8 characters).

    :param size The amount of random characters to use for a job hash.
                Defaults to 8.
    :return Returns a job hash consisting of a static prefix, a timestamp
            representing the time when the method was invoked, and random characters.
    """
    job_hash = 'peekaboo-analyses-'
    job_hash += '%s-' % datetime.now().strftime('%Y%m%dT%H%M%S')
    job_hash += ''.join(
        choice(string.digits + string.ascii_lowercase + string.ascii_uppercase)
        for _ in range(size)
    )
    return job_hash


def chown2me():
    """ Acquire ownership of all directories under /tmp with the prefix "amavis-". """
    # TODO: Find a better solution to acquire ownership and only for the directory currently in usse.
    logger.debug('Invoking chown2me...')
    config = get_config()
    proc = subprocess.Popen(config.chown2me_exec,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.wait()
    if proc.returncode != 0:
        logger.error('chown2me exited with code %d' % proc.returncode)


def guess_mime_type_from_filename(file_path):
    """ Guess the type of a file based on its filename or URL. """
    if not mimetypes.inited:
        mimetypes.init()
        mimetypes.add_type('application/javascript', '.jse')

    mt = mimetypes.guess_type(file_path)[0]
    if mt:
        return mt


def guess_mime_type_from_file_contents(file_path):
    """  Get type from file magic bytes. """
    mt = magic.from_file(file_path, mime=True)
    if mt:
        return mt
