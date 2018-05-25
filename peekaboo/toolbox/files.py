###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         files.py                                                            #
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
import subprocess
import magic
from peekaboo.config import get_config


logger = logging.getLogger(__name__)


def chown2me():
    """ Acquire ownership of all directories under /tmp with the prefix "amavis-". """
    # TODO: Find a better solution to acquire ownership and only for the directory currently in use.
    logger.debug('Invoking chown2me...')
    config = get_config()
    proc = subprocess.Popen(config.chown2me_exec,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    proc.wait()
    if proc.returncode != 0:
        logger.error('chown2me exited with code %d' % proc.returncode)


def guess_mime_type_from_file_contents(file_path):
    """  Get type from file magic bytes. """
    mt = magic.from_file(file_path, mime=True)
    if mt:
        return mt
