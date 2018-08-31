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
import mimetypes


logger = logging.getLogger(__name__)


def guess_mime_type_from_file_contents(file_path):
    """  Get type from file magic bytes. """
    mt = magic.from_file(file_path, mime=True)
    if not mt:
        return None

    return mt


def guess_mime_type_from_filename(file_path):
    """ Guess the type of a file based on its filename or URL. """
    if not mimetypes.inited:
        mimetypes.init()
        mimetypes.add_type('application/javascript', '.jse')

    mt = mimetypes.guess_type(file_path)[0]
    if not mt:
        return None

    return mt
