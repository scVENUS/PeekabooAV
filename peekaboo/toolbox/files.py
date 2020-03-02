###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         files.py                                                            #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2019  science + computing ag                             #
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
import mimetypes

import magic


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


class Filetools(object):
    """ Parent class, defines interface to various file tools. """
    def get_report(self, sample):
        """ Return filetools report or create if not already cached. """
        report = {
            "type_by_content":
                guess_mime_type_from_file_contents(sample.file_path),
            "type_by_name":
                guess_mime_type_from_filename(sample.filename),
        }

        sample.register_filetools_report(FiletoolsReport(report))
        return FiletoolsReport(report)


class FiletoolsReport(object):
    """ Represents a custom Filetools report. """
    def __init__(self, report):
        self.report = report

    def __str__(self):
        return "<FiletoolsReport('%s'>" % self.report

    @property
    def type_by_content(self):
        """ Returns the type of a file guessed based on its contents. """
        return self.report.get('type_by_content', None)

    @property
    def type_by_name(self):
        """ Returns the type of a file guessed based on its filename. """
        return self.report.get('type_by_name', None)
