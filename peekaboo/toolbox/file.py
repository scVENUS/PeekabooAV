###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         files.py                                                            #
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


import logging
import mimetypes

import magic


logger = logging.getLogger(__name__)


class Filetools:
    """ Parent class, defines interface to various file tools. """
    def __init__(self, sample):
        self.sample = sample

        if not mimetypes.inited:
            mimetypes.init()
            mimetypes.add_type('application/javascript', '.jse')

    def guess_mime_type_from_contents(self):
        """  Get type from file magic bytes. """
        mime_type = magic.from_buffer(self.sample.content, mime=True)
        if not mime_type:
            return None

        return mime_type

    def guess_mime_type_from_name(self):
        """ Guess the type of a file based on its filename or URL. """
        filename = self.sample.filename
        if not filename:
            return None
        mime_type = mimetypes.guess_type(filename)[0]
        if not mime_type:
            return None

        return mime_type

    def guess_mime_type_text_representation(self):
        """ Guess the type by content and hand back text representation rather
        than mime type. """
        type_as_text = magic.from_buffer(self.sample.content)
        if not type_as_text:
            return None

        return type_as_text

    def get_report(self):
        """ Return filetools report or create if not already cached. """
        if self.sample.filetools_report is not None:
            return self.sample.filetools_report

        ftreport = FiletoolsReport({
            "type_by_content": self.guess_mime_type_from_contents(),
            "type_by_name": self.guess_mime_type_from_name(),
            "type_as_text": self.guess_mime_type_text_representation(),
        })

        self.sample.register_filetools_report(ftreport)
        return ftreport


class FiletoolsReport:
    """ Represents a custom Filetools report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
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

    @property
    def type_as_text(self):
        """ Returns the guessed type of a file in text representation rather
        than mime type. Equal to using the `file` command. """
        return self.report.get('type_as_text', None)

    @property
    def mime_types(self):
        """ Return set of determined mime types. """
        mime_types = {self.type_by_name, self.type_by_content}
        mime_types.discard(None)

        return mime_types
