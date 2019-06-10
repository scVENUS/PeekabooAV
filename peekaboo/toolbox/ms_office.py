###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         ms_office.py                                                        #
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

""" Tool functions for handling office macros. """

import logging
from oletools.olevba import VBA_Parser


logger = logging.getLogger(__name__)

MS_OFFICE_EXTENSIONS = [
    "doc", "docm", "dotm", "docx",
    "ppt", "pptm", "pptx", "potm", "ppam", "ppsm",
    "xls", "xlsm", "xlsx",
]


def has_office_macros(office_file):
    """
    Detects macros in Microsoft Office documents.

    @param office_file: The MS Office document to check for macros.
    @return: True if macros where found, otherwise False.
             If VBA_Parser crashes it returns False too.
    """
    file_extension = office_file.split('.')[-1]
    if file_extension not in MS_OFFICE_EXTENSIONS:
        return False
    try:
        # VBA_Parser reports macros for office documents
        vbaparser = VBA_Parser(office_file)
        return vbaparser.detect_vba_macros()
    except TypeError:
        # The given file is not an office document.
        return False
    except Exception as error:
        logger.exception(error)
        return False

def has_office_macros_with_auto_action(office_file):
    """
    Detects macros for Auto_ actions in Microsoft Office documents.

    @param office_file: The MS Office document to check for Auto_ macros.
    @return: True if Auto_ macros where found, otherwise False.
             If VBA_Parser crashes it returns False too.
    """

    SUSPICIOUS_KEYWORDS = ["AutoOpen", "AutoClose"]

    file_extension = office_file.split('.')[-1]
    if file_extension not in MS_OFFICE_EXTENSIONS:
        print("/%s/" % file_extension)
        return False
    try:
        # VBA_Parser reports macros for office documents
        vbaparser = VBA_Parser(office_file)
        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
            for w in  SUSPICIOUS_KEYWORDS:
                if w in vba_code:
                    return True

        return vbaparser.detect_vba_macros()
    except TypeError:
        # The given file is not an office document.
        return False
    except Exception as error:
        logger.exception(error)
        return False