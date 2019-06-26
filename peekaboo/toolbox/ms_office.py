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
import re
from oletools.olevba import VBA_Parser


logger = logging.getLogger(__name__)

MS_OFFICE_EXTENSIONS = [
    "doc", "docm", "dotm", "docx",
    "ppt", "pptm", "pptx", "potm", "ppam", "ppsm",
    "xls", "xlsm", "xlsx",
]


def has_office_macros(office_file, file_extension):
    """
    Detects macros in Microsoft Office documents.

    @param office_file: The MS Office document to check for macros.
    @return: True if macros where found, otherwise False.
             If VBA_Parser crashes it returns False too.
    """
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


def has_office_macros_with_suspicious_keyword(office_file, file_extension, suspicious_keywords):
    """
    Detects macros with supplied suspicious keywords in Microsoft Office documents.

    @param office_file: The MS Office document to check for Auto_ macros.
    @param file_extension: The file extension of the original file.
    @param suspicious_keywords: List of suspicious keyword regexes.
    @return: True if macros with keywords where found, otherwise False.
             If VBA_Parser crashes it returns False too.
    """

    if file_extension not in MS_OFFICE_EXTENSIONS:
        return False
    try:
        # VBA_Parser reports macros for office documents
        vbaparser = VBA_Parser(office_file)

        suspicious = False
        vba = vbaparser.reveal()
        for w in suspicious_keywords:
            if re.match(w, vba):
                suspicious = True
                break

        vbaparser.close()
        return suspicious
    except IOError:
        raise
    except TypeError:
        # The given file is not an office document.
        return False
    except Exception as error:
        logger.exception(error)
        return False
