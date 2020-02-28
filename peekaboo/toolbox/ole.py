###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         ole.py                                                           #
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
import re
from oletools.olevba import VBA_Parser, FileOpenError
from oletools.olevba import detect_autoexec, detect_suspicious

logger = logging.getLogger(__name__)


class Oletools(object):
    """ Parent class, defines interface to Oletools. """
    def get_report(self, sample):
        """ Return oletools report or create if not already cached. """
        report = {
            'autoexec': [],
            'suspicious' : [],
        }

        try:
            vbaparser = VBA_Parser(sample.file_path)

            # VBA_Parser reports macros for office documents
            report['has_macros'] = vbaparser.detect_vba_macros() or vbaparser.detect_xlm_macros()
            try:
                report['vba'] = vbaparser.reveal()
            except TypeError:
                # office document with no macros
                pass

            all_macros = vbaparser.extract_all_macros()
            if (report['has_macros'] and len(all_macros) == 1
                and type(all_macros[0]) is tuple
                and len(all_macros[0]) >= 3
                and all_macros[0][2] == sample.file_path):
                logger.warning("Buggy oletools version detected, result "
                    "overridden. May lead to false negatives, please update to "
                    "fixed version")
                report['has_macros'] = False

            if vbaparser.detect_vba_macros():
                vb_code = vbaparser.extract_all_macros()
                for (_, _, _, c) in vb_code:
                    autoexec = detect_autoexec(c)
                    if len(autoexec) >= 1:
                        report['autoexec'].append(autoexec[0])

                    suspicious = detect_suspicious(c)
                    if len(suspicious) >= 1:
                        report['suspicious'].append(suspicious[0])

            vbaparser.close()
        except IOError:
            raise
        except (TypeError, FileOpenError):
            # The given file is not an office document.
            pass
        except Exception as error:
            logger.exception(error)

        report = OletoolsReport(report)
        sample.register_oletools_report(report)
        return report


class OletoolsReport(object):
    """ Represents a custom Oletools report. """
    def __init__(self, report):
        self.report = report

    def __str__(self):
        return "<OletoolsReport('%s'>" % self.report

    @property
    def has_office_macros(self):
        """
        Detects macros in Microsoft Office documents.

        @return: True if macros where found, otherwise False.
                If VBA_Parser crashes it returns False too.
        """

        try:
            return self.report['has_macros']
        except KeyError:
            return False

    @property
    def vba_code(self):
        """
        Extracts vba code from Microsoft Office documents.
        @return: vba code if found, otherwise empty string.
        """
        try:
            return self.report['vba']
        except KeyError:
            return ""

    @property
    def has_autoexec(self):
        """
        Uses olevba detect_autoexec and reports if something was found.
        @return: True or False
        """
        if len(self.report['autoexec']) > 0:
            return True
        return False

    @property
    def detected_autoexec(self):
        """
        Method to access olevba detect_autoexec report.
        @return: String from List of Tuple(marker, explanation)
        """
        return str(self.report['autoexec'])

    @property
    def is_suspicious(self):
        """
        Uses olevba detect_suspicious and reports if something was found.
        @return: True or False
        """
        if len(self.report['suspicious']) > 0:
            return True
        return False

    @property
    def detected_suspicious(self):
        """
        Method to access olevba detect_suspicious report.
        @return: String from List of Tuple(marker, explanation)
        """
        return str(self.report['suspicious'])

    def has_office_macros_with_suspicious_keyword(self, suspicious_keywords):
        """
        Detects macros with supplied suspicious keywords in Microsoft Office documents.

        @param suspicious_keywords: List of suspicious keyword regexes.
        @return: True if macros with keywords where found, otherwise False.
                If VBA_Parser crashes it returns False too.
        """
        suspicious = False
        try:
            vba = self.report['vba']
            for w in suspicious_keywords:
                if re.search(w, vba):
                    suspicious = True
                    break
        except KeyError:
            return False

        return suspicious
