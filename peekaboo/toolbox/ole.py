###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         ole.py                                                              #
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
import re
from oletools.olevba import VBA_Parser, FileOpenError
from oletools.olevba import detect_autoexec, detect_suspicious

logger = logging.getLogger(__name__)


class Oletools:
    """ Parent class, defines interface to Oletools. """
    def __init__(self, sample):
        self.sample = sample

    def get_report(self):
        """ Return oletools report or create if not already cached. """
        if self.sample.oletools_report is not None:
            return self.sample.oletools_report

        report = {
            'autoexec': [],
            'suspicious' : [],
        }

        filename = self.sample.filename
        try:
            vbaparser = VBA_Parser(filename, data=self.sample.content)

            # VBA_Parser reports macros for office documents
            report['has_macros'] = vbaparser.detect_vba_macros() or vbaparser.detect_xlm_macros()
            try:
                report['vba'] = vbaparser.reveal()
            except TypeError:
                # office document with no macros
                pass

            # When called on an empty or text document oletools will falsely
            # report that it contains macros and returns a one item list of
            # macros which contains only the filename again.
            #
            # Oletool assume the submitted file is the plain text macro if
            # it can not determine another file type.
            #
            # Add a workaround to detect this behaviour and override the
            # result.
            all_macros = vbaparser.extract_all_macros()
            if (report['has_macros'] and len(all_macros) == 1
                    and isinstance(all_macros[0], tuple)
                    and len(all_macros[0]) >= 3
                    and all_macros[0][2] == filename):
                report['has_macros'] = False

            if vbaparser.detect_vba_macros():
                vb_code = vbaparser.extract_all_macros()
                for (_, _, _, c) in vb_code:
                    autoexec = detect_autoexec(c)
                    if len(autoexec) >= 1:
                        report['autoexec'].extend(autoexec)

                    suspicious = detect_suspicious(c)
                    if len(suspicious) >= 1:
                        report['suspicious'].extend(suspicious)

            vbaparser.close()
        except IOError:
            raise
        except (TypeError, FileOpenError):
            # The given file is not an office document.
            pass
        except Exception as error:
            logger.exception(error)

        report = OletoolsReport(report)
        self.sample.register_oletools_report(report)
        return report


class OletoolsReport:
    """ Represents a custom Oletools report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
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
        return self.report.get('has_macros', False)

    @property
    def vba_code(self):
        """
        Extracts vba code from Microsoft Office documents.
        @return: vba code if found, otherwise empty string.
        """
        return self.report.get('vba', '')

    @property
    def has_autoexec(self):
        """
        Uses olevba detect_autoexec and reports if something was found.
        @return: True or False
        """
        if self.report.get('autoexec', []):
            return True
        return False

    @property
    def detected_autoexec(self):
        """
        Method to access olevba detect_autoexec report.
        @return: String from List of Tuple(marker, explanation)
        """
        return "%s" % self.report.get('autoexec', [])

    @property
    def is_suspicious(self):
        """
        Uses olevba detect_suspicious and reports if something was found.
        @return: True or False
        """
        if self.report.get('suspicious', []):
            return True
        return False

    @property
    def detected_suspicious(self):
        """
        Method to access olevba detect_suspicious report.
        @return: String from List of Tuple(marker, explanation)
        """
        return "%s" % self.report.get('suspicious', [])

    def has_office_macros_with_suspicious_keyword(self, suspicious_keywords):
        """
        Detects macros with supplied suspicious keywords in Microsoft Office documents.

        @param suspicious_keywords: List of suspicious keyword regexes.
        @return: True if macros with keywords where found, otherwise False.
                If VBA_Parser crashes it returns False too.
        """
        vba = self.report.get('vba')
        if vba is None:
            return False

        suspicious = False
        for word in suspicious_keywords:
            if re.search(word, vba):
                suspicious = True
                break

        return suspicious
