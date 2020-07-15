###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         files.py                                                            #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2020  science + computing ag                             #
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

from peekaboo.ruleset import Result

import logging


logger = logging.getLogger(__name__)


class Knowntools:
    """ Parent class, defines interface to knowntools. """
    def __init__(self, sample, db_con):
        self.sample = sample
        self.db_con = db_con

    def get_report(self):
        """ Return knowntools report or create if not already cached. """
        if self.sample.knowntools_report is not None:
            return self.sample.knowntools_report

        ktreport = KnowntoolsReport(
            self.db_con.sample_info_fetch(self.sample)
        )

        self.sample.register_knowntools_report(ktreport)
        return ktreport


class KnowntoolsReport:
    """ Represents a custom Knowntools report. """
    def __init__(self, sample_info=None):
        if sample_info is None:
            sample_info = {}
        self.sample_info = sample_info

    def __str__(self):
        return "<KnowntoolsReport('%s'>" % self.report

    @property
    def known(self):
        return bool(self.sample_info)

    @property
    def result(self):
        if self.sample_info:
            return self.sample_info.result
