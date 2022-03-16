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
from datetime import datetime

from peekaboo.ruleset import Result


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
            self.db_con.analysis_journal_fetch_journal(self.sample)
        )

        self.sample.register_knowntools_report(ktreport)
        return ktreport


class KnowntoolsReport:
    """ Represents a custom Knowntools report. """
    def __init__(self, sample_journal=None):
        if sample_journal is None:
            sample_journal = []
        self.sample_journal = sample_journal

    def __str__(self):
        return "<KnowntoolsReport('%s'>" % self.sample_journal

    @property
    def known(self):
        """ Determines if there is a database entry for this sample """
        return bool(self.sample_journal)

    @property
    def last_result(self):
        """ Return the cached result """
        if self.sample_journal:
            return self.sample_journal[-1].result
        return Result.unknown

    @property
    def result(self):
        """ Return the cached result """
        return self.last_result

    def worst(self):
        """ Return the worst (result, reason) cached """
        worst_result = Result.unchecked
        worst_reason = ""
        for _, result, reason in self.sample_journal:
            if result > worst_result:
                worst_result = result
                worst_reason = reason
        return (worst_result, worst_reason)

    @property
    def worst_result(self):
        """ Return the worst result cached """
        return self.worst()[0]

    @property
    def first(self):
        """ Calculates the age in days since first record of this sample """
        if self.sample_journal:
            first = self.sample_journal[0].analysis_time
            now = datetime.today()
            difference = now - first
            return difference.days
        return 0

    @property
    def last(self):
        """ Calculates the age in days since most recent record of this
        sample """
        if self.sample_journal:
            last = self.sample_journal[-1].analysis_time
            now = datetime.today()
            difference = now - last
            return difference.days
        return 0
