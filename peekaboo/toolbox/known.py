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
import datetime

from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


class Knowntools:
    """ Parent class, defines interface to knowntools. """
    def __init__(self, sample, db_con):
        self.sample = sample
        self.db_con = db_con

    async def get_report(self):
        """ Return knowntools report or create if not already cached. """
        if self.sample.knowntools_report is not None:
            return self.sample.knowntools_report

        ktreport = KnowntoolsReport(
            await self.db_con.analysis_journal_get_first(self.sample),
            await self.db_con.analysis_journal_get_last(self.sample),
            await self.db_con.analysis_journal_get_worst(self.sample)
        )

        self.sample.register_knowntools_report(ktreport)
        return ktreport


class KnowntoolsReport:
    """ Represents a custom Knowntools report. """
    def __init__(self, first=None, last=None, worst=None):
        self.__first = first
        self.__last = last
        self.__worst = worst

    def __str__(self):
        return "<KnowntoolsReport(first='%s', last='%s', worst='%s')>" % (
            self.__first, self.__last, self.__worst)

    @property
    def known(self):
        """ Determines if there is a database entry for this sample """
        return bool(self.__last)

    @property
    def last_result(self):
        """ Return the cached result """
        if self.__last is None:
            return Result.unknown

        return self.__last['result']

    result = last_result

    @property
    def worst(self):
        """ Return the worst cached result's attribute dict. Can be None. """
        return self.__worst

    @property
    def worst_result(self):
        """ Return the worst result cached """
        if self.__worst is None:
            return Result.unknown

        return self.worst.result

    @property
    def first(self):
        """ Calculates the age in days since first record of this sample """
        if self.__first is None:
            return 0

        first = self.__first.analysis_time
        now = datetime.datetime.now(datetime.timezone.utc)
        difference = now - first
        return difference.days

    @property
    def last(self):
        """ Calculates the age in days since most recent record of this
        sample """
        if self.__last is None:
            return 0

        last = self.__last.analysis_time
        now = datetime.datetime.now(datetime.timezone.utc)
        difference = now - last
        return difference.days
