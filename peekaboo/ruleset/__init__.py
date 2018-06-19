###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         __init__.py                                                         #
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


from enum import Enum, unique


@unique
class Result(Enum):
    """
    @author: Felix Bauer
    """
    inProgress = 0
    unchecked = 1
    unknown = 2
    ignored = 3
    checked = 4
    good = 5
    bad = 6

    @staticmethod
    def from_string(result_str):
        for i in Result:
            if i.name == result_str:
                return i
        raise ValueError('%s: Element not found' % result_str)

    def __gt__(self, other):
        return self.value >= other.value

    def __lt__(self, other):
        return other.value >= self.value


class RuleResult:
    """
    @author: Felix Bauer
    """
    def __init__(self, rule,
                 result=Result.unknown,
                 reason='regel ohne Ergebnis',
                 further_analysis=True):
        self.result = Result.unchecked
        self.rule = rule
        self.result = result
        self.reason = reason
        self.further_analysis = further_analysis

    def __str__(self):
        return ("Ergebnis \"%s\" der Regel %s - %s, Analyse wird fortgesetzt: %s."\
                                                        % (self.result.name,
                                                           self.rule,
                                                           self.reason,
                                                           'Ja' if self.further_analysis else 'Nein'))

    __repr__ = __str__
