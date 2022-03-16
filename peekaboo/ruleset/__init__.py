###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         __init__.py                                                         #
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


from enum import Enum, unique


@unique
class Result(Enum):
    """ Enumeration of rule evaluation result severities with apropriate
    comparison semantics. """
    unchecked = 1
    unknown = 2
    ignored = 3
    good = 4
    failed = 5
    bad = 6

    def __eq(self, other):
        if self.__class__ is other.__class__:
            return self.value == other.value
        return NotImplemented

    def __gt__(self, other):
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __lt__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __ge__(self, other):
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __le__(self, other):
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented


class RuleResult:
    """ A rule evaluation result with severity, deciding rule, decision
    description and reason. """
    def __init__(self, rule,
                 result=Result.unknown,
                 reason=None,
                 further_analysis=True):
        self.result = Result.unchecked
        self.rule = rule
        self.result = result
        self.reason = reason
        if self.reason is None:
            self.reason = _("Rule without result")
        self.further_analysis = further_analysis

    def __str__(self):
        return (_("Result \"%s\" of rule %s - %s, analysis continues: %s.")
                % (self.result.name, self.rule, self.reason,
                   _('Yes') if self.further_analysis else _('No')))

    __repr__ = __str__
