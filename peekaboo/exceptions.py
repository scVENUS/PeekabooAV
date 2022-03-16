###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# exceptions.py                                                               #
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


class PeekabooException(Exception):
    """ General exception class for all custom exception classes of Peekaboo. """
    pass


class PeekabooConfigException(PeekabooException):
    pass


class PeekabooDatabaseError(PeekabooException):
    pass


class PeekabooRulesetException(PeekabooException):
    pass


class PeekabooRulesetConfigError(PeekabooException):
    """ Used to signal that a rule is unhappy with its configuration. """
    pass


class PeekabooAnalysisDeferred(PeekabooRulesetException):
    """ Analysis has been deferred to a later point in time.

    An exception signifying that analysis has been deferred to a later point in
    time. Ruleset processing will be aborted (without error). Useful if we're
    waiting for someone to finish their analysis and defer our interpretation
    of their findings until they become available, most notably the Cuckoo
    report.

    Not an exception in the traditional sense since it does not indicate an
    error but actually influences control flow instead. Somewhat questionable
    in that regard.

    The raiser becomes owner of the sample and is responsible to appropriately
    resubmit it into Peekaboo once it wants processing to continue. That should
    take into account that the ruleset will be rerun from the very beginning.
    """
    pass
