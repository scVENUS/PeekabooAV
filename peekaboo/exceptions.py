###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# exceptions.py                                                               #
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


class PeekabooException(Exception):
    """ General exception class for all custom exception classes of Peekaboo. """
    pass


class PeekabooConfigException(PeekabooException):
    pass


class PeekabooDatabaseError(PeekabooException):
    pass


class PeekabooRulesetException(PeekabooException):
    pass


class CuckooReportPendingException(PeekabooRulesetException):
    """ An exception signifying that we're waiting for Cuckoo to finish its
    analysis an defer our interpretation of its findings until its report
    becomes available. """
    pass


class CuckooSubmitFailedException(PeekabooException):
    """ An exception raised if submitting a job to Cuckoo fails. """
    pass
