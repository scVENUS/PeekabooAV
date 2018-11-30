###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# __init__.py                                                                 #
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


import re


VERSION = (1, 6, 2)
AUTHORS = ['Felix Bauer', 'Sebastian Deiss']

__version__ = '.'.join(map(str, VERSION))
__author__ = ', '.join(AUTHORS)
__description__ = 'Peekaboo Extended Email Attachment Behavior Observation Owl'
__copyright__ = 'Copyright (C) 2016-2018 science + computing ag. All rights reserved.'
__license__ = 'GPLv3'


_owl = """
PEEKABOO {0}

Peekaboo Extended Email Attachment Behavior Observation Owl

                   _a_aa                    a_aa,
                    '*U4UUUULa_aa_aa_aajUUU4XU7'
                      aX''''''UUXU4XUU'''''!Ua
                    _U'        -U4UU'   _    'U,
                    ?i   jLd1   ?#Wi   4L01   Ui
                    -U,        4#000P        _U'
                     -*Xa_a_a_WUW##KUL_a_a_aX7'
                    _aXUXUUU4UUX4XX444UUUUUUXLa,
                   _UXXUXUXU47'!'!'!'!*X444U4UXX,
                   ?XU4U4''   __    ___-'UUXUUi
                   ?4U4' / | / /_  |___ \ 'UUXi
                    *Xi  | || '_ \   __) | ?X7
                     *L  | || (_) | / __/   j7
                      *a |_(_)___(_)_____|  jY
                       -L,                _/'
                         'l,            _/'
                           j7_a_;  aaa/4
               _aaaaaa#0000#00000##0##00000000aaaaaa,
        aaad0P!!!!!!                             '!!!!!!Laaa
  _aa!!!!                                                    !! _,
(never mind the K)
""".format(__version__)


#
# Helpers
#


class MultiRegexMatcher(object):
    """
    Validate multiple regular expressions for the same string.

    @author: Sebastian Deiss
    """
    def __init__(self, patterns, flags=0):
        self.__patterns = [(re.compile(pattern, flags)) for pattern in patterns]
        self.matched_pattern = -1    # No pattern matched (default value)

    def match(self, str):
        """
        Try to apply the patterns at the start of the string.
        As soon as a pattern that matches, processing is stopped
        and a match object is returned.

        :param str: The string to apply the pattern to.
        :return: a match object, or None if no match was found.
        """
        iter_count = 0
        for pattern in self.__patterns:
            _match = re.match(pattern, str)
            if _match:
                self.matched_pattern = iter_count
                return _match
            iter_count += 1
        return None
