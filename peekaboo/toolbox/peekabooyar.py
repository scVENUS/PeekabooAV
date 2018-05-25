###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         peekabooyar.py                                                      #
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


import traceback
from peekaboo.ruleset import Result, RuleResult
import yara


def contains_peekabooyar(config, s):
    """
    Checks the given sample for the PeekabooYar (EICAR like) malicious string.

    :param s: sample to check
    :return: RueleResult
    """
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    rules = yara.compile(
        source='''
        rule peekabooyar
        {
             strings:
                  $peekabooyar1 = "X5O!P%@AP-/_(:)_/-X22x8cz2$PeekabooAV-STD-ANTIVIRUS-TEST-FILE!$H+H*"
        
             condition:
                  $peekabooyar1
        }'''
    )

    with open(s.get_file_path(), 'rb') as f:
        matches = rules.match(data=f.read())

    if matches != []:
        return RuleResult(position,
                          result=Result.bad,
                          reason="Die Datei beinhaltet Peekabooyar.",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Die Datei beinhaltet kein erkennbares Peekabooyar.",
                      further_analysis=True)
