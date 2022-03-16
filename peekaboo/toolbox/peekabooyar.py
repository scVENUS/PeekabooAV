###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         peekabooyar.py                                                      #
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


from peekaboo.ruleset import Result
from peekaboo.ruleset.rules import Rule
import yara


class ContainsPeekabooYarRule(Rule):
    """
    Checks the given sample for the PeekabooYar (EICAR like) malicious string.
    """
    rule_name = 'contains_peekabooyar'

    def evaluate(self, s):
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

        # FIXME: Only user of file_path. Remove?
        with open(s.file_path, 'rb') as sample_file:
            matches = rules.match(data=sample_file.read())

        if matches != []:
            return self.result(Result.bad,
                               "Die Datei beinhaltet Peekabooyar",
                               False)

        return self.result(Result.unknown,
                           "Die Datei beinhaltet kein erkennbares Peekabooyar",
                           True)
