###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         engine.py                                                           #
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


import logging
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.rules import *
from peekaboo.toolbox.peekabooyar import ContainsPeekabooYarRule
from peekaboo.exceptions import CuckooReportPendingException


logger = logging.getLogger(__name__)


class RulesetEngine(object):
    """
    Peekaboo's ruleset engine.

    @author: Sebastian Deiss
    @since: 1.6
    """
    rules = [
        KnownRule,
        FileLargerThanRule,
        FileTypeOnWhitelistRule,
        FileTypeOnGreylistRule,
        CuckooEvilSigRule,
        CuckooScoreRule,
        OfficeMacroRule,
        RequestsEvilDomainRule,
        CuckooAnalysisFailedRule,
        ContainsPeekabooYarRule,
        FinalRule
    ]

    def __init__(self, sample, ruleset_config, db_con):
        self.sample = sample
        self.config = ruleset_config
        self.db_con = db_con

    def run(self):
        for rule in RulesetEngine.rules:
            result = self.__exec_rule(self.sample, rule)
            if not result.further_analysis:
                return

        logger.info("Rules evaluated")

    def __exec_rule(self, sample, rule_class):
        """
        rule wrapper for in/out logging and reporting
        """
        rule_name = rule_class.rule_name
        logger.debug("Processing rule '%s' for %s" % (rule_name, sample))

        try:
            # skip disabled rules.
            if self.config.rule_enabled(rule_name):
                rule_config = self.config.rule_config(rule_name)
                rule = rule_class(config=rule_config, db_con=self.db_con)
                result = rule.evaluate(sample)
            else:
                logger.debug("Rule '%s' is disabled." % rule_name)
                result = RuleResult(
                    rule_name, result=Result.unchecked,
                    reason=_("Rule '%s' is disabled.") % rule_name,
                    further_analysis=True)

            sample.add_rule_result(result)
        except CuckooReportPendingException as e:
            # in case the Sample is requesting the Cuckoo report
            raise
        # catch all other exceptions for this rule
        except Exception as e:
            logger.warning("Unexpected error in '%s' for %s" % (rule_name,
                                                                sample))
            logger.exception(e)
            # create "fake" RuleResult
            result = RuleResult("RulesetEngine", result=Result.failed,
                                reason=_("Rule aborted with error"),
                                further_analysis=False)
            sample.add_rule_result(result)

        logger.info("Rule '%s' processed for %s" % (rule_name, sample))
        return result
