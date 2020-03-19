###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         engine.py                                                           #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2020  science + computing ag                             #
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
from peekaboo.exceptions import PeekabooAnalysisDeferred, \
        PeekabooConfigException, PeekabooRulesetConfigError


logger = logging.getLogger(__name__)


class RulesetEngine(object):
    """
    Peekaboo's ruleset engine.

    @since: 1.6
    """
    known_rules = [
        KnownRule,
        FileLargerThanRule,
        ExpressionRule,
        FileTypeOnWhitelistRule,
        FileTypeOnGreylistRule,
        CuckooEvilSigRule,
        CuckooScoreRule,
        OfficeMacroRule,
        OfficeMacroWithSuspiciousKeyword,
        RequestsEvilDomainRule,
        CuckooAnalysisFailedRule,
        ContainsPeekabooYarRule,
        FinalRule
    ]

    def __init__(self, config, db_con):
        """ Initialise the engine, validate its and the individual rules'
        configuration.

        @param config: ruleset configuration parser
        @param db_con: database connection handed to rules (not used by engine
                       itself)
        @raises PeekabooRulesetConfigError: if configuration errors are found
        """
        # create a lookup table from rule name to class
        rule_classes = {}
        for known_rule in self.known_rules:
            rule_classes[known_rule.rule_name] = known_rule

        try:
            enabled_rules = config.getlist('rules', 'rule')
        except PeekabooConfigException as error:
            raise PeekabooRulesetConfigError(
                'Ruleset configuration error: %s' % error)

        if not enabled_rules:
            raise PeekabooRulesetConfigError(
                'No enabled rules found, check ruleset config.')

        # check if unknown rules are enabled
        known_rule_names = rule_classes.keys()
        unknown_rules = set(enabled_rules) - set(known_rule_names)
        if unknown_rules:
            raise PeekabooRulesetConfigError(
                'Unknown rule(s) enabled: %s' % ', '.join(unknown_rules))

        # check for unknown config sections by using rule names as rules'
        # config section names. Allow all known rules not only the enabled ones
        # because some might be temporarily disabled but should be allowed to
        # retain their configuration. Use += extension of list to avoid
        # 'TypeError: can only concatenate list (not "dict_keys") to list' with
        # python3.
        known_sections = ['rules']
        known_sections += known_rule_names
        config.check_sections(known_sections)

        # instantiate enabled rules and have them check their configuration,
        # user-defined rule order is preserved in enabled_rules and through
        # ordered append() in self.rules
        self.rules = []
        for rule in enabled_rules:
            rule = rule_classes[rule](config, db_con)
            self.rules.append(rule)

    def run(self, sample):
        """ Run all the rules in the ruleset against a given sample

        @param sample: sample to evaluate ruleset against
        @returns: Nothing, all state is recorded in the sample """
        for rule in self.rules:
            rule_name = rule.rule_name
            logger.debug("Processing rule '%s' for %s", rule_name, sample)

            try:
                result = rule.evaluate(sample)
                sample.add_rule_result(result)
            except PeekabooAnalysisDeferred:
                # in case the Sample is requesting the Cuckoo report
                raise
            # catch all other exceptions for this rule
            except Exception as error:
                logger.warning("Unexpected error in '%s' for %s", rule_name,
                               sample)
                logger.exception(error)
                # create "fake" RuleResult
                result = RuleResult("RulesetEngine", result=Result.failed,
                                    reason=_("Rule aborted with error"),
                                    further_analysis=False)
                sample.add_rule_result(result)

            logger.info("Rule '%s' processed for %s", rule_name, sample)
            if not result.further_analysis:
                return

        logger.info("Rules evaluated")
