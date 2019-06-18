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
        FileTypeOnWhitelistRule,
        FileTypeOnGreylistRule,
        CuckooEvilSigRule,
        CuckooScoreRule,
        OfficeMacroRule,
        OfficeMacroWithAutoActionRule,
        RequestsEvilDomainRule,
        CuckooAnalysisFailedRule,
        ContainsPeekabooYarRule,
        FinalRule
    ]

    def __init__(self, ruleset_config, db_con):
        """ Initialise the engine, validate its and the individual rules'
        configuration.

        @raises PeekabooRulesetConfigError: if configuration errors are found
        """
        self.config = ruleset_config
        self.db_con = db_con

        # create a lookup table from rule name to class
        self.rule_classes = {}
        for known_rule in self.known_rules:
            self.rule_classes[known_rule.rule_name] = known_rule

        try:
            self.enabled_rules = self.config.getlist('rules', 'rule')
        except PeekabooConfigException as error:
            raise PeekabooRulesetConfigError(
                'Ruleset configuration error: %s' % error)

        self.validate_rule_config()

    def validate_rule_config(self):
        """ Validate the rule configuration in various ways.

        @returns: None
        @raises PeekabooRulesetConfigError: if configuration errors are found
        @raises KeyError, ValueError, PeekabooConfigException: by failed config
            object accesses
        """
        if not self.enabled_rules:
            raise PeekabooRulesetConfigError(
                'No enabled rules found, check ruleset config.')

        # check if unknown rules are enabled
        known_rule_names = self.rule_classes.keys()
        unknown_rules = set(self.enabled_rules) - set(known_rule_names)
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
        self.config.check_sections(known_sections)

        # have enabled rules check their configuration
        for rule in self.enabled_rules:
            # not passing database connection. Needs revisiting if a rule
            # ever wants to retrieve configuration from the database. For
            # now at least rule constructor and get_config() need to be
            # able to cope without it.
            rule = self.rule_classes[rule](self.config)

    def run(self, sample):
        for rule in self.enabled_rules:
            result = self.__exec_rule(sample, self.rule_classes[rule])
            if not result.further_analysis:
                return

        logger.info("Rules evaluated")

    def __exec_rule(self, sample, rule_class):
        """
        rule wrapper for in/out logging and reporting
        """
        rule_name = rule_class.rule_name
        logger.debug("Processing rule '%s' for %s", rule_name, sample)

        try:
            rule = rule_class(config=self.config, db_con=self.db_con)
            result = rule.evaluate(sample)
            sample.add_rule_result(result)
        except PeekabooAnalysisDeferred:
            # in case the Sample is requesting the Cuckoo report
            raise
        # catch all other exceptions for this rule
        except Exception as e:
            logger.warning("Unexpected error in '%s' for %s", rule_name,
                           sample)
            logger.exception(e)
            # create "fake" RuleResult
            result = RuleResult("RulesetEngine", result=Result.failed,
                                reason=_("Rule aborted with error"),
                                further_analysis=False)
            sample.add_rule_result(result)

        logger.info("Rule '%s' processed for %s", rule_name, sample)
        return result
