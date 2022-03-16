###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         engine.py                                                           #
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


import logging
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.rules import *
from peekaboo.toolbox.cuckoo import Cuckoo
from peekaboo.toolbox.cortex import Cortex
from peekaboo.toolbox.peekabooyar import ContainsPeekabooYarRule
from peekaboo.exceptions import PeekabooAnalysisDeferred, \
        PeekabooConfigException, PeekabooRulesetConfigError


logger = logging.getLogger(__name__)


class RulesetEngine:
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

    def __init__(self, config, job_queue, db_con, analyzer_config):
        """ Create the engine and store its config. Postpone lengthy
        initialisation for later so that it can be registered quickly for
        shutdown requests.

        @param config: ruleset configuration parser
        @param config: PeekabooConfigParser
        @param job_queue: the job queue to optionally submit
                          new/changed/updated samples to
        @type job_queue: JobQueue
        @param db_con: database connection handed to rules (not used by engine
                       itself)
        @type db_con: PeekabooDatabase
        @param analyzer_config: analyzer configuration
        @type analyzer_config: PeekabooAnalyzerConfig
        """
        self.config = config
        self.job_queue = job_queue
        self.db_con = db_con
        self.analyzer_config = analyzer_config
        self.cuckoo = None
        self.cortex = None
        self.rules = []

        self.shutdown_requested = False

    def start(self):
        """ Initialise the engine, validate its and the individual rules'
        configuration.

        @raises PeekabooRulesetConfigError: if configuration errors are found
        """
        # create a lookup table from rule name to class
        rule_classes = {}
        for known_rule in self.known_rules:
            rule_classes[known_rule.rule_name] = known_rule

        try:
            enabled_rules = self.config.getlist('rules', 'rule')
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
        self.config.check_sections(known_sections)

        # instantiate enabled rules and have them check their configuration,
        # user-defined rule order is preserved in enabled_rules and through
        # ordered append() in self.rules
        for rule_name in enabled_rules:
            rule = rule_classes[rule_name](self.config, self.db_con)

            # check if the rule requires any common, long lived logic and
            # instantiate now
            if rule.uses_cuckoo:
                if self.cuckoo is None:
                    logger.debug(
                        "Rule %s uses Cuckoo. Starting job tracker.", rule_name)

                    self.cuckoo = Cuckoo(
                        self.job_queue, self.analyzer_config.cuckoo_url,
                        self.analyzer_config.cuckoo_api_token,
                        self.analyzer_config.cuckoo_poll_interval,
                        self.analyzer_config.cuckoo_submit_original_filename,
                        self.analyzer_config.cuckoo_maximum_job_age)

                    if not self.cuckoo.start_tracker():
                        raise PeekabooRulesetConfigError(
                            "Failure to initialize Cuckoo job tracker")

                rule.set_cuckoo_job_tracker(self.cuckoo)

            if rule.uses_cortex:
                if self.cortex is None:
                    logger.debug(
                        "Rule %s uses Cortex. Starting job tracker.", rule_name)

                    self.cortex = Cortex(
                        self.job_queue,
                        self.analyzer_config.cortex_url,
                        self.analyzer_config.cortex_tlp,
                        self.analyzer_config.cortex_api_token,
                        self.analyzer_config.cortex_poll_interval,
                        self.analyzer_config.cortex_submit_original_filename,
                        self.analyzer_config.cortex_maximum_job_age)

                    if not self.cortex.start_tracker():
                        raise PeekabooRulesetConfigError(
                            "Failure to initialize Cortex job tracker")

                rule.set_cortex_job_tracker(self.cortex)

            self.rules.append(rule)

            # abort startup if we've been asked to shut down meanwhile
            if self.shutdown_requested:
                break

        # shut down what we've initialised if our startup was racing a shutdown
        # request because these resources may not have been allocated yet when
        # the shutdown request arrived.
        if self.shutdown_requested:
            self.shut_down_resources()

    def run(self, sample):
        """ Run all the rules in the ruleset against a given sample

        @param sample: sample to evaluate ruleset against
        @returns: Nothing, all state is recorded in the sample """
        for rule in self.rules:
            rule_name = rule.rule_name
            logger.debug("%d: Processing rule '%s'", sample.id, rule_name)

            try:
                result = rule.evaluate(sample)
                sample.add_rule_result(result)
            except PeekabooAnalysisDeferred:
                # in case the Sample is requesting the Cuckoo report
                raise
            # catch all other exceptions for this rule
            except Exception as error:
                logger.warning(
                    "%d: Unexpected error in '%s'", sample.id, rule_name)
                logger.exception(error)
                # create "fake" RuleResult
                result = RuleResult("RulesetEngine", result=Result.failed,
                                    reason=_("Rule aborted with error"),
                                    further_analysis=False)
                sample.add_rule_result(result)

            logger.info("%d: Rule '%s' processed", sample.id, rule_name)
            if not result.further_analysis:
                return

        logger.info("%d: Rules evaluated", sample.id)

    def shut_down_resources(self):
        """ Shut down dynamically allocated resources such as job trackers.
        """
        if self.cuckoo is not None:
            self.cuckoo.shut_down()

        if self.cortex is not None:
            self.cortex.shut_down()

    def shut_down(self):
        """ Initiate asynchronous shutdown of the ruleset engine and dependent
        logic such as job trackers. """
        self.shutdown_requested = True
        self.shut_down_resources()

    def close_down(self):
        """ Finalize ruleset engine shutdown synchronously. """
        if self.cuckoo is not None:
            self.cuckoo.close_down()

        if self.cortex is not None:
            self.cortex.close_down()
