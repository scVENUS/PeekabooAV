###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         rules.py                                                            #
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

""" Classes implementing the Ruleset """


import re
import logging
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.expressions import ExpressionParser, \
        IdentifierMissingException
from peekaboo.exceptions import PeekabooAnalysisDeferred, \
        PeekabooRulesetConfigError
from peekaboo.sample import Sample
from peekaboo.toolbox.cuckoo import CuckooReport, CuckooSubmitFailedException
from peekaboo.toolbox.ole import Oletools, OletoolsReport
from peekaboo.toolbox.file import Filetools, FiletoolsReport
from peekaboo.toolbox.known import Knowntools, KnowntoolsReport
from peekaboo.toolbox.cortex import CortexReport, \
        CortexSubmitFailedException, CortexAnalyzerReportMissingException

logger = logging.getLogger(__name__)


class Rule:
    """ This is the base class for all rules. It provides common infrastructure
    such as resources that can be used by the rules (configuration, database
    connection) or helper functions. """
    rule_name = 'unimplemented'
    uses_cuckoo = False
    uses_cortex = False

    def __init__(self, config, db_con):
        """ Initialize common configuration and resources.

        @param config: the ruleset configuration
        @type config: PeekabooConfigParser
        @param db_con: the database connection for storing or looking up data
        @type db_con: PeekabooDatabase
        """
        self.config = config
        self.db_con = db_con

        self.cuckoo = None
        self.cortex = None

        # initialise and validate configuration
        self.config_options = {}
        self.get_config()
        # if this rule has (tried to) read any options from the config, it must
        # believe them to be known and allowed
        if self.config_options:
            self.config.check_section_options(
                self.rule_name, self.config_options.keys())

    def result(self, result, reason, further_analysis):
        """ Construct a RuleResult for returning to the engine. """
        return RuleResult(self.rule_name, result=result, reason=reason,
                          further_analysis=further_analysis)

    def evaluate(self, sample):
        """ Evaluate a rule agaimst a sample. Findings are recorded in the
        sample or returned in the rule result. *Must not* change the rule
        object's internal state because it will be called by multiple workers
        in parallel.

        @param sample: The sample to evaluate.
        @returns: RuleResult containing verdict, reason, source of this
                  assessment (i.e. the rule's name) and whether to continue
                  analysis or not.
        """
        raise NotImplementedError

    def get_config(self):
        """ Extract this rule's configuration out of the ruleset configuration
        object given at creation. To be overridden by child classes if they
        have configuration options. """
        # pass

    def get_config_value(self, option, default, option_type=None):
        """ Get a configuation value for this rule from the ruleset
        configuration. Getter routine and option name to be provided by caller.
        The rule's name is always used as configuration section name.

        @param option: name of option to read
        @type option: string
        @param default: default value to use as fallback and for type
                        determination
        @type default: None, int, float, string, list, tuple
        @param option_type: force the option's value type, necessary for lists
                            of regular expressions or log levels by specifying
                            self.config.RELIST or self.config.LOG_LEVEL
        @type option_type: option type constant of PeekabooConfigParser, e.g.
                           LOG_LEVEL
        @param args, kwargs: additional arguments passed to the getter routine,
                             such as fallback.

        @returns: configuration value read from config
        """
        # mark this config option as known
        self.config_options[option] = True
        return self.config.get_by_type(
            self.rule_name, option, fallback=default, option_type=option_type)

    def set_cuckoo_job_tracker(self, cuckoo):
        """ Set the Cuckoo job tracker to use for submitting samples to Cuckoo
        as well as tracking status.

        @param cuckoo: the Cuckoo job tracker to use
        @type cuckoo: Cuckoo
        """
        self.cuckoo = cuckoo

    def set_cortex_job_tracker(self, cortex):
        """ Set the Cortex job tracker to use for submitting samples to Cortex
        as well as tracking status.

        @param cortex: the Cortex job tracker to use
        @type cortex: Cortex
        """
        self.cortex = cortex

    def get_cuckoo_report(self, sample):
        """ Get the samples cuckoo_report or submit the sample for analysis by
            Cuckoo.

            @returns: CuckooReport
        """
        if sample.cuckoo_failed:
            return None

        report = sample.cuckoo_report
        if report is not None:
            return report

        logger.debug("%d: Submitting to Cuckoo", sample.id)
        try:
            job_id = self.cuckoo.submit(sample)
        except CuckooSubmitFailedException as failed:
            logger.error("%d: Submit to Cuckoo failed: %s", sample.id, failed)
            return None

        logger.info("%d: Sample submitted to Cuckoo. Job ID: %s",
                    sample.id, job_id)
        raise PeekabooAnalysisDeferred()

    def get_oletools_report(self, sample):
        """ Get an Oletools report on the sample.

        @returns: OletoolsReport
        """
        return Oletools(sample).get_report()

    def get_filetools_report(self, sample):
        """ Get a Filetools report on the sample.

        @returns: FiletoolsReport
        """
        return Filetools(sample).get_report()

    def get_knowntools_report(self, sample):
        """ Get a Knowntools report on the sample.

        @returns: KnowntoolsReport
        """
        return Knowntools(sample, self.db_con).get_report()

    def get_cortex_report(self, sample):
        """ Get the sample's Cortex report.

        @returns: CortexReport or None if a previous analysis attempt has
                  already failed.
        """
        if sample.cortex_failed:
            return None

        report = sample.cortex_report
        if report is None:
            # here we synthesize the main CortexReport as a (mostly) empty
            # proxy and attach it to the sample. Since the report consists of
            # potentially multiple subreports of Cortex analyzers, the report
            # may request submission to an actual analyzer through an
            # exception when accessing certain properties.
            report = CortexReport()
            sample.register_cortex_report(report)

        return report

    def submit_to_cortex(self, sample, analyzer):
        """ Submit the sample to an actual Cortex analyzer to augment the
        report.

        @param sample: The sample to submit to Cortex.
        @type sample: Sample
        @param analyzer: The Cortex analyzer to submit to.
        @type analyzer: subclass of CortexAnalyzer
        @returns: None if submit failed
        @raises PeekabooAnalysisDeferred: if successfully submitted to abort
                                          ruleset run until result has been
                                          retrieved.
        """
        logger.debug("%d: Submitting to Cortex", sample.id)
        try:
            job_id = self.cortex.submit(sample, analyzer)
        except CortexSubmitFailedException as failed:
            logger.error("%d: Submit to Cortex failed: %s", sample.id, failed)
            return None

        logger.info("%d: Sample submitted to Cortex. Job ID: %s",
                    sample.id, job_id)
        raise PeekabooAnalysisDeferred()


class KnownRule(Rule):
    """ A rule determining if a sample is known by looking at the database for
    a previous record of an identical sample sample. """
    rule_name = 'known'

    def evaluate(self, sample):
        """ Try to get information about the sample from the database. Return
        the old result and reason if found and advise the engine to stop
        processing. """
        ktreport = self.get_knowntools_report(sample)
        if ktreport.known:
            result, reason = ktreport.worst()
            return self.result(result, reason, False)

        return self.result(Result.unknown,
                           _("File is not yet known to the system"),
                           True)


class FileLargerThanRule(Rule):
    """ A rule determining by file size whether a sample can be harmful at all.
    """
    rule_name = 'file_larger_than'

    def get_config(self):
        self.size_threshold = self.get_config_value('bytes', 5)

    def evaluate(self, sample):
        """ Evaluate whether the sample is larger than a certain threshold.
        Advise the engine to stop processing if the size is below the
        threshold. """
        try:
            sample_size = sample.file_size
        except OSError as oserr:
            return self.result(
                Result.failed,
                _("Failure to determine sample file size: %s") % oserr,
                False)

        if sample_size > self.size_threshold:
            return self.result(Result.unknown,
                               _("File has more than %d bytes")
                               % self.size_threshold,
                               True)

        return self.result(
            Result.ignored,
            _("File is only %d bytes long") % sample_size,
            False)


class FileTypeOnWhitelistRule(Rule):
    """ A rule checking whether the known file type(s) of the sample are on a
    whitelist. """
    rule_name = 'file_type_on_whitelist'

    def get_config(self):
        whitelist = self.get_config_value('whitelist', [])
        if not whitelist:
            raise PeekabooRulesetConfigError(
                "Empty whitelist, check %s rule config." % self.rule_name)

        self.whitelist = set(whitelist)

    def evaluate(self, sample):
        """ Ignore the file only if *all* of its mime types are on the
        whitelist and we could determine at least one. """
        filereport = self.get_filetools_report(sample)
        mimetypes = filereport.mime_types
        if sample.type_declared is not None:
            mimetypes.add(sample.type_declared)
        if mimetypes and mimetypes.issubset(self.whitelist):
            return self.result(Result.ignored,
                               _("File type is on whitelist"),
                               False)

        return self.result(Result.unknown,
                           _("File type is not on whitelist"),
                           True)


class FileTypeOnGreylistRule(Rule):
    """ A rule checking whether any of the sample's known file types are on a
    greylist, i.e. enabled for analysis. """
    rule_name = 'file_type_on_greylist'

    def get_config(self):
        greylist = self.get_config_value('greylist', [])
        if not greylist:
            raise PeekabooRulesetConfigError(
                "Empty greylist, check %s rule config." % self.rule_name)

        self.greylist = set(greylist)

    def evaluate(self, sample):
        """ Continue analysis if any of the sample's MIME types are on the
        greylist or in case we don't have one. """
        filereport = self.get_filetools_report(sample)
        mimetypes = filereport.mime_types
        if sample.type_declared is not None:
            mimetypes.add(sample.type_declared)
        if not mimetypes or mimetypes.intersection(self.greylist):
            return self.result(Result.unknown,
                               _("File type is on the list of types to "
                                 "analyze"),
                               True)

        return self.result(Result.unknown,
                           _("File type is not on the list of types to "
                             "analyse (%s)") % mimetypes,
                           False)


class OleRule(Rule):
    """ A common base class for rules that evaluate the Ole report. """
    def evaluate(self, sample):
        """ Report the sample as bad if it contains a macro. """
        # we always get a report, albeit a maybe empty one
        return self.evaluate_report(self.get_oletools_report(sample))

    def evaluate_report(self, report):
        """ Evaluate an Ole report.

        @param report: The Ole report.
        @returns: RuleResult containing verdict.
        """
        raise NotImplementedError


class OfficeMacroRule(OleRule):
    """ A rule checking the sample for Office macros. """
    rule_name = 'office_macro'

    def evaluate_report(self, report):
        """ Report the sample as bad if it contains a macro. """
        if report.has_office_macros:
            return self.result(Result.bad,
                               _("The file contains an Office macro"),
                               False)

        return self.result(Result.unknown,
                           _("The file does not contain a recognizable "
                             "Office macro"),
                           True)


class OfficeMacroWithSuspiciousKeyword(OleRule):
    """ A rule checking the sample for Office macros. """
    rule_name = 'office_macro_with_suspicious_keyword'

    def get_config(self):
        # get list of keywords from config file
        self.suspicious_keyword_list = self.get_config_value(
            'keyword', [], option_type=self.config.IRELIST)
        if not self.suspicious_keyword_list:
            raise PeekabooRulesetConfigError(
                "Empty suspicious keyword list, check %s rule config." %
                self.rule_name)

    def evaluate_report(self, report):
        if report.has_office_macros_with_suspicious_keyword(self.suspicious_keyword_list):
            return self.result(Result.bad,
                               _("The file contains an Office macro which "
                                 "runs at document open"),
                               False)

        return self.result(Result.unknown,
                           _("The file does not contain a recognizable "
                             "Office macro that is run at document open"),
                           True)


class CuckooRule(Rule):
    """ A common base class for rules that evaluate the Cuckoo report. """
    uses_cuckoo = True

    def evaluate(self, sample):
        """ If a report is present for the sample in question we call method
        evaluate_report() implemented by subclasses to evaluate it for
        findings. Otherwise we submit the sample to Cuckoo and raise
        PeekabooAnalysisDeferred to abort the current run of the ruleset
        until the report arrives. If submission to Cuckoo fails we will
        ourselves report the sample as failed.

        @param sample: The sample to evaluate.
        @raises PeekabooAnalysisDeferred: if the sample was submitted to Cuckoo
        @returns: RuleResult containing verdict.
        """
        report = self.get_cuckoo_report(sample)
        if report is None:
            # exception message intentionally not present in message
            # delivered back to client as to not disclose internal
            # information, should request user to contact admin instead
            return self.result(
                Result.failed,
                _("Behavioral analysis by Cuckoo has produced an error "
                  "and did not finish successfully"),
                False)

        # call report evaluation function if we get here
        return self.evaluate_report(report)

    def evaluate_report(self, report):
        """ Evaluate a Cuckoo report.

        @param report: The Cuckoo report.
        @returns: RuleResult containing verdict.
        """
        raise NotImplementedError


class CuckooEvilSigRule(CuckooRule):
    """ A rule evaluating the signatures from the Cuckoo report against a list
    of signatures considered bad. """
    rule_name = 'cuckoo_evil_sig'

    def get_config(self):
        # list all installed signatures
        # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
        self.bad_sigs = self.get_config_value(
            'signature', [], option_type=self.config.RELIST)
        if not self.bad_sigs:
            raise PeekabooRulesetConfigError(
                "Empty bad signature list, check %s rule config." %
                self.rule_name)

    def evaluate_report(self, report):
        """ Evaluate the sample against signatures that if matched mark a
        sample as bad. """
        # look through matched signatures
        sigs = []
        for descr in report.signature_descriptions:
            logger.debug("Signature from cuckoo report: %s", descr)
            sigs.append(descr)

        # check if there is a "bad" signatures and return bad
        matched_bad_sigs = []
        for bad_sig in self.bad_sigs:
            # iterate over each sig individually to allow regexes to use
            # anchors such as ^ and $ and avoid mismatches, e.g. by ['foo',
            # 'bar'] being stringified to "['foo', 'bar']" and matching
            # /fo.*ar/.
            for sig in sigs:
                match = re.search(bad_sig, sig)
                if match:
                    matched_bad_sigs.append(sig)

        if not matched_bad_sigs:
            return self.result(Result.unknown,
                               _("No signature suggesting malware detected"),
                               True)

        matched = ", ".join(matched_bad_sigs)
        return self.result(Result.bad,
                           _("The following signatures have been recognized: "
                             "%s") % matched,
                           False)


class CuckooScoreRule(CuckooRule):
    """ A rule checking the score reported by Cuckoo against a configurable
    threshold. """
    rule_name = 'cuckoo_score'

    def get_config(self):
        self.score_threshold = self.get_config_value('higher_than', 4.0)

    def evaluate_report(self, report):
        """ Evaluate the score reported by Cuckoo against the threshold from
        the configuration and report sample as bad if above. """

        if report.score >= self.score_threshold:
            return self.result(Result.bad,
                               _("Cuckoo score >= %s: %s") %
                               (self.score_threshold, report.score),
                               False)

        return self.result(Result.unknown,
                           _("Cuckoo score < %s: %s") %
                           (self.score_threshold, report.score),
                           True)


class RequestsEvilDomainRule(CuckooRule):
    """ A rule checking the domains reported as requested by the sample by
    Cuckoo against a blacklist. """
    rule_name = 'requests_evil_domain'

    def get_config(self):
        self.evil_domains = self.get_config_value('domain', [])
        if not self.evil_domains:
            raise PeekabooRulesetConfigError(
                "Empty evil domain list, check %s rule config."
                % self.rule_name)

    def evaluate_report(self, report):
        """ Report the sample as bad if one of the requested domains is on our
        list of evil domains. """

        for domain in report.requested_domains:
            if domain in self.evil_domains:
                return self.result(Result.bad,
                                   _("The file attempts to contact at least "
                                     "one domain on the blacklist (%s)")
                                   % domain,
                                   False)

        return self.result(Result.unknown,
                           _("File does not seem to attempt contact with "
                             "domains on the blacklist"),
                           True)


class CuckooAnalysisFailedRule(CuckooRule):
    """ A rule checking the final status reported by Cuckoo for success. """
    rule_name = 'cuckoo_analysis_failed'

    def get_config(self):
        self.failure_matches = self.get_config_value('failure', [])
        self.success_matches = self.get_config_value(
            'success', ['analysis completed successfully'])

    def evaluate_report(self, report):
        """ Report the sample as bad if the Cuckoo indicates that the analysis
        has failed. """
        if report.errors:
            logger.warning('Cuckoo produced %d error(s) during processing.',
                           len(report.errors))

        failure_reason = _("Behavioral analysis by Cuckoo has produced "
                           "an error and did not finish successfully")

        for entry in report.server_messages:
            for failure in self.failure_matches:
                if failure in entry:
                    logger.debug('Failure indicator "%s" found in Cuckoo '
                                 'messages', failure)
                    return self.result(Result.failed, failure_reason, False)

        for entry in report.server_messages:
            for success in self.success_matches:
                if success in entry:
                    logger.debug('Success indicator "%s" found in Cuckoo '
                                 'messages', success)
                    return self.result(Result.unknown,
                                       _("Behavioral analysis by Cuckoo "
                                         "completed successfully"),
                                       True)

        logger.debug('Neither success nor failure indicators found, '
                     'considering analysis failed.')
        return self.result(Result.failed, failure_reason, False)


class ExpressionRule(Rule):
    """ A rule checking the sample and cuckoo report against an almost
    arbitrary logical expression. """
    rule_name = 'expressions'

    def get_config(self):
        # allow to raise debug level of expressions module explicitly. Beware:
        # This affects not just individual objects but the whole module which
        # is why we do it by poking the logger and not via a setter method.
        log_level = self.get_config_value(
            'log_level', logging.WARNING, option_type=self.config.LOG_LEVEL)
        expression_logger = logging.getLogger('peekaboo.ruleset.expressions')
        expression_logger.setLevel(log_level)

        raw_expressions = self.get_config_value('expression', [])
        if not raw_expressions:
            raise PeekabooRulesetConfigError(
                "List of expressions empty, check %s rule config."
                % self.rule_name)

        self.expressions = []
        parser = ExpressionParser()

        # context of dummy objects to test expressions against
        context = {
            'variables': {
                'sample': Sample(b"dummy"),
                'cuckooreport': CuckooReport(),
                'olereport': OletoolsReport(),
                'filereport': FiletoolsReport(),
                'knownreport': KnowntoolsReport(),
                'cortexreport': CortexReport(),
            }
        }

        for raw_expression in raw_expressions:
            try:
                parsed_expression = parser.parse(raw_expression)
                logger.debug("Expression from config file: %s", raw_expression)
                logger.debug("Expression parsed: %s", parsed_expression)
            except SyntaxError as error:
                raise PeekabooRulesetConfigError(error)

            if not parsed_expression.is_implication():
                raise PeekabooRulesetConfigError(
                    "Malformed expression, missing implication: %s" %
                    raw_expression)

            # run expression against dummy objects to find out if it's
            # attempting anything illegal
            try:
                parsed_expression.eval(context=context)
            except CortexAnalyzerReportMissingException:
                # This exception tells us that CortexReport knows the analyzer
                # and wants a job submitted. So all is well.
                pass
            except IdentifierMissingException as missing:
                # our dummy context provides everything we would provide at
                # runtime as well, so any missing identifier is an error at
                # this point
                identifier = missing.name
                raise PeekabooRulesetConfigError(
                    "Invalid expression, unknown identifier %s: %s" % (
                        identifier, raw_expression))
            except AttributeError as missing:
                raise PeekabooRulesetConfigError(
                    "Invalid expression, %s: %s" % (missing, raw_expression))

            self.expressions.append(parsed_expression)

    def uses_identifier(self, identifier):
        """ Determine if any of the expressions uses a particular identifier.

        @param identifier: the identifier to look for
        @type identifier: string """
        for expression in self.expressions:
            if identifier in expression.identifiers:
                # this expression may request the cuckoo report
                return True

        return False

    @property
    def uses_cuckoo(self):
        """ Tells if any expression uses the cuckoo report. Overrides base
        class variable with a dynamic determination. """
        return self.uses_identifier("cuckooreport")

    @property
    def uses_cortex(self):
        """ Tells if any expression uses the Cortex report. Overrides base
        class variable with a dynamic determination. """
        return self.uses_identifier("cortexreport")

    def resolve_identifier(self, identifier, context, sample):
        """ Resolves a missing identifer into an object.

        @param identifer: Name of identifer to resolve.
        @type identifier: string
        @returns: object or None if identifier is unknown.
        """
        if identifier == "cuckooreport":
            logger.debug("Expression requests cuckoo report")
            value = self.get_cuckoo_report(sample)
            if value is None:
                return self.result(
                    Result.failed,
                    _("Evaluation of expression couldn't get cuckoo "
                      "report."),
                    False)
        elif identifier == "olereport":
            logger.debug("Expression requests oletools report")
            value = self.get_oletools_report(sample)
        elif identifier == "filereport":
            logger.debug("Expression requests filetools report")
            value = self.get_filetools_report(sample)
        elif identifier == "knownreport":
            logger.debug("Expression requests knowntools report")
            value = self.get_knowntools_report(sample)
        elif identifier == "cortexreport":
            logger.debug("Expression requests cortex report")
            value = self.get_cortex_report(sample)
            if value is None:
                return self.result(
                    Result.failed,
                    _("Evaluation of expression couldn't get Cortex "
                      "report."),
                    False)
        # elif here for other identifiers
        else:
            return self.result(
                Result.failed,
                _("Evaluation of expression uses undefined identifier."), False)

        context['variables'][identifier] = value
        return None

    def evaluate(self, sample):
        """ Match what rules report against our known result status names. """
        for ruleno, expression in enumerate(self.expressions):
            result = None
            context = {'variables': {'sample': sample}}

            # retry until expression evaluation doesn't throw exceptions any
            # more
            while True:
                identifier = None
                cortex_analyzer = None
                try:
                    result = expression.eval(context=context)
                    break
                except IdentifierMissingException as missing:
                    identifier = missing.name
                except CortexAnalyzerReportMissingException as missing:
                    cortex_analyzer = missing.analyzer

                if identifier is not None:
                    result = self.resolve_identifier(
                        identifier, context, sample)
                    if result is not None:
                        return result

                if cortex_analyzer is not None:
                    self.submit_to_cortex(sample, cortex_analyzer)
                    # submission either raises an exception or has failed, so
                    # getting here is an error
                    return self.result(
                        Result.failed,
                        _("Evaluation of expression failed to submit Cortex "
                          "analysis."),
                        False)

                # beware: here we intentionally loop on through for retry

            # our implication returns None if expression did not match
            if result is None:
                continue

            # eval will return something completely different if implication is
            # missing
            if not isinstance(result, Result):
                logger.warning("Expression %d is returning an invalid result, "
                               "failing evaluation: %s", ruleno, expression)
                result = Result.failed

            return self.result(
                result,
                _("The expression (%d) classified the sample as %s")
                % (ruleno, result),
                False)

        return self.result(
            Result.unknown,
            _("No expression classified the sample in any way."),
            True)


class FinalRule(Rule):
    """ A catch-all rule. """
    rule_name = 'final_rule'

    def evaluate(self, sample):
        """ Report an unknown analysis result indicating that nothing much can
        be said about the sample. """
        return self.result(Result.unknown,
                           _("File does not seem to exhibit recognizable "
                             "malicious behaviour"),
                           True)
