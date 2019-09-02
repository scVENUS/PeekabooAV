###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         rules.py                                                            #
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

""" Classes implementing the Ruleset """


import re
import logging
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.expressions import ExpressionParser, \
        IdentifierMissingException
from peekaboo.exceptions import PeekabooAnalysisDeferred, \
        CuckooSubmitFailedException, PeekabooRulesetConfigError
from peekaboo.toolbox.ole import Oletools, OletoolsReport, \
        OleNotAnOfficeDocumentException


logger = logging.getLogger(__name__)


class Rule(object):
    """ This is the base class for all rules. It provides common infrastructure
    such as resources that can be used by the rules (configuration, database
    connection) or helper functions. """
    rule_name = 'unimplemented'

    def __init__(self, config=None, db_con=None):
        """ Initialize common configuration and resources """
        self.db_con = db_con
        self.config = config

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
        """ Evaluate a rule against a sample.

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

    def get_cuckoo_report(self, sample):
        """ Get the samples cuckoo_report or submit the sample for analysis by
            Cuckoo.

            @returns: CuckooReport
        """
        report = sample.cuckoo_report
        if report is not None:
            return report

        try:
            job_id = sample.submit_to_cuckoo()
        except CuckooSubmitFailedException as failed:
            logger.error("Submit to Cuckoo failed: %s", failed)
            # exception message intentionally not present in message
            # delivered back to client as to not disclose internal
            # information, should request user to contact admin instead
            return self.result(
                Result.failed,
                _("Behavioral analysis by Cuckoo has produced an error "
                  "and did not finish successfully"),
                False)

        logger.info('Sample submitted to Cuckoo. Job ID: %s. '
                    'Sample: %s', job_id, sample)
        raise PeekabooAnalysisDeferred()


class KnownRule(Rule):
    """ A rule determining if a sample is known by looking at the database for
    a previous record of an identical sample sample. """
    rule_name = 'known'

    def evaluate(self, sample):
        """ Try to get information about the sample from the database. Return
        the old result and reason if found and advise the engine to stop
        processing. """
        sample_info = self.db_con.sample_info_fetch(sample)
        if sample_info:
            return self.result(sample_info.result, sample_info.reason, False)

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
        if sample.mimetypes and sample.mimetypes.issubset(self.whitelist):
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
        if not sample.mimetypes or sample.mimetypes.intersection(self.greylist):
            return self.result(Result.unknown,
                               _("File type is on the list of types to "
                                 "analyze"),
                               True)

        return self.result(Result.unknown,
                           _("File type is not on the list of types to "
                             "analyse (%s)") % sample.mimetypes,
                           False)


class OleRule(Rule):
    """ A common base class for rules that evaluate the Ole report. """
    def evaluate(self, sample):
        """ Report the sample as bad if it contains a macro. """
        if sample.oletools_report is None:
            try:
                ole = Oletools()
                report = ole.get_report(sample)
                sample.register_oletools_report(OletoolsReport(report))
            except OleNotAnOfficeDocumentException:
                return self.result(Result.unknown,
                                   _("File is not an office document"),
                                   True)
            except Exception:
                raise

        return self.evaluate_report(sample.oletools_report)

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
        if report.has_office_macros():
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
        for descr in report.signatures:
            logger.debug(descr['description'])
            sigs.append(descr['description'])

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

        matched = ''.ljust(8).join(["%s\n" % s for s in matched_bad_sigs])
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

        for entry in report.cuckoo_server_messages:
            for failure in self.failure_matches:
                if failure in entry:
                    logger.debug('Failure indicator "%s" found in Cuckoo '
                                 'messages', failure)
                    return self.result(Result.failed, failure_reason, False)

        for entry in report.cuckoo_server_messages:
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
        expressions = self.get_config_value('expression', [])
        if not expressions:
            raise PeekabooRulesetConfigError(
                "List of expressions empty, check %s rule config."
                % self.rule_name)

        self.rules = []
        parser = ExpressionParser()
        for expr in expressions:
            try:
                rule = parser.parse(expr)
                logger.debug("EXPR: %s", expr)
                logger.debug("RULE: %s", rule)
                self.rules.append(rule)
            except SyntaxError as error:
                raise PeekabooRulesetConfigError(error)

    def evaluate(self, sample):
        """ Match what rules report against our known result status names. """
        for rule in self.rules:
            result = None
            context = {'variables': {'sample': sample}}

            while result is None:
                try:
                    result = rule.eval(context = context)
                    # otherwise this is an endless loop
                    if result is None:
                        break
                except IdentifierMissingException as error:
                    if "cuckooreport" == error.args[0]:
                        context['variables']['cuckooreport'] = self.get_cuckoo_report(sample)
                    # here elif for other reports
                    else:
                        return self.result(
                            Result.failed,
                            _("Evaluation of expression uses undefined identifier."),
                            False)

            if result:
                return self.result(result,
                                   _("A rule classified the sample as %s")
                                   % result,
                                   False)

        return self.result(Result.unknown,
                           _("No rule classified the sample in any way."),
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
