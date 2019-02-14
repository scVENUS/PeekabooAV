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
from peekaboo.exceptions import CuckooReportPendingException, \
        CuckooAnalysisFailedException


logger = logging.getLogger(__name__)


class Rule(object):
    """ This is the base class for all rules. It provides common infrastructure
    such as resources that can be used by the rules (configuration, database
    connection) or helper functions. """
    def __init__(self, config=None, db_con=None):
        """ Initialize common configuration and resources """
        self.db_con = db_con

        # initialise and retain config as empty dict if no rule config is given
        # to us so the rule can rely on it and does not need to do any type
        # checking
        self.config = {}
        if config is not None:
            self.config = config

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

    def evaluate(self, sample):
        """ Evaluate whether the sample is larger than a certain threshold.
        Advise the engine to stop processing if the size is below the
        threshold. """
        size = int(self.config.get('bytes', 5))

        if sample.file_size > size:
            return self.result(Result.unknown,
                               _("File has more than %d bytes") % size,
                               True)

        return self.result(
            Result.ignored,
            _("File is more than %d bytes long") % sample.file_size,
            False)


class FileTypeOnWhitelistRule(Rule):
    """ A rule checking whether the known file type(s) of the sample are on a
    whitelist. """
    rule_name = 'file_type_on_whitelist'

    def evaluate(self, sample):
        """ Ignore the file only if *all* of its mime types are on the
        whitelist and we could determine at least one. """
        whitelist = self.config.get('whitelist', ())
        if not whitelist:
            logger.warning("Empty whitelist, check ruleset config.")
            return self.result(Result.unknown, "Whitelist ist leer", True)

        if sample.mimetypes and sample.mimetypes.issubset(set(whitelist)):
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

    def evaluate(self, sample):
        """ Continue analysis if any of the sample's MIME types are on the
        greylist or in case we don't have one. """
        greylist = self.config.get('greylist', ())
        if not greylist:
            logger.warning("Empty greylist, check ruleset config.")
            return self.result(Result.unknown, "Greylist is leer", False)

        if not sample.mimetypes or sample.mimetypes.intersection(set(greylist)):
            return self.result(Result.unknown,
                               _("File type is on the list of types to "
                                 "analyze"),
                               True)

        return self.result(Result.unknown,
                           _("File type is not on the list of types to "
                             "analyse (%s)") % (str(sample.mimetypes)),
                           False)


class OfficeMacroRule(Rule):
    """ A rule checking the sample for Office macros. """
    rule_name = 'office_macro'

    def evaluate(self, sample):
        """ Report the sample as bad if it contains a macro. """
        if sample.office_macros:
            return self.result(Result.bad,
                               _("The file contains an Office macro"),
                               False)

        return self.result(Result.unknown,
                           _("The file does not contain a recognizable "
                             "Office macro"),
                           True)


class CuckooRule(Rule):
    """ A common base class for rules that evaluate the Cuckoo report. """
    def evaluate(self, sample):
        """ If a report is present for the sample in question we call method
        evaluate_report() implemented by subclasses to evaluate it for
        findings. Otherwise we submit the sample to Cuckoo and raise
        CuckooReportPendingException to abort the current run of the ruleset
        until the report arrives. If submission to Cuckoo fails we will
        ourselves report the sample as failed.

        @param sample: The sample to evaluate.
        @raises CuckooReportPendingException: if the sample was submitted to
                                              Cuckoo
        @returns: RuleResult containing verdict.
        """
        report = sample.cuckoo_report
        if report is None:
            try:
                job_id = sample.submit_to_cuckoo()
            except CuckooAnalysisFailedException:
                return self.result(
                    Result.failed,
                    _("Behavioral analysis by Cuckoo has produced an error "
                      "and did not finish successfully"),
                    False)

            logger.info('Sample submitted to Cuckoo. Job ID: %s. '
                        'Sample: %s', job_id, sample)
            raise CuckooReportPendingException()

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

    def evaluate_report(self, report):
        """ Evaluate the sample against signatures that if matched mark a
        sample as bad. """
        # list all installed signatures
        # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
        bad_sigs = self.config.get('signature', ())
        if not bad_sigs:
            logger.warning("Empty bad signature list, check ruleset config.")
            return self.result(Result.unknown,
                               _("Empty list of malicious signatures"),
                               True)

        # look through matched signatures
        sigs = []
        for descr in report.signatures:
            logger.debug(descr['description'])
            sigs.append(descr['description'])

        # check if there is a "bad" signatures and return bad
        matched_bad_sigs = []
        for sig in bad_sigs:
            match = re.search(sig, str(sigs))
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

    def evaluate_report(self, report):
        """ Evaluate the score reported by Cuckoo against the threshold from
        the configuration and report sample as bad if above. """
        threshold = float(self.config.get('higher_than', 4.0))

        if report.score >= threshold:
            return self.result(Result.bad,
                               _("Cuckoo score >= %s: %s") %
                               (threshold, report.score),
                               False)

        return self.result(Result.unknown,
                           _("Cuckoo score < %s: %s") %
                           (threshold, report.score),
                           True)


class RequestsEvilDomainRule(CuckooRule):
    """ A rule checking the domains reported as requested by the sample by
    Cuckoo against a blacklist. """
    rule_name = 'requests_evil_domain'

    def evaluate_report(self, report):
        """ Report the sample as bad if one of the requested domains is on our
        list of evil domains. """
        evil_domains = self.config.get('domain', ())
        if not evil_domains:
            logger.warning("Empty evil domain list, check ruleset config.")
            return self.result(Result.unknown, _("Empty domain list"), True)

        for domain in report.requested_domains:
            if domain in evil_domains:
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

    def evaluate_report(self, report):
        """ Report the sample as bad if the Cuckoo indicates that the analysis
        has failed. """
        if report.errors:
            logger.warning('Cuckoo produced %d error(s) during processing.',
                           len(report.errors))

        for entry in report.cuckoo_server_messages:
            if 'analysis completed successfully' in entry:
                return self.result(Result.unknown,
                                   _("Behavioral analysis by Cuckoo "
                                     "completed successfully"),
                                   True)

        return self.result(Result.failed,
                           _("Behavioral analysis by Cuckoo has produced "
                             "an error and did not finish successfully"),
                           False)


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
