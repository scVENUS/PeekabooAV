###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         rules.py                                                            #
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

""" Classes implementing the Ruleset """


import re
import logging
from peekaboo.ruleset import Result, RuleResult


logger = logging.getLogger(__name__)


class Rule(object):
    """ This is the base class for all rules. It provides common infrastructure
    such as resources that can be used by the rules (configuration, database
    connection) or helper functions. """
    def __init__(self, config=None, db_con=None):
        """ Initialize common configuration and resources """
        self.config = config
        self.db_con = db_con

    def result(self, result, reason, further_analysis):
        """ Construct a RuleResult for returning to the engine. """
        return RuleResult(self.rule_name, result=result, reason=reason,
                          further_analysis=further_analysis)

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
                           "Datei ist dem System noch nicht bekannt",
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
                               "Datei hat mehr als %d bytes" % size,
                               True)

        return self.result(Result.ignored,
                           "Datei ist nur %d bytes lang" % sample.file_size,
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
            logger.warn("Empty whitelist, check ruleset config.")
            return self.result(Result.unknown, "Whitelist ist leer", True)

        if sample.mimetypes and sample.mimetypes.issubset(set(whitelist)):
            return self.result(Result.ignored,
                               "Dateityp ist auf Whitelist",
                               False)

        return self.result(Result.unknown,
                           "Dateityp ist nicht auf Whitelist",
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
            logger.warn("Empty greylist, check ruleset config.")
            return self.result(Result.unknown, "Greylist is leer", False)

        if not sample.mimetypes or sample.mimetypes.intersection(set(greylist)):
            return self.result(Result.unknown,
                               "Dateityp ist auf der Liste der zu "
                               "analysiserenden Typen",
                               True)

        return self.result(Result.unknown,
                           "Dateityp ist nicht auf der Liste der zu "
                           "analysierenden Typen (%s)" %
                           (str(sample.mimetypes)),
                           False)


class CuckooEvilSigRule(Rule):
    """ A rule evaluating the signatures from the Cuckoo report against a list
    of signatures considered bad. """
    rule_name = 'cuckoo_evil_sig'

    def evaluate(self, sample):
        """ Evaluate the sample against signatures that if matched mark a
        sample as bad. """
        # list all installed signatures
        # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
        bad_sigs = self.config.get('signature', ())
        if not bad_sigs:
            logger.warn("Empty bad signature list, check ruleset config.")
            return self.result(Result.unknown,
                               "Leere Liste schaedlicher Signaturen",
                               True)

        sigs = []

        # look through matched signatures
        for descr in sample.cuckoo_report.signatures:
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
                               "Keine Signatur erkannt die auf Schadcode "
                               "hindeutet",
                               True)

        matched = ''.ljust(8).join(["%s\n" % s for s in matched_bad_sigs])
        return self.result(Result.bad,
                           "Folgende Signaturen wurden erkannt: %s" % matched,
                           False)


class CuckooScoreRule(Rule):
    """ A rule checking the score reported by Cuckoo against a configurable
    threshold. """
    rule_name = 'cuckoo_score'

    def evaluate(self, sample):
        """ Evaluate the score reported by Cuckoo against the threshold from
        the configuration and report sample as bad if above. """
        threshold = float(self.config.get('higher_than', 4.0))

        if sample.cuckoo_report.score >= threshold:
            return self.result(Result.bad,
                               "Cuckoo score >= %s: %s" %
                               (threshold, sample.cuckoo_report.score),
                               False)

        return self.result(Result.unknown,
                           "Cuckoo score < %s: %s" %
                           (threshold, sample.cuckoo_report.score),
                           True)


class OfficeMacroRule(Rule):
    """ A rule checking the sample for Office macros. """
    rule_name = 'office_macro'

    def evaluate(self, sample):
        """ Report the sample as bad if it contains a macro. """
        if sample.office_macros:
            return self.result(Result.bad,
                               "Die Datei beinhaltet ein Office-Makro",
                               False)

        return self.result(Result.unknown,
                           "Die Datei beinhaltet kein erkennbares "
                           "Office-Makro",
                           True)


class RequestsEvilDomainRule(Rule):
    """ A rule checking the domains reported as requested by the sample by
    Cuckoo against a blacklist. """
    rule_name = 'requests_evil_domain'

    def evaluate(self, sample):
        """ Report the sample as bad if one of the requested domains is on our
        list of evil domains. """
        evil_domains = self.config.get('domain', ())
        if not evil_domains:
            logger.warn("Empty evil domain list, check ruleset config.")
            return self.result(Result.unknown, "Leere Domainliste", True)

        for domain in sample.cuckoo_report.requested_domains:
            if domain in evil_domains:
                return self.result(Result.bad,
                                   "Die Datei versucht mindestens eine Domain "
                                   "aus der Blacklist zu kontaktieren "
                                   "(%s)" % domain,
                                   False)

        return self.result(Result.unknown,
                           "Datei scheint keine Domains aus der Blacklist "
                           "kontaktieren zu wollen",
                           True)


class CuckooAnalysisFailedRule(Rule):
    """ A rule checking the final status reported by Cuckoo for success. """
    rule_name = 'cuckoo_analysis_failed'

    def evaluate(self, sample):
        """ Report the sample as bad if the Cuckoo indicates that the analysis
        has failed. """
        if sample.cuckoo_report.analysis_failed:
            return self.result(Result.bad,
                               "Die Verhaltensanalyse durch Cuckoo hat einen "
                               "Fehler produziert und konnte nicht erfolgreich "
                               "abgeschlossen werden",
                               False)

        return self.result(Result.unknown,
                           "Die Verhaltensanalyse durch Cuckoo wurde "
                           "erfolgreich abgeschlossen",
                           True)


class FinalRule(Rule):
    """ A catch-all rule. """
    rule_name = 'final_rule'

    def evaluate(self, sample):
        """ Report an unknown analysis result indicating that nothing much can
        be said about the sample. """
        return self.result(Result.unknown,
                           "Datei scheint keine erkennbaren Schadroutinen "
                           "zu starten",
                           True)
