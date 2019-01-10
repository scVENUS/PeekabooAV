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


import re
import logging
from peekaboo.ruleset import Result, RuleResult


logger = logging.getLogger(__name__)


class Rule(object):
    def __init__(self, config):
        self.config = config

    def result(self, result, reason, further_analysis):
        return RuleResult(self.rule_name, result=result, reason=reason,
                          further_analysis=further_analysis)

class KnownRule(Rule):
    rule_name = 'known'

    def evaluate(self, s):
        sample_info = s.info_from_db
        if sample_info:
            return self.result(sample_info.result, sample_info.reason, False)

        return self.result(Result.unknown,
                           "Datei ist dem System noch nicht bekannt",
                           True)


class FileLargerThanRule(Rule):
    rule_name = 'file_larger_than'

    def evaluate(self, s):
        size = int(self.config.get('bytes', 5))

        if s.file_size > size:
            return self.result(Result.unknown,
                               "Datei hat mehr als %d bytes" % size,
                               True)

        return self.result(Result.ignored,
                           "Datei ist nur %d bytes lang" % s.file_size,
                           False)


class FileTypeOnWhitelistRule(Rule):
    rule_name = 'file_type_on_whitelist'

    def evaluate(self, s):
        whitelist = self.config.get('whitelist', ())
        if len(whitelist) == 0:
            logger.warn("Empty whitelist, check ruleset config.")
            return self.result(Result.unknown, "Whitelist ist leer", True)

        # ignore the file only if *all* of its mime types are on the whitelist
        # and we could determine at least one
        if len(s.mimetypes) > 0 and s.mimetypes.issubset(set(whitelist)):
            return self.result(Result.ignored,
                               "Dateityp ist auf Whitelist",
                               False)

        return self.result(Result.unknown,
                           "Dateityp ist nicht auf Whitelist",
                           True)


class FileTypeOnGreylistRule(Rule):
    rule_name = 'file_type_on_greylist'

    def evaluate(self, s):
        greylist = self.config.get('greylist', ())
        if len(greylist) == 0:
            logger.warn("Empty greylist, check ruleset config.")
            return self.result(Result.unknown, "Greylist is leer", False)

        # continue analysis if any of the sample's mime types are on the greylist or in case
        # we don't have one
        if len(s.mimetypes.intersection(set(greylist))) > 0 or len(s.mimetypes) == 0:
            return self.result(Result.unknown,
                               "Dateityp ist auf der Liste der zu "
                               "analysiserenden Typen",
                               True)

        return self.result(Result.unknown,
                           "Dateityp ist nicht auf der Liste der zu "
                           "analysierenden Typen (%s)" % (str(s.mimetypes)),
                           False)


class CuckooEvilSigRule(Rule):
    rule_name = 'cuckoo_evil_sig'

    def evaluate(self, s):
        # signatures that if matched mark a sample as bad
        # list all installed signatures
        # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
        bad_sigs = self.config.get('signature', ())
        if len(bad_sigs) == 0:
            logger.warn("Empty bad signature list, check ruleset config.")
            return self.result(Result.unknown,
                               "Leere Liste schaedlicher Signaturen",
                               True)

        sigs = []

        # look through matched signatures
        for descr in s.cuckoo_report.signatures:
            logger.debug(descr['description'])
            sigs.append(descr['description'])

        # check if there is a "bad" signatures and return bad
        matched_bad_sigs = []
        for sig in bad_sigs:
            match = re.search(sig, str(sigs))
            if match:
                matched_bad_sigs.append(sig)

        if len(matched_bad_sigs) == 0:
            return self.result(Result.unknown,
                               "Keine Signatur erkannt die auf Schadcode "
                               "hindeutet",
                               True)

        matched = ''.ljust(8).join(["%s\n" % s for s in matched_bad_sigs])
        return self.result(Result.bad,
                           "Folgende Signaturen wurden erkannt: %s" % matched,
                           False)


class CuckooScoreRule(Rule):
    rule_name = 'cuckoo_score'

    def evaluate(self, s):
        threshold = float(self.config.get('higher_than', 4.0))

        if s.cuckoo_report.score >= threshold:
            return self.result(Result.bad,
                               "Cuckoo score >= %s: %s" %
                               (threshold, s.cuckoo_report.score),
                               False)

        return self.result(Result.unknown,
                           "Cuckoo score < %s: %s" %
                           (threshold, s.cuckoo_report.score),
                           True)


class OfficeMacroRule(Rule):
    rule_name = 'office_macro'

    def evaluate(self, s):
        if s.office_macros:
            return self.result(Result.bad,
                               "Die Datei beinhaltet ein Office-Makro",
                               False)

        return self.result(Result.unknown,
                           "Die Datei beinhaltet kein erkennbares "
                           "Office-Makro",
                           True)


class RequestsEvilDomainRule(Rule):
    rule_name = 'requests_evil_domain'

    def evaluate(self, s):
        evil_domains = self.config.get('domain', ())
        if len(evil_domains) == 0:
            logger.warn("Empty evil domain list, check ruleset config.")
            return self.result(Result.unknown, "Leere Domainliste", True)

        for d in s.cuckoo_report.requested_domains:
            if d in evil_domains:
                return self.result(Result.bad,
                                   "Die Datei versucht mindestens eine Domain "
                                   "aus der Blacklist zu kontaktieren "
                                   "(%s)" % d,
                                   False)

        return self.result(Result.unknown,
                           "Datei scheint keine Domains aus der Blacklist "
                           "kontaktieren zu wollen",
                           True)


class CuckooAnalysisFailedRule(Rule):
    rule_name = 'cuckoo_analysis_failed'

    def evaluate(self, s):
        if s.cuckoo_report.analysis_failed:
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
    rule_name = 'final_rule'

    def evaluate(self, s):
        return self.result(Result.unknown,
                           "Datei scheint keine erkennbaren Schadroutinen "
                           "zu starten",
                           True)
