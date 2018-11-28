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


import traceback
import re
import logging
from peekaboo.ruleset import Result, RuleResult


logger = logging.getLogger(__name__)


def known(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    if s.known_to_db:
        sample_info = s.info_from_db
        return RuleResult(position,
                          result=sample_info.get_result(),
                          reason=sample_info.reason,
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei ist dem System noch nicht bekannt",
                      further_analysis=True)


def file_larger_than(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    size = int(config.get('bytes', 5))

    if s.file_size > size:
        return RuleResult(position,
                          result=Result.unknown,
                          reason="Datei hat mehr als %d bytes"
                          % size,
                          further_analysis=True)

    return RuleResult(position,
                      result=Result.ignored,
                      reason="Datei ist nur %d bytes lang"
                      % s.file_size,
                      further_analysis=False)


def file_type_on_whitelist(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    whitelist = config.get('whitelist', ())
    if len(whitelist) == 0:
        logger.warn("Empty whitelist, check ruleset config.")

    # ignore the file only if *all* of its mime types are on the whitelist and we could
    # determin at least one
    if len(s.mimetypes) > 0 and s.mimetypes.issubset(set(whitelist)):
        return RuleResult(position,
                          result=Result.ignored,
                          reason="Dateityp ist auf Whitelist",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Dateityp ist nicht auf Whitelist",
                      further_analysis=True)


def file_type_on_greylist(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    greylist = config.get('greylist', ())
    if len(greylist) == 0:
        logger.warn("Empty greylist, check ruleset config.")

    # continue analysis if any of the sample's mime types are on the greylist or in case
    # we don't have one
    if len(s.mimetypes.intersection(set(greylist))) > 0 or len(s.mimetypes) == 0:
        return RuleResult(position,
                          result=Result.unknown,
                          reason="Dateityp ist auf der Liste der zu analysiserenden Typen",
                          further_analysis=True)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Dateityp ist nicht auf der Liste der zu analysierenden Typen (%s)"
                      % (str(s.mimetypes)),
                      further_analysis=False)


def cuckoo_evil_sig(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    # signatures that if matched mark a sample as bad
    # list all installed signatures
    # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
    bad_sigs = config.get('signature', ())
    if len(bad_sigs) == 0:
        logger.warn("Empty bad signature list, check ruleset config.")

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
        return RuleResult(position,
                          result=Result.unknown,
                          reason="Keine Signatur erkannt die auf Schadcode hindeutet",
                          further_analysis=True)

    return RuleResult(position,
                      result=Result.bad,
                      reason="Folgende Signaturen wurden erkannt: %s"
                      % ''.ljust(8).join(["%s\n" % s for s in matched_bad_sigs]),
                      further_analysis=False)


def cuckoo_score(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    threshold = float(config.get('higher_than', 4.0))

    if s.cuckoo_report.score >= threshold:
        return RuleResult(position,
                          result=Result.bad,
                          reason="Cuckoo score >= %s: %s"
                          % (threshold, s.cuckoo_report.score),
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Cuckoo score < %s: %s"
                      % (threshold, s.cuckoo_report.score),
                      further_analysis=True)


def office_macro(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    if s.office_macros:
        return RuleResult(position,
                          result=Result.bad,
                          reason="Die Datei beinhaltet ein Office-Makro",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Die Datei beinhaltet kein erkennbares Office-Makro",
                      further_analysis=True)


def requests_evil_domain(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    evil_domains = config.get('domain', ())
    if len(evil_domains) == 0:
        logger.warn("Empty evil domain list, check ruleset config.")

    for d in s.cuckoo_report.requested_domains:
        if d in evil_domains:
            return RuleResult(position,
                              result=Result.bad,
                              reason="Die Datei versucht mindestens eine Domain aus der Blacklist zu kontaktieren (%s)" % d,
                              further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei scheint keine Domains aus der Blacklist kontaktieren zu wollen",
                      further_analysis=True)


def cuckoo_analysis_failed(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    if s.cuckoo_report.analysis_failed:
        return RuleResult(position,
                          result=Result.bad,
                          reason="Die Verhaltensanalyse durch Cuckoo hat einen Fehler Produziert und konnte nicht erfolgreich abgeschlossen werden",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Die Verhaltensanalyse durch Cuckoo wurde erfolgreich abgeschlossen",
                      further_analysis=True)


def final_rule(config, s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei scheint keine erkennbaren Schadroutinen zu starten",
                      further_analysis=True)
