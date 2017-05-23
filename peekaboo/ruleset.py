###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset.py                                                                  #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2017  science + computing ag                             #
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


from __future__ import absolute_import
import traceback
import re
from enum import Enum, unique
from . import logger


'''
# this module contains methods and data structures which allow to
# create a ruleset to decide good or bad for any given file
#
# works together with peekaboo
# and uses cuckoo
'''


@unique
class Result(Enum):
    """
    @author: Felix Bauer
    """
    inProgress = 0
    unchecked = 1
    unknown = 2
    ignored = 3
    checked = 4
    good = 5
    bad = 6

    @staticmethod
    def from_string(result_str):
        for i in Result:
            if i.name == result_str:
                return i
        raise ValueError('%s: Element not found' % result_str)

    def __gt__(self, other):
        return self.value >= other.value

    def __lt__(self, other):
        return other.value >= self.value


class RuleResult:
    """
    @author: Felix Bauer
    """
    def __init__(self, rule,
                 result=Result.unknown,
                 reason='regel ohne Ergebnis',
                 further_analysis=True):
        self.rule = None
        self.result = Result.unchecked
        self.rule = rule
        self.result = result
        self.reason = reason
        self.further_analysis = further_analysis

    def __str__(self):
        return ("Ergebnis \"%s\" der Regel %s - %s, Analyse wird fortgesetzt: %s."\
                                                        % (self.result.name,
                                                           self.rule,
                                                           self.reason,
                                                           'Ja' if self.further_analysis else 'Nein'))

    __repr__ = __str__


def evaluate(sample):
    """
    function that is run by a worker for every Sample object.
    """
    evaluate_rules(sample)

    logger.debug("Rules evaluated")
    # TODO: might be better to do this for each rule individually
    sample.report()
    sample.save_result()


def rule(sample, rule_function, args={}):
    """
    rule wrapper for in/out logging and reporting
    """
    function_name = rule_function.func_name
    logger.debug("Processing rule '%s' for %s" % (function_name, sample))

    try:
        if args:
            res = rule_function(sample, args)
        else:
            res = rule_function(sample)

        sample.add_rule_result(res)
    # catch all exceptions in rule
    except Exception as e:
        # in case this our Sample is requesting the Cuckoo report
        if type(e) == ValueError and \
           e.args == ValueError('Cuckoo report not yet available. Sample '
                                'submitted for analysis').args:
            raise

        logger.info("Unexpected error in '%s' for %s" % (function_name,
                                                         sample))
        # create "fake" RuleResult
        res = RuleResult("rule_wrapper", result=Result.unknown,
                         reason="Regel mit Fehler abgebrochen",
                         further_analysis=True)
        sample.add_rule_result(res)
        raise

    logger.debug("Rule '%s' processed for %s" % (function_name, sample))
    return res


def evaluate_rules(sample):
    s = sample
#                      ____   _   _  _      _____  ____
#                     |  _ \ | | | || |    | ____|/ ___|
#                     | |_) || | | || |    |  _|  \___ \
#                     |  _ < | |_| || |___ | |___  ___) |
#                     |_| \_\ \___/ |_____||_____||____/

# TODO (cuckooWrapper needs to check if there is other samples in pjobs with
# the same hash)
#    p = rule(  already_inProgress                   ,s)
#    if not p.further_analysis:
#        raise Exception

    p = rule(s, known)
    if not p.further_analysis:
        return

    p = rule(s, file_larger_than, {"byte": 5})
    if not p.further_analysis:
        return

    p = rule(s, file_type_on_whitelist)
    if not p.further_analysis:
        return

    p = rule(s, file_type_on_greylist)
    if not p.further_analysis:
        return

    p = rule(s, office_macro)
    if not p.further_analysis:
        return

    p = rule(s, requests_evil_domain)
    if not p.further_analysis:
        return

    p = rule(s, cuckoo_evil_sig)
    if not p.further_analysis:
        return

    p = rule(s, cuckoo_analysis_failed)
    if not p.further_analysis:
        return

    p = rule(s, final_rule)
    if not p.further_analysis:
        return

#                   __ ____   _   _  _      _____  ____
#                  / /|  _ \ | | | || |    | ____|/ ___|
#                 / / | |_) || | | || |    |  _|  \___ \
#                / /  |  _ < | |_| || |___ | |___  ___) |
#               /_/   |_| \_\ \___/ |_____||_____||____/
    return None


def known(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    if s.known:
        return RuleResult(position,
                          result=s.get_result(),
                          reason=s.reason,
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei ist dem System noch nicht bekannt",
                      further_analysis=True)


def file_larger_than(s, args):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    size = args['byte']
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


def file_type_on_whitelist(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    # MIME file types that should not be analyzed
    whitelist = [
        # MIME types
        'text/plain',
        'text/html',
        'message/rfc822',
        'None',
        # magic
        'inode/x-empty',
        'text/plain',
        'application/pkcs7-signature',
    ]

    # analysis wanted for file type
    mtypes = s.mimetypes
    n = 0
    logger.debug("Filetype is %s" % mtypes)
    for mtype in mtypes:
        if mtype in whitelist:
            n = n + 1

    # TODO: Check if one hit on the whitelist is sufficient!
    if n != len(mtypes):
        logger.debug('Length of n: %s, Content of mtypes: %s' % (str(n),
                                                                 str(mtypes)))

    if n > 0:
        return RuleResult(position,
                          result=Result.ignored,
                          reason="Dateityp ist auf Whitelist",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Dateityp ist nicht auf Whitelist",
                      further_analysis=True)


def file_type_on_greylist(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    # MIME file types that should be analyzed
    greylist = [
        # magic
        'application/octet-stream',
        'application/vnd.ms-excel',
        'application/pdf',
        'application/javascript',
        'application/pdf',
        'application/vnd.ms-excel',
        'application/vnd.ms-excel.sheet.macroEnabled.12',
        'application/vnd.ms-word.document.macroEnabled.12',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/x-7z-compressed',
        'application/x-ms-dos-executable',
        'application/x-dosexec',
        'application/x-vbscript',
        'application/zip',
        'application/x-rar',
        'application/msword',
        # 'message/rfc822',
        # 'text/html',
        'text/x-msdos-batch',
        # MIME types
        'text/x-sh',
        'text/x-python',
        'image/png',
        'image/jpeg',
        'application/zip',
        'application/x-silverlight',
        'application/x-python-code',
        'application/x-msdos-program',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/vnd.oasis.opendocument.text',
        'application/vnd.oasis.opendocument.spreadsheet',
        'application/vnd.oasis.opendocument.presentation',
        'application/vnd.ms-word.template.macroEnabled.12',
        'application/vnd.ms-powerpoint',
        'application/vnd.ms-excel.template.macroEnabled.12',
        'application/vnd.ms-excel',
        'application/pdf',
        'application/msword'
    ]

    mtypes = s.mimetypes
    logger.debug("filetype is %s" % mtypes)

    for mtype in mtypes:
        if mtype in greylist:
            return RuleResult(position,
                              result=Result.unknown,
                              reason="Dateityp ist auf der Liste der zu analysiserenden Typen",
                              further_analysis=True)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Dateityp ist nicht auf der Liste der zu analysierenden Typen (%s)"
                      % (str(s.mimetypes)),
                      further_analysis=False)


def cuckoo_evil_sig(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    # signatures that if matched mark a sample as bad
    # list all installed signatures
    # grep -o "description.*" -R . ~/cuckoo2.0/modules/signatures/
    bad_sigs = [
        "A potential heapspray has been detected. .*",
        "A process attempted to delay the analysis task.",
        "Attempts to detect Cuckoo Sandbox through the presence of a file",
        "Attempts to modify desktop wallpaper",
        "Checks amount of memory in system, this can be used to detect " +
        "virtual machines that have a low amount of memory available",
        "Checks the version of Bios, possibly for anti-virtualization",
        "Collects information on the system (ipconfig, netstat, systeminfo)",
        "Connects to an IRC server, possibly part of a botnet",
        "Connects to Tor Hidden Services through Tor2Web",
        "Creates a suspicious process",
        "Creates a windows hook that monitors keyboard input (keylogger)",
        "Creates executable files on the filesystem",
        "Creates known Upatre files, registry keys and/or mutexes",
        # "Creates (office) documents on the filesystem",
        "Detects the presence of Wine emulator",
        "Detects VirtualBox through the presence of a file",
        "Detects VirtualBox through the presence of a registry key",
        "Detects VirtualBox through the presence of a window",
        "Detects VirtualBox using WNetGetProviderName trick",
        "Detects VMWare through the in instruction feature",
        "Detects VMWare through the presence of a registry key",
        "Detects VMWare through the presence of various files",
        "Executes javascript",
        "Executes one or more WMI queries",
        "File has been identified by .* AntiVirus engines on VirusTotal as " +
        "malicious",
        "Installs itself for autorun at Windows startup",
        "Looks for known filepaths where sandboxes execute samples",
        "Looks for the Windows Idle Time to determine the uptime",
        "Makes SMTP requests, possibly sending spam",
        "This sample modifies more than .* files through suspicious ways,",
        "Network communications indicative of a potential document or script" +
        " payload download was initiated by the process wscript.exe",
        "One of the processes launched crashes",
        "One or more of the buffers contains an embedded PE file",
        "One or more potentially interesting buffers were extracted, these " +
        "generally",
        "Potentially malicious URL found in document",
        "Queries for the computername",
        "Queries the disk size.*",
        "Raised Suricata alerts",
        "Starts servers listening on {0}",
        "Steals private information from local Internet browsers",
        "Suspicious Javascript actions",
        "Tries to detect analysis programs from within the browser",
        "Tries to locate whether any sniffers are installed",
        "Wscript.exe initiated network communications indicative of a script" +
        " based payload download",
    ]

    sigs = []
    data = s.cuckoo_report

    # look through matched signatures
    for descr in data['signatures']:
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


def office_macro(s):
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


def requests_evil_domain(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    evil_domains = ["canarytokens.com"]

    for d in s.requested_domains:
        if d in evil_domains:
            return RuleResult(position,
                              result=Result.bad,
                              reason="Die Datei versucht mindestens eine Domain aus der Blacklist zu kontaktieren (%s)" % d,
                              further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei scheint keine Domains aus der Blacklist kontaktieren zu wollen",
                      further_analysis=True)


def cuckoo_analysis_failed(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    if s.cuckoo_analysis_failed:
        return RuleResult(position,
                          result=Result.bad,
                          reason="Die Verhaltensanalyse durch Cuckoo hat einen Fehler Produziert und konnte nicht erfolgreich abgeschlossen werden",
                          further_analysis=False)

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Die Verhaltensanalyse durch Cuckoo wurde erfolgreich abgeschlossen",
                      further_analysis=True)


def final_rule(s):
    tb = traceback.extract_stack()
    tb = tb[-1]
    position = "%s:%s" % (tb[2], tb[1])

    return RuleResult(position,
                      result=Result.unknown,
                      reason="Datei scheint keine erkennbaren Schadroutinen zu starten",
                      further_analysis=True)
