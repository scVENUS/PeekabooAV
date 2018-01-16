###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# ruleset/                                                                    #
#         engine.py                                                           #
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


import os
import logging
from shutil import copyfile
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.rules import *
from peekaboo.exceptions import CuckooReportPendingException
from peekaboo.toolbox.plugins.oneanalysis import OneAnalysis
from peekaboo.toolbox.peekabooyar import contains_peekabooyar

'''
# this module contains methods and data structures which allow to
# create a ruleset to decide good or bad for any given file
#
# works together with peekaboo
# and uses cuckoo
'''


logger = logging.getLogger(__name__)


def run_analysis(sample):
    """
    function that is run by a worker for every Sample object.
    """
    process_rules(sample)
    logger.info("Rules evaluated")
    report(sample)
    one_analysis_tool = OneAnalysis()
    one_analysis_tool.queue_identical_samples(sample)  # depends on already_in_progress


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
    except CuckooReportPendingException as e:
        # in case this our Sample is requesting the Cuckoo report
        raise
    # catch all exceptions in rule
    except Exception as e:
        logger.warning("Unexpected error in '%s' for %s" % (function_name,
                                                            sample))
        logger.exception(e)
        # create "fake" RuleResult
        res = RuleResult("rule_wrapper", result=Result.unknown,
                         reason="Regel mit Fehler abgebrochen",
                         further_analysis=True)
        sample.add_rule_result(res)

    logger.info("Rule '%s' processed for %s" % (function_name, sample))
    return res


def process_rules(sample):
    s = sample
#                      ____   _   _  _      _____  ____
#                     |  _ \ | | | || |    | ____|/ ___|
#                     | |_) || | | || |    |  _|  \___ \
#                     |  _ < | |_| || |___ | |___  ___) |
#                     |_| \_\ \___/ |_____||_____||____/

# TODO (cuckooWrapper needs to check if there is other samples in pjobs with
# the same hash)
    one_analysis_tool = OneAnalysis()
    p = rule(s, one_analysis_tool.already_in_progress)
    if not p.further_analysis:
        return

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

    p = rule(s, contains_peekabooyar)
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

    p = rule(s, cuckoo_score, {"higher": 4.0})
    if not p.further_analysis:
        return

    p = rule(s, cuckoo_analysis_failed)
    if not p.further_analysis:
        return

    p = rule(s, final_rule)
    if not p.further_analysis:
        return

    # active rules, non reporting
#    report(sample)

#                   __ ____   _   _  _      _____  ____
#                  / /|  _ \ | | | || |    | ____|/ ___|
#                 / / | |_) || | | || |    |  _|  \___ \
#                / /  |  _ < | |_| || |___ | |___  ___) |
#               /_/   |_| \_\ \___/ |_____||_____||____/
    return None


def report(s):
    # TODO: might be better to do this for each rule individually
    s.report()
    if s.get_result() == Result.bad:
        dump_processing_info(s)
    s.save_result()


def dump_processing_info(sample):
    """
    Saves the Cuckoo report as HTML + JSON and the meta info file (if available)
    to a directory named after the job hash.
    """
    job_hash = sample.get_job_hash()
    dump_dir = os.path.join(os.environ['HOME'], 'malware_reports', job_hash)
    if not os.path.isdir(dump_dir):
        os.makedirs(dump_dir, 0770)
    filename = sample.get_filename() + '-' + sample.sha256sum

    logger.debug('Dumping processing info to %s for sample %s' % (dump_dir, sample))

    # meta info file
    if sample.has_attr('meta_info_file'):
        try:
            copyfile(sample.get_attr('meta_info_file'),
                     os.path.join(dump_dir, filename + '.info'))
        except Exception as e:
            logger.exception(e)

    # Peekaboo's report
    try:
        with open(os.path.join(dump_dir, filename + '_report.txt'), 'w+') as f:
            f.write(sample.get_peekaboo_report())
    except Exception as e:
        logger.exception(e)

    if sample.has_attr('cuckoo_json_report_file'):
        # Cuckoo report
        try:
            # JSON
            copyfile(sample.get_attr('cuckoo_json_report_file'),
                     os.path.join(dump_dir, filename + '.json'))
        except Exception as e:
            logger.exception(e)
        try:
            # HTML
            copyfile(sample.get_attr('cuckoo_json_report_file').replace('json', 'html'),
                     os.path.join(dump_dir, filename + '.html'))
        except Exception as e:
            logger.exception(e)
