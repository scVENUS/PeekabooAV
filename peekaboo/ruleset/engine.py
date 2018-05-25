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
from peekaboo.config import PeekabooRulesetConfiguration, get_config
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.rules import *
from peekaboo.toolbox.peekabooyar import contains_peekabooyar
from peekaboo.exceptions import CuckooReportPendingException
from peekaboo.toolbox.plugins.oneanalysis import OneAnalysis


logger = logging.getLogger(__name__)


class RulesetEngine(object):
    """
    Peekaboo's ruleset engine.

    @author: Sebastian Deiss
    @since: 1.6
    """
    rules = [
        known,
        file_larger_than,
        file_type_on_whitelist,
        file_type_on_greylist,
        cuckoo_evil_sig,
        cuckoo_score,
        office_macro,
        requests_evil_domain,
        cuckoo_analysis_failed,
        contains_peekabooyar,
        final_rule
    ]

    def __init__(self, sample):
        peekaboo_config = get_config()
        ruleset_config = PeekabooRulesetConfiguration(peekaboo_config.ruleset_config)
        ruleset_config.parse()
        self.sample = sample
        self.config = ruleset_config.get_config()
        self.one_analysis_tool = OneAnalysis()

    def run(self):
        # TODO: Integrate this special rule in the base ruleset.
        result = self.__exec_rule(
            self.config,
            self.sample,
            self.one_analysis_tool.already_in_progress
        )
        if not result.further_analysis:
            return

        for rule in RulesetEngine.rules:
            result = self.__exec_rule(self.config, self.sample, rule)
            if not result.further_analysis:
                return

        logger.info("Rules evaluated")

    def report(self):
        # TODO: might be better to do this for each rule individually
        self.sample.report()
        if self.sample.get_result() == Result.bad:
            dump_processing_info(self.sample)
        self.sample.save_result()
        # TODO: might be better to move this call to a separate function, since it's not related to reporting.
        self.one_analysis_tool.queue_identical_samples(self.sample)  # depends on already_in_progress

    def __exec_rule(self, config, sample, rule_function):
        """
        rule wrapper for in/out logging and reporting
        """
        rule_name = rule_function.func_name
        logger.debug("Processing rule '%s' for %s" % (rule_name, sample))

        try:
            # skip disabled rules.
            if rule_name in config.keys() and \
               'enabled' in config[rule_name].keys() and \
               config[rule_name]['enabled'] == 'no':
                logger.debug("Rule '%s' is disabled." % rule_name)
                result = RuleResult(rule_name, result=Result.unchecked,
                                    reason="Regel '%s' ist deaktiviert." % rule_name,
                                    further_analysis=True)
            else:
                result = rule_function(config, sample)
            sample.add_rule_result(result)
        except CuckooReportPendingException as e:
            # in case the Sample is requesting the Cuckoo report
            raise
        # catch all other exceptions for this rule
        except Exception as e:
            logger.warning("Unexpected error in '%s' for %s" % (rule_name,
                                                                sample))
            logger.exception(e)
            # create "fake" RuleResult
            result = RuleResult("RulesetEngine", result=Result.unknown,
                                reason="Regel mit Fehler abgebrochen",
                                further_analysis=True)
            sample.add_rule_result(result)

        logger.info("Rule '%s' processed for %s" % (rule_name, sample))
        return result


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
