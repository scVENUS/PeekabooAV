###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# processor.py                                                                  #
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


from peekaboo import logger
from peekaboo.ruleset import Result, RuleResult
from peekaboo.ruleset.rules import *
from peekaboo.exceptions import CuckooReportPendingException


'''
# this module contains methods and data structures which allow to
# create a ruleset to decide good or bad for any given file
#
# works together with peekaboo
# and uses cuckoo
'''


def evaluate(sample):
    """
    function that is run by a worker for every Sample object.
    """
    process_rules(sample)
    logger.debug("Rules evaluated")
    report(sample)


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
        # create "fake" RuleResult
        res = RuleResult("rule_wrapper", result=Result.unknown,
                         reason="Regel mit Fehler abgebrochen",
                         further_analysis=True)
        sample.add_rule_result(res)

    logger.debug("Rule '%s' processed for %s" % (function_name, sample))
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
    #p = rule(s, already_in_progress)
    #if not p.further_analysis:
    #    return

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

    # active rules, non reporting
#    report(sample)
#    queue_identical_samples(sample) # depends on already_in_progress

#                   __ ____   _   _  _      _____  ____
#                  / /|  _ \ | | | || |    | ____|/ ___|
#                 / / | |_) || | | || |    |  _|  \___ \
#                / /  |  _ < | |_| || |___ | |___  ___) |
#               /_/   |_| \_\ \___/ |_____||_____||____/
    return None


def report(s):
    # TODO: might be better to do this for each rule individually
    s.report()
    s.save_result()
