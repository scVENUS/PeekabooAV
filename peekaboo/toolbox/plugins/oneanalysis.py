###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         plugins/                                                            #
#                 oneanalysis.py                                              #
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


import threading
import traceback
import sys
import logging
import peekaboo.queuing
from peekaboo.ruleset import RuleResult
from peekaboo.exceptions import CuckooReportPendingException
from peekaboo.toolbox.sampletools import ConnectionMap


logger = logging.getLogger(__name__)


def singleton(class_):
    instances = {}

    def getinstance(*args, **kwargs):
        if class_ not in instances:
            instances[class_] = class_(*args, **kwargs)
        return instances[class_]
    return getinstance


@singleton
class OneAnalysis(object):
    """
    @author: Felix Bauer
    """
    __in_use = threading.Lock()
    
    def already_in_progress(self, config, s):
        with self.__in_use:
            logger.debug("enter already_in_progress")
            tb = traceback.extract_stack()
            tb = tb[-1]
            position = "%s:%s" % (tb[2], tb[1])

            if s.has_attr('pending'):
                s.set_attr('pending', False)
                return RuleResult(position,
                                  result=s.get_result(),
                                  reason='Datei wird jetzt Analysiert',
                                  further_analysis=True)

            l = []
            for sample in ConnectionMap.get_samples_by_sha256(s.sha256sum):
                if sample != s:
                    if not sample.has_attr('pending') or not sample.get_attr('pending') is True:
                        l.append(sample)

            if len(l) == 0:
                s.set_attr("pending", False)
                logger.debug("no second analysis present")
                return RuleResult(position,
                                  result=s.get_result(),
                                  reason='Datei wird jetzt Analysiert',
                                  further_analysis=True)

            logger.debug("there is another same sample")
            logger.debug("I'll be off until needed")
            s.set_attr("pending", True)
            # stop worker
            sys.stdout.flush()
            logger.debug("leave already_in_progress")
            raise CuckooReportPendingException()

    def queue_identical_samples(self, s):
        with self.__in_use:
            logger.debug("queueing identical samples")
            for sample in ConnectionMap.get_samples_by_sha256(s.sha256sum):
                pending = sample.get_attr('pending')
                if pending:
                    sample.set_attr('pending', False)
                    peekaboo.queuing.JobQueue.submit(sample, self.__class__)
