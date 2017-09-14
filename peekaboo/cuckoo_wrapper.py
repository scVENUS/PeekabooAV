###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# cuckoo_wrapper.py                                                           #
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


import re
import os
import logging
from twisted.internet import protocol
from peekaboo import MultiRegexMatcher
import peekaboo.pjobs as pjobs


logger = logging.getLogger(__name__)


class CuckooManager(protocol.ProcessProtocol):
    """
    Class that is used by twisted.internet.reactor to process Cuckoo
    output and process its behavior.

    Usage:
    mgr = CuckooManager()
    reactor.spawnProcess(mgr, 'python2', ['python2', '/path/to/cukoo.py'])
    reactor.run()

    @author: Felix Bauer
    """

    def connectionMade(self):
        logger.info('Connected. Cuckoo PID %s' % self.transport.pid)
        return None

    def outReceived(self, data):
        """ on receiving output on STDOUT from Cuckoo """
        logger.debug('STDOUT %s' % str(data))

    def errReceived(self, data):
        """ on receiving output on STDERR from Cuckoo """
        logger.debug('STDERR %s' % str(data.replace('\n', '')))

        #
        # FILE SUBMITTED
        # printed out but has no further effect
        #
        # 2016-04-12 09:14:06,984 [lib.cuckoo.core.scheduler] INFO: Starting
        # analysis of FILE "cuckoo.png" (task #201, options "")
        # INFO: Starting analysis of FILE ".bashrc" (task #4, options "")
        m = re.match('.*INFO: Starting analysis of FILE \"(.*)\" \(task #([0-9]*), options .*', data)

        if m:
            logger.info("file submitted: task #%s filename %s" % (m.group(2),
                                                                  m.group(1)))

        #
        # ANALYSIS DONE
        #
        # 2016-04-12 09:25:27,824 [lib.cuckoo.core.scheduler] INFO: Task #202:
        # reports generation completed ...
        m = re.match(".*INFO: Task #([0-9]*): reports generation completed.*",
                     data)
        if m:
            job_id = int(m.group(1))
            logger.info("Analysis done for task #%d" % job_id)

            logger.debug("Queued jobs %d" % pjobs.Jobs.length())
            sample = pjobs.Jobs.get_sample_by_job_id(job_id)
            if sample:
                logger.debug('Requesting Cuckoo report for sample %s' % sample)
                sample.parse_cuckoo_report()

                pjobs.Workers.submit_job(sample, self.__class__)
                logger.debug("Queued jobs %d" % pjobs.Jobs.length())
            else:
                logger.info('No job found for ID %d' % job_id)

    def inConnectionLost(self):
        logger.debug("Cuckoo closed STDIN")
        os._exit(1)

    def outConnectionLost(self):
        logger.debug("Cuckoo closed STDOUT")
        os._exit(1)

    def errConnectionLost(self):
        logger.warning("Cuckoo closed STDERR")
        os._exit(1)

    def processExited(self, reason):
        logger.info("Cuckoo exited status %d" % reason.value.exitCode)
        os._exit(0)

    def processEnded(self, reason):
        logger.info("Cuckoo ended status %d" % reason.value.exitCode)
        os._exit(0)
