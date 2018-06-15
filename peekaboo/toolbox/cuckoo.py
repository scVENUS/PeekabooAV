###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cuckoo.py                                                           #
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
import os
import logging
import json
import subprocess
from twisted.internet import protocol
from peekaboo import MultiRegexMatcher
from peekaboo.config import get_config
from peekaboo.exceptions import CuckooAnalysisFailedException
from peekaboo.toolbox.sampletools import ConnectionMap
from peekaboo.queuing import JobQueue


logger = logging.getLogger(__name__)


def submit_to_cuckoo(sample):
    """
    Submit a file or directory to Cuckoo for behavioural analysis.

    :param sample: Path to a file or a directory.
    :return: The job ID used by Cuckoo to identify this analysis task.
    """
    config = get_config()
    try:
        proc = config.cuckoo_submit
        proc.append(sample)
        p = subprocess.Popen(proc,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.wait()
    except Exception as e:
        raise CuckooAnalysisFailedException(e)

    if not p.returncode == 0:
        # TODO: tell opponent on socket that file has not been checked.
        raise CuckooAnalysisFailedException('cuckoo submit returned a non-zero return code.')
    else:
        out, err = p.communicate()
        logger.debug("cuckoo submit STDOUT: %s" % out)
        logger.debug("cuckoo submit STDERR: %s" % err)
        # process output to get job ID
        patterns = list()
        # Example: Success: File "/var/lib/peekaboo/.bashrc" added as task with ID #4
        patterns.append(".*Success.*: File .* added as task with ID #([0-9]*).*")
        patterns.append(".*added as task with ID ([0-9]*).*")
        matcher = MultiRegexMatcher(patterns)
        response = out.replace("\n", "")
        m = matcher.match(response)
        logger.debug('Pattern %d matched.' % matcher.matched_pattern)

        if m:
            job_id = int(m.group(1))
            return job_id
        raise CuckooAnalysisFailedException(
            'Unable to extract job ID from given string %s' % response
        )


class CuckooServer(protocol.ProcessProtocol):
    """
    Class that is used by twisted.internet.reactor to process Cuckoo
    output and process its behavior.

    Usage:
    srv = CuckooServer()
    reactor.spawnProcess(srv, 'python2', ['python2', '/path/to/cukoo.py'])
    reactor.run()

    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    def __init__(self):
        self.__report = None

    def connectionMade(self):
        logger.info('Connected. Cuckoo PID: %s' % self.transport.pid)
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
            logger.info("File submitted: task #%s, filename %s" % (m.group(2),
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
            logger.debug("Analysis done for task #%d" % job_id)
            logger.debug("Remaining connections: %d" % ConnectionMap.size())
            sample = ConnectionMap.get_sample_by_job_id(job_id)
            if sample:
                logger.debug('Requesting Cuckoo report for sample %s' % sample)
                self.__report = CuckooReport(job_id)
                sample.set_attr('cuckoo_report', self.__report)
                sample.set_attr('cuckoo_json_report_file', self.__report.file_path)
                JobQueue.submit(sample, self.__class__)
                logger.debug("Remaining connections: %d" % ConnectionMap.size())
            else:
                logger.debug('No connection found for ID %d' % job_id)

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
        logger.info("Cuckoo exited with status %s" % str(reason.value.exitCode))
        os._exit(0)

    def processEnded(self, reason):
        logger.info("Cuckoo ended with status %s" % str(reason.value.exitCode))
        os._exit(0)


class CuckooReport(object):
    """
    Represents a Cuckoo analysis JSON report.

    @author: Sebastian Deiss
    """
    def __init__(self, job_id):
        self.job_id = job_id
        self.file_path = None
        self.report = None
        self._parse()

    def _parse(self):
        """
        Reads the JSON report from Cuckoo and loads it into the Sample object.
        """
        config = get_config()
        cuckoo_report = os.path.join(
            config.cuckoo_storage, 'analyses/%d/reports/report.json'
                                   % self.job_id
        )

        if not os.path.isfile(cuckoo_report):
            raise OSError('Cuckoo report not found at %s.' % cuckoo_report)
        else:
            logger.debug(
                'Accessing Cuckoo report for task %d at %s '
                % (self.job_id, cuckoo_report)
            )
            self.file_path = cuckoo_report
            with open(cuckoo_report) as data:
                try:
                    report = json.load(data)
                    self.report = report
                except ValueError as e:
                    logger.exception(e)

    @property
    def requested_domains(self):
        """
        Gets the requested domains from the Cuckoo report.

        :return: The requested domains from the Cuckoo report.
        """
        try:
            return [d['request'] for d in self.report['network']['dns']]
        except KeyError:
            return None

    @property
    def signatures(self):
        """
        Gets the triggered signatures from the Cuckoo report.

        :return: The triggered signatures from the Cuckoo report or
                 None of there was an error parsing the Cuckoo report.
        """
        try:
            return self.report['signatures']
        except KeyError:
            return None

    @property
    def score(self):
        """
        Gets the score from the Cuckoo report.

        :return: The score from the Cuckoo report or
                 None of there was an error parsing the Cuckoo report.
        """
        try:
            return self.report['info']['score']
        except KeyError:
            return None

    @property
    def errors(self):
        """
        Errors occurred during Cuckoo analysis.

        :return: The errors occurred during Cuckoo analysis or
                 None of there was an error parsing the Cuckoo report.
        """
        try:
            return self.report['debug']['errors']
        except KeyError:
            return None

    @property
    def analysis_failed(self):
        """
        Has the Cuckoo analysis failed?

        :return: True if the Cuckoo analysis failed, otherwise False.
        """
        if self.errors:
            logger.warning('Cuckoo run_analysis failed. Reason: %s' % str(self.errors))
            return True
        return False
