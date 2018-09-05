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
import requests
import random
from twisted.internet import protocol, reactor
from time import sleep
from peekaboo import MultiRegexMatcher
from peekaboo.config import get_config
from peekaboo.exceptions import CuckooAnalysisFailedException


logger = logging.getLogger(__name__)


class Cuckoo:
    """
        Parent class, defines interface to Cuckoo
    """
    def __init__(self, job_queue, connection_map):
        self.job_queue = job_queue
        self.connection_map = connection_map

    def submit(self):
        logger.error("Not implemented yet")

    def resubmit_with_report(self, job_id):
        logger.debug("Analysis done for task #%d" % job_id)
        logger.debug("Remaining connections: %d" % self.connection_map.size())
        sample = self.connection_map.get_sample_by_job_id(job_id)
        if sample:
            logger.debug('Requesting Cuckoo report for sample %s' % sample)
            report = CuckooReport(job_id)
            sample.set_attr('cuckoo_report', report)
            if report.file_path:
                sample.set_attr('cuckoo_json_report_file', report.file_path)
            self.job_queue.submit(sample, self.__class__)
            logger.debug("Remaining connections: %d" % self.connection_map.size())
        else:
            logger.debug('No connection found for ID %d' % job_id)

    def do(self):
        # wait for the cows to come home
        while True:
            sleep(600)


class CuckooEmbed(Cuckoo):
    """
        Runs and interfaces with Cuckoo in IPC
        
        @author: Sebastian Deiss
        @author: Felix Bauer
    """
    def __init__(self, job_queue, connection_map, interpreter,
            cuckoo_exec):
        Cuckoo.__init__(self, job_queue, connection_map)
        self.interpreter = interpreter
        self.cuckoo_exec = cuckoo_exec
    
    def submit(self, sample):
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

    def do(self):
        # reaktor and shit
        # Run Cuckoo sandbox, parse log output, and report back of Peekaboo.
        srv = CuckooServer(self)
        reactor.spawnProcess(srv, self.interpreter, [self.interpreter, '-u',
                                                     self.cuckoo_exec])
        reactor.run()


class CuckooApi(Cuckoo):
    """
        Interfaces with a Cuckoo installation via its REST API
        
        @author: Felix Bauer
    """
    def __init__(self, job_queue, connection_map,
            url="http://localhost:8090"):
        Cuckoo.__init__(self, job_queue, connection_map)
        self.url = url
        self.reported = self.__status()["tasks"]["reported"]
        logger.info("Connection to Cuckoo seems to work, %i reported tasks seen", self.reported)
    
    def __get(self, url, method="get", files=""):
        r = ""
        logger.debug("Requesting %s, method %s" % (url, method))
        
        # try 3 times to get a successfull response
        for retry in range(0, 3):
            try:
                if method == "get":
                    r = requests.get("%s/%s" % (self.url, url))
                elif method == "post":
                    r = requests.post("%s/%s" % (self.url, url), files=files)
                else:
                    break
                if r.status_code != 200:
                    continue
                else:
                    return r.json()
            except requests.exceptions.Timeout as e:
                # Maybe set up for a retry, or continue in a retry loop
                print(e)
                if e and retry >= 2:
                    raise e
            except requests.exceptions.TooManyRedirects as e:
                # Tell the user their URL was bad and try a different one
                print(e)
                if e and retry >= 2:
                    raise e
            except requests.exceptions.RequestException as e:
                # catastrophic error. bail.
                print(e)
                if e and retry >= 2:
                    raise e
        return None
    
    def __status(self):
        return self.__get("cuckoo/status")
    
    def submit(self, sample):
        filename = os.path.basename(sample)
        files = {"file": (filename, open(sample, 'rb'))}
        r = self.__get("tasks/create/file", method="post", files=files)
        
        task_id = r["task_id"]
        if task_id > 0:
            return task_id
        raise CuckooAnalysisFailedException(
                                            'Unable to extract job ID from given string %s' % response
                                            )

    def getReport(self, job_id):
        return self.__get("tasks/report/%d" % job_id)
    
    def do(self):
        # do the polling for finished jobs
        # record analysis count and call status over and over again
        # logger ......
        
        limit = 1000000
        offset = self.__status()["tasks"]["total"]
        config = get_config()
        
        while True:
            cuckoo_tasks_list = None
            try:
                cuckoo_tasks_list = self.__get("tasks/list/%i/%i" % (limit, offset))
            except Exception as e:
                logger.warn('Unable to communicate with Cuckoo API: %s' % e)
                pass

            #maxJobID = cuckoo_tasks_list[-1]["id"]
            
            first = True
            if cuckoo_tasks_list:
                for j in cuckoo_tasks_list["tasks"]:
                    if j["status"] == "reported":
                        job_id = j["id"]
                        self.resubmit_with_report(job_id)
            #self.reported = reported
            sleep(float(config.cuckoo_poll_interval))


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
    def __init__(self, cuckoo):
        self.cuckoo = cuckoo

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
            self.cuckoo.resubmit_with_report(job_id)

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
    @author: Felix Bauer
    """
    def __init__(self, job_id, cuckoo="embed", cuckoo_report=None):
        """
        arg. cuckoo is either "embed" or a cuckoo object to use the api
        """
        self.job_id = job_id
        self.cuckoo = cuckoo
        self.file_path = None
        self.report = None
        self.cuckoo_report = cuckoo_report
        self._parse()

    def _parse(self):
        """
        Reads the JSON report from Cuckoo and loads it into the Sample object.
        """
        config = get_config()
        if self.cuckoo == "embed":
            if not self.cuckoo_report:
                self.cuckoo_report = os.path.join(
                                                  config.cuckoo_storage, 'analyses/%d/reports/report.json'
                                                  % self.job_id
                                                  )

            if not os.path.isfile(self.cuckoo_report):
                raise OSError('Cuckoo report not found at %s.' % self.cuckoo_report)
            else:
                logger.debug(
                    'Accessing Cuckoo report for task %d at %s '
                    % (self.job_id, self.cuckoo_report)
                )
                self.file_path = self.cuckoo_report
                with open(self.cuckoo_report) as data:
                    try:
                        report = json.load(data)
                        self.report = report
                    except ValueError as e:
                        logger.exception(e)
        elif isinstance(self.cuckoo, CuckooApi):
            logger.debug("Report from Cuckoo API requested, job_id = %d" % self.job_id)
            report = self.cuckoo.getReport(self.job_id)
            self.report = report
        else:
            raise ValueError("Invalid report source given in config")


    @property
    def requested_domains(self):
        """
        Gets the requested domains from the Cuckoo report.

        :return: The requested domains from the Cuckoo report.
        """
        try:
            return [d['request'] for d in self.report['network']['dns']]
        except KeyError:
            return []

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
            return []

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
            return 0.0

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
            return []

    @property
    def analysis_failed(self):
        """
        Has the Cuckoo analysis failed?

        :return: True if the Cuckoo analysis failed, otherwise False.
        """
        if self.errors:
            logger.warning('Cuckoo produced %d error(s) during processing.' % len(self.errors))
        try:
            log = self.report['debug']['cuckoo']
            for entry in log:
                if 'analysis completed successfully' in entry:
                    return False
            return True
        except KeyError:
            return True
