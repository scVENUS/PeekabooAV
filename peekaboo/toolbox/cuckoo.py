###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cuckoo.py                                                           #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2019  science + computing ag                             #
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
import locale
import logging
import json
import subprocess
import requests
import random
from twisted.internet import protocol, reactor, process
from time import sleep
from peekaboo.exceptions import CuckooAnalysisFailedException


logger = logging.getLogger(__name__)


class Cuckoo:
    """ Parent class, defines interface to Cuckoo """
    def __init__(self, job_queue):
        self.job_queue = job_queue
        self.shutdown_requested = False
        self.running_jobs = {}

    def resubmit_with_report(self, job_id):
        logger.debug("Analysis done for task #%d" % job_id)

        # thread-safe, no locking required, revisit if splitting into
        # multiple operations
        sample = self.running_jobs.pop(job_id, None)
        if sample is None:
            logger.debug('No sample found for job ID %d', job_id)
            return None

        logger.debug('Requesting Cuckoo report for sample %s', sample)
        report = self.get_report(job_id)

        # do not register the report with the sample if we were unable to
        # get it because e.g. it was corrupted or the API connection
        # failed. This will cause the sample to be resubmitted to Cuckoo
        # upon the next try to access the report.
        # TODO: This can cause an endless loop.
        if report is not None:
            reportobj = CuckooReport(report)
            sample.register_cuckoo_report(reportobj)

        self.job_queue.submit(sample, self.__class__)

    def shut_down(self):
        self.shutdown_requested = True

    def reap_children(self):
        pass

    def get_report(self, job_id):
        """ Extract the report of a finished analysis from Cuckoo. To be
        overridden by derived classes for actual implementation. """
        raise NotImplementedError

class CuckooEmbed(Cuckoo):
    """ Runs and interfaces with Cuckoo in IPC
        
    @author: Sebastian Deiss
    @author: Felix Bauer
    """
    def __init__(self, job_queue, cuckoo_exec, cuckoo_submit,
                 cuckoo_storage, interpreter=None):
        Cuckoo.__init__(self, job_queue)
        self.interpreter = interpreter
        self.cuckoo_exec = cuckoo_exec
        self.cuckoo_submit = cuckoo_submit
        self.cuckoo_storage = cuckoo_storage
        self.exit_code = 0

        # process output to get job ID
        patterns = (
            # Example: Success: File "/var/lib/peekaboo/.bashrc" added as task with ID #4
            "Success.*: File .* added as task with ID #([0-9]*)",
            "added as task with ID ([0-9]*)",
        )
        self.job_id_patterns = [re.compile(pattern) for pattern in patterns]
    
    def submit(self, sample):
        """
        Submit a file or directory to Cuckoo for behavioural analysis.
            
        @param sample: Sample object to analyse.
        @return: The job ID used by Cuckoo to identify this analysis task.
        """
        try:
            # cuckoo_submit is a list, make a copy as to not modify the
            # original value
            proc = self.cuckoo_submit.split(' ') + [sample.submit_path]

            # universal_newlines opens channels to child in text mode and
            # returns strings instead of bytes in return which we do to avoid
            # the need to handle decoding ourselves
            p = subprocess.Popen(proc,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 universal_newlines=True)
            p.wait()
        except Exception as e:
            raise CuckooAnalysisFailedException(e)
        
        if not p.returncode == 0:
            raise CuckooAnalysisFailedException('cuckoo submit returned a non-zero return code.')
        else:
            out, err = p.communicate()
            logger.debug("cuckoo submit STDOUT: %s", out)
            logger.debug("cuckoo submit STDERR: %s", err)

            match = None
            pattern_no = 0
            for pattern in self.job_id_patterns:
                match = re.search(pattern, out)
                if match is not None:
                    logger.debug('Pattern %d matched.' % pattern_no)
                    break

                pattern_no += 1
            
            if match is not None:
                job_id = int(match.group(1))
                # thread-safe, no locking required, revisit if splitting into
                # multiple operations
                self.running_jobs[job_id] = sample
                return job_id

            raise CuckooAnalysisFailedException(
                'Unable to extract job ID from given string %s' % out)

    def get_report(self, job_id):
        path = os.path.join(self.cuckoo_storage,
                'analyses/%d/reports/report.json' % job_id)

        if not os.path.isfile(path):
            raise OSError('Cuckoo report not found at %s.' % path)

        logger.debug('Accessing Cuckoo report for task %d at %s ' %
                (job_id, path))

        report = None
        with open(path) as data:
            try:
                report = json.load(data)
            except ValueError as e:
                logger.exception(e)

        return report

    def do(self):
        """ Run Cuckoo sandbox, parse log output, and report back of Peekaboo. """
        command = self.cuckoo_exec.split(' ')

        # allow for injecting a custom interpreter which we use to run cuckoo
        # with python -u for unbuffered standard output
        if self.interpreter:
            command = self.interpreter.split(' ') + command

        reactor.spawnProcess(CuckooServer(self), command[0], command)

        # do not install twisted's signal handlers because it will screw with
        # our logic (install a handler for SIGTERM and SIGCHLD but not for
        # SIGINT). Instead do what their SIGCHLD handler would do and call the
        # global process reaper.
        reactor.run(installSignalHandlers = False)
        process.reapAllProcesses()
        return self.exit_code

    def shut_down(self, exit_code = 0):
        """ Signal handler callback but in this instance also used as callback
        for protocol to ask us to shut down if anything adverse happens to the
        child """
        # the reactor doesn't like it to be stopped more than once and catching
        # the resulting ReactorNotRunning exception is foiled by the fact that
        # sigTerm defers the call through a queue into another thread which
        # insists on logging it
        if not self.shutdown_requested:
            reactor.sigTerm(0)

        self.shutdown_requested = True
        self.exit_code = exit_code

    def reap_children(self):
        """ Since we only have one child, SIGCHLD will cause us to shut down
        and we reap all child processes on shutdown. This method is therefore
        (currently) intentionally a no-op. """
        pass

class CuckooApi(Cuckoo):
    """
    Interfaces with a Cuckoo installation via its REST API
        
    @author: Felix Bauer
    """
    def __init__(self, job_queue, url="http://localhost:8090", poll_interval=5):
        Cuckoo.__init__(self, job_queue)
        self.url = url
        self.poll_interval = poll_interval
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
        path = sample.submit_path
        filename = os.path.basename(path)
        files = {"file": (filename, open(path, 'rb'))}
        response = self.__get("tasks/create/file", method="post", files=files)
        
        task_id = response["task_id"]
        if task_id > 0:
            # thread-safe, no locking required, revisit if splitting into
            # multiple operations
            self.running_jobs[task_id] = sample
            return task_id
        raise CuckooAnalysisFailedException(
            'Unable to extract job ID from given string %s' % response)

    def get_report(self, job_id):
        logger.debug("Report from Cuckoo API requested, job_id = %d" % job_id)
        return self.__get("tasks/report/%d" % job_id)
    
    def do(self):
        # do the polling for finished jobs
        # record analysis count and call status over and over again
        # logger ......
        
        limit = 1000000
        offset = self.__status()["tasks"]["total"]
        
        while not self.shutdown_requested:
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
            sleep(float(self.poll_interval))

        return 0

class CuckooServer(protocol.ProcessProtocol):
    """
    Class that is used by twisted.internet.reactor to process Cuckoo
    output and process its behavior. Usage::

        srv = CuckooServer()
        reactor.spawnProcess(srv, 'python2', ['python2', '/path/to/cukoo.py'])
        reactor.run()

    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    def __init__(self, cuckoo):
        self.cuckoo = cuckoo
        self.encoding = locale.getpreferredencoding()

    def connectionMade(self):
        logger.info('Connected. Cuckoo PID: %s' % self.transport.pid)
        return None

    def outReceived(self, data):
        """ on receiving output on STDOUT from Cuckoo """
        # explicit decoding: The program is sending us stuff and because it's
        # just stdout/stderr we have no defined protocol, no structure and no
        # guaranteed encoding. Normally we'd tell popen to open in text mode
        # which would automatically apply the system encoding. With Twisted
        # there doesn't seem to be that option. But since it's our child, we
        # can (hopefully) assume that it uses our locale settings. So we use
        # the default encoding as returned by our interpreter.
        logger.debug('STDOUT %s', data.decode(self.encoding))

    def errReceived(self, data):
        """ on receiving output on STDERR from Cuckoo """
        content = data.decode(self.encoding)
        logger.debug('STDERR %s', content.replace('\n', ''))

        #
        # FILE SUBMITTED
        # printed out but has no further effect
        #
        # 2016-04-12 09:14:06,984 [lib.cuckoo.core.scheduler] INFO: Starting
        # analysis of FILE "cuckoo.png" (task #201, options "")
        # INFO: Starting analysis of FILE ".bashrc" (task #4, options "")
        match = re.match(r'.*INFO: Starting analysis of FILE "(.*)" '
                         r'\(task #([0-9]*), options .*', content)

        if match:
            logger.info("File submitted: task #%s, filename %s",
                        match.group(2), match.group(1))

        #
        # ANALYSIS DONE
        #
        # 2016-04-12 09:25:27,824 [lib.cuckoo.core.scheduler] INFO: Task #202:
        # reports generation completed ...
        m = re.match(".*INFO: Task #([0-9]*): reports generation completed.*",
                     content)
        if m:
            job_id = int(m.group(1))
            self.cuckoo.resubmit_with_report(job_id)

    def inConnectionLost(self):
        logger.debug("Cuckoo closed STDIN")
        self.cuckoo.shut_down(1)

    def outConnectionLost(self):
        logger.debug("Cuckoo closed STDOUT")
        self.cuckoo.shut_down(1)

    def errConnectionLost(self):
        logger.warning("Cuckoo closed STDERR")
        self.cuckoo.shut_down(1)

    def processExited(self, reason):
        logger.info("Cuckoo exited with status %s", reason.value.exitCode)
        self.cuckoo.shut_down()

    def processEnded(self, reason):
        logger.info("Cuckoo ended with status %s", reason.value.exitCode)
        self.cuckoo.shut_down()


class CuckooReport(object):
    """
    Represents a Cuckoo analysis JSON report.

    @author: Sebastian Deiss
    @author: Felix Bauer
    """
    def __init__(self, report):
        """
        @param report: hash with report data from Cuckoo
        """
        self.report = report

    @property
    def raw(self):
        return self.report

    @property
    def requested_domains(self):
        """
        Gets the requested domains from the Cuckoo report.

        @returns: The requested domains from the Cuckoo report.
        """
        try:
            return [d['request'] for d in self.report['network']['dns']]
        except KeyError:
            return []

    @property
    def signatures(self):
        """
        Gets the triggered signatures from the Cuckoo report.

        @returns: The triggered signatures from the Cuckoo report or None of
                  there was an error parsing the Cuckoo report.
        """
        try:
            return self.report['signatures']
        except KeyError:
            return []

    @property
    def score(self):
        """
        Gets the score from the Cuckoo report.

        @returns: The score from the Cuckoo report or None of there was an
                  error parsing the Cuckoo report.
        """
        try:
            return self.report['info']['score']
        except KeyError:
            return 0.0

    @property
    def errors(self):
        """
        Errors occurred during Cuckoo analysis.

        @returns: The errors occurred during Cuckoo analysis or None of there
                  was an error parsing the Cuckoo report.
        """
        try:
            return self.report['debug']['errors']
        except KeyError:
            return []

    @property
    def cuckoo_server_messages(self):
        """
        Messages logged by the Cuckoo server (as opposed to those logged by the
        agent inside the analysis VM).

        @returns: List of messages.
        """
        if self.errors:
            logger.warning('Cuckoo produced %d error(s) during processing.' % len(self.errors))
        try:
            return self.report['debug']['cuckoo']
        except KeyError:
            return []
