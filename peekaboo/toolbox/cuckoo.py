###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cuckoo.py                                                           #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2020  science + computing ag                             #
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


from future.builtins import super  # pylint: disable=wrong-import-order

import datetime
import re
import os
import locale
import logging
import json
import subprocess
import random
import requests
import urllib3.util.retry

from threading import RLock, Event
from time import sleep
from twisted.internet import protocol, reactor, process

from peekaboo.exceptions import CuckooSubmitFailedException


logger = logging.getLogger(__name__)


class CuckooJob(object):
    """ Remember sample and submission time of a Cuckoo job. """
    def __init__(self, sample):
        self.__sample = sample
        self.__submission_time = datetime.datetime.utcnow()

    def is_older_than(self, seconds):
        """ Returns True if the difference between submission time and now,
        i.e. the age of the job, is larger than given number of seconds. """
        max_age = datetime.timedelta(seconds=seconds)
        return datetime.datetime.utcnow() - self.__submission_time > max_age

    @property
    def sample(self):
        """ Returns the sample the job is analyzing. """
        return self.__sample


class Cuckoo(object):
    """ Parent class, defines interface to Cuckoo. """
    def __init__(self, job_queue):
        self.job_queue = job_queue
        self.shutdown_requested = Event()
        self.shutdown_requested.clear()
        self.running_jobs = {}
        # reentrant because we're doing nested calls within critical sections
        self.running_jobs_lock = RLock()

    def register_running_job(self, job_id, sample):
        """ Register a job as running. Detect if another sample has already
        been registered with the same job ID which obviously must never happen
        because it corrupts our internal housekeeping. Guarded by a lock
        because multiple worker threads will call this routine and check for
        collision and update of job log might otherwise race each other.

        @param job_id: ID of the job to register as running.
        @type job_id: int
        @param sample: Sample object to associate with this job ID
        @type sample: Sample

        @returns: None
        @raises: CuckooSubmitFailedException on job id collision """
        with self.running_jobs_lock:
            if (job_id in self.running_jobs and
                    self.running_jobs[job_id] is not sample):
                raise CuckooSubmitFailedException(
                    'A job with ID %d is already registered as running '
                    'for sample %s' % (job_id, self.running_jobs[job_id]))

            self.running_jobs[job_id] = CuckooJob(sample)

    def deregister_running_job(self, job_id):
        """ Deregister a running job by job id.

        @returns: Sample object of the job or None if job not found. """
        with self.running_jobs_lock:
            job = self.running_jobs.pop(job_id, None)
            if job is not None:
                return job.sample

        return None

    def deregister_running_job_if_too_old(self, job_id, max_age):
        """ Check if a job has gotten too old and remove it from the list of
        running jobs if so.

        @returns: Sample object of the job or None if job not found. """
        with self.running_jobs_lock:
            if self.running_jobs[job_id].is_older_than(max_age):
                return self.deregister_running_job(job_id)

        return None

    def resubmit_with_report(self, job_id):
        """ Resubmit a sample to the job queue after the report became
        available. Retrieves the report from Cuckoo.

        @param job_id: ID of job which has finished.
        @type job_id: int

        @returns: None """
        logger.debug("Analysis done for task #%d" % job_id)

        sample = self.deregister_running_job(job_id)
        if sample is None:
            logger.debug('No sample found for job ID %d', job_id)
            return None

        logger.debug('Requesting Cuckoo report for sample %s', sample)
        report = self.get_report(job_id)
        if report is None:
            # mark analysis as failed if we could not get the report e.g.
            # because it was corrupted or the API connection failed.
            sample.mark_cuckoo_failure()
        else:
            reportobj = CuckooReport(report)
            sample.register_cuckoo_report(reportobj)

        self.job_queue.submit(sample, self.__class__)
        return None

    def resubmit_as_failed_if_too_old(self, job_id, max_age):
        """ Resubmit a sample to the job queue with a failure report if the
        Cuckoo job has been running for too long.

        @param job_id: ID of job to check.
        @type job_id: int
        @param max_age: maximum job age in seconds
        @type max_age: int
        """
        sample = self.deregister_running_job_if_too_old(job_id, max_age)
        if sample is not None:
            logger.warning("Dropped job %d because it has been running for "
                           "too long", job_id)
            sample.mark_cuckoo_failure()
            self.job_queue.submit(sample, self.__class__)

    def shut_down(self):
        """ Request the module to shut down. """
        self.shutdown_requested.set()

    def reap_children(self):
        pass

    def get_report(self, job_id):
        """ Extract the report of a finished analysis from Cuckoo. To be
        overridden by derived classes for actual implementation. """
        raise NotImplementedError

class CuckooEmbed(Cuckoo):
    """ Runs and interfaces with Cuckoo in IPC. """
    def __init__(self, job_queue, cuckoo_exec, cuckoo_submit,
                 cuckoo_storage, interpreter=None):
        super().__init__(job_queue)
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
        except Exception as error:
            raise CuckooSubmitFailedException(error)

        if not p.returncode == 0:
            raise CuckooSubmitFailedException(
                'cuckoo submit returned a non-zero return code.')

        out, err = p.communicate()
        logger.debug("cuckoo submit STDOUT: %s", out)
        logger.debug("cuckoo submit STDERR: %s", err)

        match = None
        pattern_no = 0
        for pattern in self.job_id_patterns:
            match = re.search(pattern, out)
            if match is not None:
                logger.debug('Pattern %d matched.', pattern_no)
                break

            pattern_no += 1

        if match is not None:
            job_id = int(match.group(1))
            self.register_running_job(job_id, sample)
            return job_id

        raise CuckooSubmitFailedException(
            'Unable to extract job ID from given string %s' % out)

    def get_report(self, job_id):
        path = os.path.join(self.cuckoo_storage,
                'analyses/%d/reports/report.json' % job_id)

        if not os.path.isfile(path):
            return None

        logger.debug('Accessing Cuckoo report for task %d at %s ' %
                (job_id, path))

        report = None
        with open(path) as data:
            try:
                report = json.load(data)
            except ValueError as e:
                logger.warning("Error loading JSON report for cuckoo "
                               "job id %d", job_id)

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
        if not self.shutdown_requested.is_set():
            reactor.sigTerm(0)

        self.shutdown_requested.set()
        self.exit_code = exit_code

    def reap_children(self):
        """ Since we only have one child, SIGCHLD will cause us to shut down
        and we reap all child processes on shutdown. This method is therefore
        (currently) intentionally a no-op. """
        pass


class WhitelistRetry(urllib3.util.retry.Retry):
    """ A Retry class which has a status code whitelist, allowing to retry all
    requests not whitelisted in a hard-core, catch-all manner. """
    def __init__(self, status_whitelist=None, **kwargs):
        super().__init__(**kwargs)
        self.status_whitelist = status_whitelist or set()

    def is_retry(self, method, status_code, has_retry_after=False):
        """ Override Retry's is_retry to introduce our status whitelist logic.
        """
        # we retry all methods so no check if method is retryable here

        if self.status_whitelist and status_code not in self.status_whitelist:
            return True

        return super().is_retry(method, status_code, has_retry_after)


class CuckooApi(Cuckoo):
    """ Interfaces with a Cuckoo installation via its REST API. """
    def __init__(self, job_queue, url="http://localhost:8090", api_token="",
                 poll_interval=5, submit_original_filename=True,
                 max_job_age=900, retries=5, backoff=0.5):
        super().__init__(job_queue)
        self.url = url
        self.api_token = api_token
        self.poll_interval = poll_interval
        self.submit_original_filename = submit_original_filename
        self.max_job_age = max_job_age

        # urrlib3 backoff formula:
        # <backoff factor> * (2 ^ (<retry count so far> - 1))
        # with second try intentionally having no sleep,
        # e.g. with retry count==5 and backoff factor==0.5:
        # try 1: fail, sleep(0.5*2^(1-1)==0.5*2^0==0.5*1==0.5->intentionally
        #   overridden to 0)
        # try 2: fail, sleep(0.5*2^(2-1)==0.5*2^1==1)
        # try 3: fail, sleep(0.5*2^(3-1)==0.5*2^2==2)
        # try 4: fail, sleep(0.5*2^(4-1)==0.5*2^3==4)
        # try 5: fail, abort, sleep would've been 8 before try 6
        #
        # Also, use method_whitelist=False to enable POST and other methods for
        # retry which aren't by default because they're not considered
        # idempotent. We assume that with the REST API a request either
        # succeeds or fails without residual effects, making them atomic and
        # idempotent.
        #
        # And finally we retry everything but a 200 response, which admittedly
        # is a bit hard-core but serves our purposes for now.
        retry_config = WhitelistRetry(total=retries,
                                      backoff_factor=backoff,
                                      method_whitelist=False,
                                      status_whitelist=set([200]))
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=retry_config)
        self.session = requests.session()
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)

    def __get(self, path):
        request_url = "%s/%s" % (self.url, path)
        logger.debug("Getting %s", request_url)
        headers = {"Authorization": "Bearer %s" % self.api_token}

        try:
            response = self.session.get(request_url, headers=headers)
        # all requests exceptions are derived from RequestsException, including
        # RetryError, TooManyRedirects and Timeout
        except requests.exceptions.RequestException as error:
            logger.error('Request to REST API failed: %s', error)
            return None

        # no check for status code here since we retry all but 200
        # responses and raise an exception if retries fail
        try:
            json_resp = response.json()
        except ValueError as error:
            logger.error(
                'Invalid JSON in response when getting %s: %s',
                request_url, error)
            return None

        return json_resp

    def submit(self, sample):
        path = sample.submit_path
        filename = os.path.basename(path)
        # override with the original file name if available
        if self.submit_original_filename:
            if sample.name_declared:
                filename = sample.name_declared
            elif sample.filename:
                filename = sample.filename

        files = {"file": (filename, open(path, 'rb'))}
        logger.debug("Creating Cuckoo task with content from %s and "
                     "filename %s", path, filename)
        headers = {"Authorization": "Bearer %s" % self.api_token}

        try:
            response = self.session.post(
                "%s/tasks/create/file" % self.url, headers=headers, files=files)
        except requests.exceptions.RequestException as error:
            raise CuckooSubmitFailedException(
                'Error creating Cuckoo task: %s' % error)

        try:
            json_resp = response.json()
        except ValueError as error:
            raise CuckooSubmitFailedException(
                'Invalid JSON in response when creating Cuckoo task: %s'
                % error)

        if "task_id" in json_resp:
            task_id = json_resp["task_id"]
            if task_id > 0:
                self.register_running_job(task_id, sample)
                return task_id

        raise CuckooSubmitFailedException(
            'Unable to extract job ID from response %s' % json_resp)

    def get_report(self, job_id):
        logger.debug("Report from Cuckoo API requested, job_id = %d" % job_id)
        return self.__get("tasks/report/%d" % job_id)

    def do(self):
        """ Do the polling for finished jobs. """
        # do a simple initial test of connectivity. With this we require the
        # API to be reachable at startup (with the usual retries to account for
        # a bit of a race condition in parallel startup) but later on hope
        # that all errors are transient and retry endlessly
        status = self.__get("cuckoo/status")
        if status is None:
            logger.critical("Connection to Cuckoo REST API failed")
            return 1
        if "tasks" not in status or "reported" not in status["tasks"]:
            logger.critical("Invalid status JSON structure from Cuckoo REST "
                            "API: %s", status)
            return 1

        reported = status["tasks"]["reported"]
        logger.info("Connection to Cuckoo seems to work, "
                    "%i reported tasks seen", reported)

        while not self.shutdown_requested.wait(self.poll_interval):
            # no lock, atomic, copy() because keys() returns an iterable view
            # instead of a fresh new list in python3
            running_jobs = self.running_jobs.copy().keys()

            # somewhat inefficient for the potential number of requests per
            # poll round but more efficient in that it does not download an
            # ever growing list of jobs using tasks/list. Might also take
            # quite a while to get to all jobs if retries happen on each
            # request.
            # A call to get data about multiple tasks in one go would be nice
            # here. tasks/list could be used with the minimum job number as
            # offset and spread between highest and lowest job id as limit *if*
            # its output was sorted by job ID. Apparently limit and offset are
            # only meant to iterate over the job list in blocks but not to
            # return data about a specific range of job IDs from that list.
            for job_id in running_jobs:
                job = self.__get("tasks/view/%i" % job_id)
                if job is None:
                    # ignore and retry on next polling run
                    continue

                # but fail hard if we get invalid stuff
                if "task" not in job or "status" not in job["task"]:
                    logger.error("Invalid JSON structure from Cuckoo REST "
                                 "API: %s", job)
                    return 1

                if job["task"]["status"] == "reported":
                    self.resubmit_with_report(job_id)
                    continue

                # drop jobs which have been running for too long. This is
                # mainly to prevent accumulation of jobs in our job list which
                # will never finish. We still want to wait for jobs to finish
                # even though our client might not be interested any more so
                # that we have the result cached for the next time we get the
                # same sample.
                self.resubmit_as_failed_if_too_old(job_id, self.max_job_age)

        logger.debug("Shutting down.")
        return 0

class CuckooServer(protocol.ProcessProtocol):
    """ Class that is used by twisted.internet.reactor to process Cuckoo output
    and process its behavior. Usage::

        srv = CuckooServer()
        reactor.spawnProcess(srv, 'python2', ['python2', '/path/to/cukoo.py'])
        reactor.run() """
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
    """ Represents a Cuckoo analysis JSON report. """
    def __init__(self, report=None):
        """
        @param report: hash with report data from Cuckoo
        """
        if report is None:
            report = {}
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
        return self.report.get('signatures', [])

    @property
    def signature_descriptions(self):
        """
        Gets the description of triggered Cuckoo signatures from report.

        @returns: The description of triggered signatures from the Cuckoo
                  report or empty list if there was an error parsing the
                  Cuckoo report.
        """
        descriptions = []
        for sig in self.signatures:
            descriptions.append(sig['description'])
        return descriptions

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
