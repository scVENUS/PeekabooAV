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

""" Interface to Cuckoo. """

import datetime
import os
import logging
import threading

import requests
import urllib3.util.retry

from peekaboo.exceptions import PeekabooException


logger = logging.getLogger(__name__)


class CuckooSubmitFailedException(PeekabooException):
    """ An exception raised if submitting a job to Cuckoo fails. """
    pass


class CuckooJob:
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


class WhitelistRetry(urllib3.util.retry.Retry):
    """ A Retry class which has a status code whitelist, allowing to retry all
    requests not whitelisted in a hard-core, catch-all manner. """
    def __init__(self, status_whitelist=None, abort=None, **kwargs):
        super().__init__(**kwargs)
        self.status_whitelist = status_whitelist or set()
        # Event that is set if we're not to retry
        self.abort = abort

    def new(self, **kwargs):
        """ Adjusted shallow copy method to carry our parameters over into our
        copy. """
        if 'status_whitelist' not in kwargs:
            kwargs['status_whitelist'] = self.status_whitelist
        if 'abort' not in kwargs:
            kwargs['abort'] = self.abort
        return super().new(**kwargs)

    def is_exhausted(self):
        """ Allow to abort a retry chain through an external signal. """
        if self.abort and self.abort.is_set():
            return True

        return super().is_exhausted()

    def is_retry(self, method, status_code, has_retry_after=False):
        """ Override Retry's is_retry to introduce our status whitelist logic.
        """
        # we retry all methods so no check if method is retryable here

        if self.status_whitelist and status_code not in self.status_whitelist:
            return True

        return super().is_retry(method, status_code, has_retry_after)


class Cuckoo:
    """ Interfaces with a Cuckoo installation via its REST API. """
    def __init__(self, job_queue, url="http://localhost:8090", api_token="",
                 poll_interval=5, submit_original_filename=True,
                 max_job_age=900, retries=5, backoff=0.5):
        """ Initialize the object.

        @param job_queue: The job queue to use from now on
        @type job_queue: JobQueue object
        @param url: Where to reach the Cuckoo REST API
        @type url: string
        @param api_token: API token to use for authentication
        @type api_token: string
        @param poll_interval: How long to wait inbetween job status checks
        @type poll_interval: int
        @param submit_original_filename: Whether to provide the original
                                         filename to Cuckoo to enhance analysis.
        @type submit_original_filename: bool
        @param max_job_age: How long to track jobs before declaring them failed.
        @type max_job_age: int (seconds)
        @param retries: Number of retries on API requests
        @type retries: int
        @param backoff: Backoff factor for urllib3
        @type backoff: float
        """
        self.job_queue = job_queue
        self.shutdown_requested = threading.Event()
        self.shutdown_requested.clear()
        self.running_jobs = {}
        # reentrant because we're doing nested calls within critical sections
        self.running_jobs_lock = threading.RLock()
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
                                      status_whitelist=set([200]),
                                      abort=self.shutdown_requested)
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=retry_config)
        self.session = requests.session()
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)

        self.tracker = None

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
        logger.debug("Analysis done for task #%d", job_id)

        sample = self.deregister_running_job(job_id)
        if sample is None:
            logger.debug('No sample found for job ID %d', job_id)
            return None

        logger.debug('Requesting Cuckoo report for sample %s', sample)
        report = self.__get("tasks/report/%d" % job_id)
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

    def submit(self, sample):
        """ Submit a sample to Cuckoo for analysis.
        @param sample: Sample to submit.
        @type sample: Sample

        @raises: CuckooSubmitFailedException if submission failed
        @returns: ID of the submitted Cuckoo job.
        """
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
                "%s/tasks/create/file" % self.url,
                headers=headers, files=files)
        except requests.exceptions.RequestException as error:
            raise CuckooSubmitFailedException(
                'Error creating Cuckoo task: %s' % error)

        try:
            json_resp = response.json()
        except ValueError as error:
            raise CuckooSubmitFailedException(
                'Invalid JSON in response when creating Cuckoo task: %s'
                % error)

        if "task_id" not in json_resp:
            raise CuckooSubmitFailedException(
                'No job ID present in API response')

        task_id = json_resp["task_id"]
        if not isinstance(task_id, int):
            raise CuckooSubmitFailedException(
                'Invalid data type for job ID in API response')

        if task_id is None or task_id <= 0:
            raise CuckooSubmitFailedException(
                'Invalid value for job ID in API response')

        self.register_running_job(task_id, sample)
        return task_id

    def start_tracker(self):
        """ Start tracking running jobs in a separate thread. """
        # do a simple initial test of connectivity. With this we require the
        # API to be reachable at startup (with the usual retries to account for
        # a bit of a race condition in parallel startup) but later on hope
        # that all errors are transient and retry endlessly
        status = self.__get("cuckoo/status")
        if status is None:
            logger.critical("Connection to Cuckoo REST API failed")
            return False
        if "tasks" not in status or "reported" not in status["tasks"]:
            logger.critical("Invalid status JSON structure from Cuckoo REST "
                            "API: %s", status)
            return False

        reported = status["tasks"]["reported"]
        logger.info("Connection to Cuckoo seems to work, "
                    "%i reported tasks seen", reported)

        self.tracker = threading.Thread(target=self.track,
                                        name="CuckooJobTracker")
        self.tracker.start()
        return True

    def track(self):
        """ Do the polling for finished jobs. """
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

                if "task" not in job or "status" not in job["task"]:
                    logger.error("Invalid JSON structure from Cuckoo REST "
                                 "API: %s", job)
                    continue

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

        logger.debug("Cuckoo job tracker shut down.")

    def shut_down(self):
        """ Request the module to shut down, used by the signal handler. """
        logger.debug("Cuckoo job tracker shutdown requested.")
        self.shutdown_requested.set()

    def close_down(self):
        """ Close down tracker resources, particularly, wait for the thread to
        terminate. """
        if self.tracker:
            self.tracker.join()
            self.tracker = None


class CuckooReport:
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
        """ Return the raw report structure.

        @returns: dict of the report.
        """
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
            logger.warning('Cuckoo produced %d error(s) during processing.',
                           len(self.errors))
        try:
            return self.report['debug']['cuckoo']
        except KeyError:
            return []
