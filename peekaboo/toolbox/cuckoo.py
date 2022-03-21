###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cuckoo.py                                                           #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2022 science + computing ag                              #
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
import schema
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


class AllowedStatusRetry(urllib3.util.retry.Retry):
    """ A Retry class which has a list of allowed status codes, allowing to
    retry all status codes not explicitly allowed in a hard-core, catch-all
    manner. """
    def __init__(self, allowed_statuses=None, abort=None, **kwargs):
        super().__init__(**kwargs)
        self.allowed_statuses = allowed_statuses or set()
        # Event that is set if we're not to retry
        self.abort = abort

    def new(self, **kwargs):
        """ Adjusted shallow copy method to carry our parameters over into our
        copy. """
        if 'allowed_statuses' not in kwargs:
            kwargs['allowed_statuses'] = self.allowed_statuses
        if 'abort' not in kwargs:
            kwargs['abort'] = self.abort
        return super().new(**kwargs)

    def is_exhausted(self):
        """ Allow to abort a retry chain through an external signal. """
        if self.abort and self.abort.is_set():
            return True

        return super().is_exhausted()

    def is_retry(self, method, status_code, has_retry_after=False):
        """ Override Retry's is_retry to introduce our allowed statuses logic.
        """
        # we retry all methods so no check if method is retryable here

        if self.allowed_statuses and status_code not in self.allowed_statuses:
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
        # Also, use allowed_methods=None to enable POST and other methods for
        # retry which aren't by default because they're not considered
        # idempotent. We assume that with the REST API a request either
        # succeeds or fails without residual effects, making them atomic and
        # idempotent.
        #
        # And finally we retry everything but a 200 response, which admittedly
        # is a bit hard-core but serves our purposes for now.
        retry_config = AllowedStatusRetry(
            total=retries, backoff_factor=backoff, allowed_methods=None,
            allowed_statuses=set([200]), abort=self.shutdown_requested)
        retry_adapter = requests.adapters.HTTPAdapter(max_retries=retry_config)
        self.session = requests.session()
        self.session.mount('http://', retry_adapter)
        self.session.mount('https://', retry_adapter)

        self.tracker = None

    def request_url(self, path):
        """ Return the full request URL for a given path based on the
        configured base URL of the Cuckoo API.

        @param path: resource path relative to the API base URL
        @type path: string

        @returns: string representing URL
        """
        return "%s/%s" % (self.url, path)

    def __get(self, path):
        request_url = self.request_url(path)
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
                logger.warning(
                    '%d: A job with ID %d already registered as running '
                    'for different sample %d will be marked failed',
                    sample.id, job_id,
                    self.running_jobs[job_id].sample.id)
                self.resubmit_as_failed(job_id)

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

        logger.debug('%d: Requesting Cuckoo report', sample.id)
        report_path = "tasks/report/%d" % job_id
        report = self.__get(report_path)
        if report is None:
            # mark analysis as failed if we could not get the report e.g.
            # because it was corrupted or the API connection failed.
            sample.mark_cuckoo_failure()
        else:
            try:
                reportobj = CuckooReport(report, self.request_url(report_path))
                sample.register_cuckoo_report(reportobj)
            except schema.SchemaError as err:
                logger.warning('Report returned from Cuckoo contained '
                               'invalid data: %s', err)
                sample.mark_cuckoo_failure()

        self.job_queue.submit(sample)
        return None

    def resubmit_as_failed(self, job_id):
        """ Resubmit a sample to the job queue with a failure report if the
        Cuckoo job has failed for some reason.

        @param job_id: ID of job that failed.
        @type job_id: int
        """
        sample = self.deregister_running_job(job_id)
        if sample is not None:
            sample.mark_cuckoo_failure()
            self.job_queue.submit(sample)

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
            self.job_queue.submit(sample)

    def submit(self, sample):
        """ Submit a sample to Cuckoo for analysis.
        @param sample: Sample to submit.
        @type sample: Sample

        @raises: CuckooSubmitFailedException if submission failed
        @returns: ID of the submitted Cuckoo job.
        """
        filename = sample.sha256sum

        # append file extension to aid cuckoo in file type detection
        if sample.file_extension:
            filename = '%s.%s' % (filename, sample.file_extension)

        # override with the original file name if available
        if self.submit_original_filename and sample.filename:
            filename = sample.filename

        files = {"file": (filename, sample.content)}
        logger.debug("Creating Cuckoo task with filename %s", filename)
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
    def __init__(self, report=None, url=None):
        """
        @param report: hash with report data from Cuckoo
        @type report: dict
        @param url: URL where the report was retrieved from
        @type url: string
        """
        self._url = url

        if report is None:
            report = {}

        # some common building blocks for reuse
        dns_element_schema = {'request': str}
        description_element_schema = {'description': str}

        # defaults of optional keys are not validated. Therefore their
        # validators can't set more default values. So we can only rely on the
        # validation result to contain the top-level key defaults. To avoid
        # confusion make no assumptions about optional key existance at all and
        # only schema compliance. We still use the result though because
        # ignore_extra_keys has stripped it of extraneous data which protects
        # us somewhat from accidentally processing it.
        report = schema.Schema({
            schema.Optional('network', default={}, ignore_extra_keys=True): {
                schema.Optional('dns', default=[]): schema.Or(
                    list([dns_element_schema]),
                    tuple([dns_element_schema]),
                    ignore_extra_keys=True),
                },
            schema.Optional('signatures', default=[]): schema.Or(
                list([description_element_schema]),
                tuple([description_element_schema]),
                ignore_extra_keys=True),
            schema.Optional('info', default={}): {
                schema.Optional('score', default=0.0): schema.Or(int, float),
                },
            schema.Optional('debug', default={}): {
                schema.Optional('errors', default=[]): schema.Or(
                    list([str]),
                    tuple([str])),
                schema.Optional('cuckoo', default=[]): schema.Or(
                    list([str]),
                    tuple([str])),
                },
            }, ignore_extra_keys=True).validate(report)

        self._requested_domains = [
            domain['request'] for domain in report.get(
                'network', {}).get('dns', [])]

        self._signature_descriptions = [
            sig['description'] for sig in report.get('signatures', [])]

        # explicitly convert to the types of our external API here if we accept
        # multiple types as input (schema.Use could convert as well but does it
        # before validation in duck-typing fashion which could make us accept
        # unintended types, e.g. a string because it can be converted to a list
        # because it's iterable).
        self._score = float(report.get('info', {}).get('score', 0.0))

        debug = report.get('debug', {})
        self._errors = list(debug.get('errors', []))
        self._server_messages = list(debug.get('cuckoo', []))

    @property
    def dump(self):
        """ Return the a dump of the report in a defined structure similar to
        the original Cuckoo report dict.

        @returns: dict containiing all the information we have.
        """
        return {
            "x-peekaboo": {
                "origin-url": self.url,
            },
            "info": {
                "score": self.score,
            },
            "network": {
                "dns": [
                    {"request": domain} for domain in self.requested_domains],
            },
            "signatures": [
                {"description": desc} for desc in self.signature_descriptions],
            "debug": {
                "errors": self.errors,
                "cuckoo": self.server_messages,
            },
        }

    @property
    def requested_domains(self):
        """
        Gets the requested domains from the Cuckoo report.

        @returns: The requested domains from the Cuckoo report.
        """
        return self._requested_domains

    @property
    def signature_descriptions(self):
        """
        Gets the description of triggered Cuckoo signatures from report.

        @returns: The description of triggered signatures from the Cuckoo
                  report.
        """
        return self._signature_descriptions

    @property
    def score(self):
        """
        Gets the score from the Cuckoo report.

        @returns: The score from the Cuckoo report.
        """
        return self._score

    @property
    def errors(self):
        """
        Errors occurred during Cuckoo analysis.

        @returns: The errors occurred during Cuckoo analysis.
        """
        return self._errors

    @property
    def server_messages(self):
        """
        Messages logged by the Cuckoo server (as opposed to those logged by the
        agent inside the analysis VM).

        @returns: List of messages.
        """
        return self._server_messages

    @property
    def url(self):
        """ Return a URL where the full Cuckoo report this object is based on
        can be retrieved (again).

        @returns: string representing the URL.
        """
        return self._url
