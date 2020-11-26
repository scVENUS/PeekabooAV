###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cortex.py                                                           #
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

""" Interface to Cortex. """

import datetime
import logging
import os
import threading

import cortex4py.api
import cortex4py.exceptions

from peekaboo.exceptions import PeekabooException


logger = logging.getLogger(__name__)


class CortexSubmitFailedException(PeekabooException):
    """ An exception raised if submitting a job to Cortex fails. """


class CortexAnalyzerReportMissingException(PeekabooException):
    """ An exception raised if an analysis still needs to be performed. """
    def __init__(self, analyzer):
        super().__init__("Cortex analysis report for analyzer '%s' is missing"
                         % analyzer)
        self.analyzer = analyzer


class CortexAnalyzerReport:
    """ Cortex analyzer report base class. """


class CortexAnalyzer:
    """ Cortex analyzer base class. """
    name = 'unknown'
    reportclass = CortexAnalyzerReport


class CortexFileAnalyzer:
    """ An analyzer which accepts a file as main input. """
    def get_submit_parameters(self, sample, submit_original_filename=False):
        """ Return this analyzer's submit parameters for a given sample. """
        path = sample.submit_path
        filename = os.path.basename(path)

        # override with the original file name if available
        if submit_original_filename:
            if sample.name_declared:
                filename = sample.name_declared
            elif sample.filename:
                filename = sample.filename

        params = {
            'data': path,
            'dataType': 'file',
            'tlp': 1,
            'parameters': {
                'filename': filename,
            }
        }

        return params


class CortexHashAnalyzer(CortexAnalyzer):
    """ An analyzer which accepts hashes as main input. """
    def get_submit_parameters(self, sample, submit_original_filename=False):
        """ Return this analyzer's submit parameters for a given sample. """
        params = {
            'data': sample.sha256sum,
            'dataType': 'hash',
            'tlp': 1,
        }

        return params


class FileInfoAnalyzerReport(CortexAnalyzerReport):
    """ Represents a Cortex FileInfo_7_0 analysis JSON report. """
    def __init__(self, report):
        self.report = report

    @property
    def full(self):
        """ Return the full report. """
        return self.report.get('full', None)


class FileInfoAnalyzer(CortexFileAnalyzer):
    """ Interfaces with Cortex Analyzer FileInfo_7_0. """
    name = 'FileInfo_7_0'
    reportclass = FileInfoAnalyzerReport


class HybridAnalysisReport(CortexAnalyzerReport):
    """ Represents a Cortex HybridAnalysis_GetReport_1_0 analysis JSON
        report. """
    def __init__(self, report):
        self.report = report

    @property
    def full(self):
        """ Return the full report. """
        return self.report.get('full', None)


class HybridAnalysis(CortexFileAnalyzer):
    """ Interfaces with Cortex Analyzer HybridAnalysis_GetReport_1_0. """
    name = 'HybridAnalysis_GetReport_1_0'
    reportclass = HybridAnalysisReport


class VirusTotalQueryReport(CortexAnalyzerReport):
    """ Represents a Cortex VirusTotal_GetReport_3_0 analysis JSON report. """
    def __init__(self, report):
        self.report = report
        self.taxonomies = report.get("summary", {}).get("taxonomies", [{}])[0]

    @property
    def n_of_all(self):
        """ n of all Virusscanners at VirusTotal have rated this file as
            malicious. """
        return int(self.taxonomies.get('value', '-1/0').split('/')[0])

    @property
    def level(self):
        """ safe, suspicious, malicious """
        return self.taxonomies.get('level', None)


class VirusTotalQuery(CortexHashAnalyzer):
    """ Interfaces with Cortex Analyzer VirusTotal_GetReport_3_0. """
    name = 'VirusTotal_GetReport_3_0'
    reportclass = VirusTotalQueryReport


class CuckooSandboxFileAnalysisReport(CortexAnalyzerReport):
    """ Represents a Cortex CuckooSandbox_File_Analysis_Inet_1_2 analysis JSON
        report. """
    def __init__(self, report):
        self.report = report
        self.taxonomies = report.get("summary", {}).get("taxonomies", [{}])

    @property
    def signatures(self):
        """ Matched Cuckoo signatures. """
        return self.report.get('full', {}).get('Signatures', None)

    @property
    def malscore(self):
        """ Malscore n of 10 (might be bigger). """
        for tax in self.taxonomies:
            if tax.get('predicate') == 'Malscore':
                return float(tax['value'])
        return -1


class CuckooSandboxFileAnalysis(CortexFileAnalyzer):
    """ Interfaces with Cortex Analyzer CuckooSandbox_File_Analysis_Inet_1_2.
    """
    name = 'CuckooSandbox_File_Analysis_Inet_1_2'
    reportclass = CuckooSandboxFileAnalysisReport


class CAPEv2FileAnalysisReport(CortexAnalyzerReport):
    """ Represents a Cortex CAPESandbox_File_Analysis_Inet_0_1 analysis JSON
        report. """
    def __init__(self, report):
        self.report = report
        self.taxonomies = report.get("summary", {}).get("taxonomies", [{}])

    @property
    def signatures(self):
        """ Matched CAPE signatures. """
        return self.report.get('full', {}).get('signatures', None)

    @property
    def malscore(self):
        """ Malscore n of 10 (might be bigger). """
        for tax in self.taxonomies:
            if tax.get('predicate') == 'Malscore':
                return float(tax['value'])
        return -1


class CAPEv2FileAnalysis(CortexFileAnalyzer):
    """ Interfaces with Cortex Analyzer CAPESandbox_File_Analysis_Inet_0_1. """
    name = 'CAPESandbox_File_Analysis_Inet_0_1'
    reportclass = CAPEv2FileAnalysisReport


class CortexReport:
    """ Meta class that either returns Cortex analysis reports or requests an
    analysis to be performed if it's not available yet. """
    def __init__(self):
        """ Initialize the report object. """
        self.reports = {}

    def register_report(self, analyzer, report):
        """ Register a report from an analyzer.

        @param analyzer: The analyzer the report is from.
        @type analyzer: CortexAnalyzer
        @param report: The report dict as returned by the API.
        @type report: dict
        """
        if analyzer.name in self.reports:
            logger.warning('Analysis report for %s already present - '
                           'replacing.', analyzer.name)

        self.reports[analyzer.name] = analyzer.reportclass(report)

    def get_report(self, analyzer):
        """ Try to retrieve an analyzer report from the sample.

        @param analyzer: Name of the analyzer
        @type analyzer: string
        @returns: CortexAnalyzerReport if present
        @raises: CortexAnalyzerReportMissingException if the report is not
                 yet present.
        """
        report = self.reports.get(analyzer.name)
        if report is None:
            raise CortexAnalyzerReportMissingException(analyzer)

        return report

    @property
    def FileInfoReport(self):
        """ Retrieve FileInfo analyzer report. """
        return self.get_report(FileInfoAnalyzer())

    @property
    def HybridAnalysisReport(self):
        """ Retrieve HybridAnalysis analyzer report. """
        return self.get_report(HybridAnalysis())

    @property
    def VirusTotalQueryReport(self):
        """ Retrieve VirusTotalQuery analyzer report. """
        return self.get_report(VirusTotalQuery())

    @property
    def CuckooSandboxFileReport(self):
        """ Retrieve CuckooSandboxFile analyzer report. """
        return self.get_report(CuckooSandboxFileAnalysis())

    @property
    def CAPEv2FileReport(self):
        """ Retrieve CAPEv2File analyzer report. """
        return self.get_report(CAPEv2FileAnalysis())


class CortexJob:
    """ Remember sample and submission time of a Cortex job. """
    def __init__(self, sample, analyzer):
        """ Initialise the CortexJob wrapper.

        @param sample: The sample in analysis.
        @type sample: Sample
        @param job: The Cortex analysis job
        @type job: cortex4py.controllers.JobController
        @param analyzer: Our analyzer object
        @type analyzer: CortexAnalyzer
        """
        self.__sample = sample
        self.__submission_time = datetime.datetime.utcnow()
        self.__analyzer = analyzer

    def is_older_than(self, seconds):
        """ Returns True if the difference between submission time and now,
        i.e. the age of the job, is larger than given number of seconds. """
        max_age = datetime.timedelta(seconds=seconds)
        return datetime.datetime.utcnow() - self.__submission_time > max_age

    @property
    def sample(self):
        """ Returns the sample the job is analyzing. """
        return self.__sample

    @property
    def analyzer(self):
        """ Returns the analyzer used to analyse the sample. """
        return self.__analyzer


class Cortex:
    """ Interfaces with a Cortex installation via its REST API. """
    def __init__(self, job_queue, url="http://localhost:9001", api_token="",
                 poll_interval=5, submit_original_filename=True,
                 max_job_age=900):
        """ Initialize the object.

        @param job_queue: The job queue to use from now on
        @type job_queue: JobQueue object
        @param url: Where to reach the Cortex REST API
        @type url: string
        @param api_token: API token to use for authentication
        @type api_token: string
        @param poll_interval: How long to wait inbetween job status checks
        @type poll_interval: int
        @param submit_original_filename: Whether to provide the original
                                         filename to Cortex to enhance
                                         analysis.
        @type submit_original_filename: bool
        @param max_job_age: How long to track jobs before declaring them
                            failed.
        @type max_job_age: int (seconds)
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

        self.api = None
        self.tracker = None

    def register_running_job(self, job_id, job):
        """ Register a job as running. Detect if another sample has already
        been registered with the same job ID which obviously must never happen
        because it corrupts our internal housekeeping. Guarded by a lock
        because multiple worker threads will call this routine and check for
        collision and update of job log might otherwise race each other.

        @param job_id: Cortex job ID of the job to register as running.
        @type job_id: string
        @param job: Our Cortex job wrapper object
        @type job: CortexJob

        @returns: None
        @raises: CortexSubmitFailedException on job id collision """
        with self.running_jobs_lock:
            if (job_id in self.running_jobs and
                    self.running_jobs[job_id] is not job):
                raise CortexSubmitFailedException(
                    'A job with ID %s is already registered as running '
                    'for sample %s' % (job_id, self.running_jobs[job_id]))

            self.running_jobs[job_id] = job

    def deregister_running_job(self, job_id):
        """ Deregister a running job by job id.

        @param job_id: Cortex job ID of the job do deregister.
        @type job_id: string
        @returns: Sample object of the job or None if job not found. """
        with self.running_jobs_lock:
            return self.running_jobs.pop(job_id, None)

    def deregister_running_job_if_too_old(self, job_id, max_age):
        """ Check if a job has gotten too old and remove it from the list of
        running jobs if so.

        @param job_id: Cortex job ID of the job do deregister.
        @type job_id: string
        @returns: Sample object of the job or None if job not found. """
        with self.running_jobs_lock:
            if self.running_jobs[job_id].is_older_than(max_age):
                return self.deregister_running_job(job_id)

        return None

    def resubmit_with_analyzer_report(self, job_id):
        """ Resubmit a sample to the job queue after an analyzer report became
        available. Retrieves the report from Cortex.

        @param job_id: ID of job which has finished.
        @type job_id: string
        @param report: Analyzer report
        @type report: dict

        @returns: None
        """
        logger.debug("Analysis done for job %s", job_id)

        job = self.deregister_running_job(job_id)
        if job is None:
            logger.debug('No job found for job ID %s', job_id)
            return None

        logger.debug('Requesting Cortex report for sample %s', job.sample)
        try:
            report = self.api.jobs.get_report(job_id)
            # register this job's analysis report with our main report object
            job.sample.cortex_report.register_report(
                job.analyzer, report.report)
        # FIXME: More error handling and retrying here
        except cortex4py.exceptions.CortexException:
            # mark analysis as failed if we could not get the report e.g.
            # because it was corrupted or the API connection failed.
            job.sample.mark_cortex_failure()

        self.job_queue.submit(job.sample, self.__class__)
        return None

    def resubmit_as_failed(self, job_id):
        """ Resubmit a sample to the job queue with a failure report if the
        Cortex job has failed for some reason.

        @param job_id: ID of job that failed.
        @type job_id: string
        """
        job = self.deregister_running_job(job_id)
        if job is not None:
            logger.warning("Dropped job %s because it has failed in Cortex",
                           job_id)
            job.sample.mark_cortex_failure()
            self.job_queue.submit(job.sample, self.__class__)

    def resubmit_as_failed_if_too_old(self, job_id, max_age):
        """ Resubmit a sample to the job queue with a failure report if the
        Cortex job has been running for too long.

        @param job_id: ID of job to check.
        @type job_id: string
        @param max_age: maximum job age in seconds
        @type max_age: int
        """
        job = self.deregister_running_job_if_too_old(job_id, max_age)
        if job is not None:
            logger.warning("Dropped job %s because it has been running for "
                           "too long", job_id)
            job.sample.mark_cortex_failure()
            self.job_queue.submit(job.sample, self.__class__)

    def submit(self, sample, analyzer):
        """ Submit a sample to Cortex for analysis.
        @param sample: Sample to submit.
        @type sample: Sample

        @raises: CortexSubmitFailedException if submission failed
        @returns: ID of the submitted Cortex job.
        """
        params = analyzer.get_submit_parameters(
            sample, self.submit_original_filename)

        logger.debug("Creating Cortex job with analyzer %s and "
                     "parameters %s", analyzer.name, params)
        job = self.api.analyzers.run_by_name(analyzer.name, params)
        self.register_running_job(job.id, CortexJob(sample, analyzer))
        return job.id

    def start_tracker(self):
        """ Start tracking running jobs in a separate thread. """
        # do a simple initial test of connectivity. With this we require the
        # API to be reachable at startup (with the usual retries to account for
        # a bit of a race condition in parallel startup) but later on hope
        # that all errors are transient and retry endlessly
        self.api = cortex4py.api.Api(self.url, self.api_token)
        self.api.analyzers.find_all({}, range='all')

        self.tracker = threading.Thread(target=self.track,
                                        name="CortexJobTracker")
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
                cortexjob = self.api.jobs.get_by_id(job_id)
                if cortexjob.status in ['Success']:
                    self.resubmit_with_analyzer_report(job_id)
                    continue

                if cortexjob.status in ['Failure', 'Deleted']:
                    self.resubmit_as_failed(job_id)
                    continue

                # drop jobs which have been running for too long. This is
                # mainly to prevent accumulation of jobs in our job list which
                # will never finish. We still want to wait for jobs to finish
                # even though our client might not be interested any more so
                # that we have the result cached for the next time we get the
                # same sample.
                self.resubmit_as_failed_if_too_old(job_id, self.max_job_age)

        logger.debug("Cortex job tracker shut down.")

    def shut_down(self):
        """ Request the module to shut down, used by the signal handler. """
        logger.debug("Cortex job tracker shutdown requested.")
        self.shutdown_requested.set()

    def close_down(self):
        """ Close down tracker resources, particularly, wait for the thread to
        terminate. """
        if self.tracker:
            self.tracker.join()
            self.tracker = None
