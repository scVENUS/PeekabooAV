###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# toolbox/                                                                    #
#         cortex.py                                                           #
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

""" Interface to Cortex. """

import asyncio
import datetime
import http.cookiejar
import json
import logging
import os
import urllib.parse
import enum

import aiohttp
import schema
import tenacity

from peekaboo.exceptions import PeekabooException


logger = logging.getLogger(__name__)

class tlp(enum.Enum):
    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3

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
    report_schema = schema.Schema(None, error='Subclass needs to provide a schema')

    report_schema_artifacts = [schema.Schema({
        "data": str,
        "dataType": str,
    # Possible future extensions
    #    "message": schema.Schema(schema.Or(str, None)),
    #    "tags": list,
    #    "tlp": int
    }, ignore_extra_keys=True)]

    def __init__(self, unvalidated_report):
        if unvalidated_report is None:
            unvalidated_report = {}

        # validate the report against subclass attribute report_schema
        self.report = self.report_schema.validate(unvalidated_report)

        self._domain_artifacts = self.get_filtered_elements_from_list_of_dicts(
                self.report.get('artifacts', []), 'dataType', 'domain', 'data', str)
        self._hash_artifacts = self.get_filtered_elements_from_list_of_dicts(
                self.report.get('artifacts', []), 'dataType', 'hash', 'data', str)
        self._ip_artifacts = self.get_filtered_elements_from_list_of_dicts(
                self.report.get('artifacts', []), 'dataType', 'ip', 'data', str)

    @classmethod
    def get_element_from_list_of_dicts(cls, list_, ident_key, ident_value, default={}):
        #pylint: disable=dangerous-default-value
        """ Search a list of dicts for an element with a matching value for an
            identifying key """
        element = [dictionary for dictionary in list_
            if dictionary.get(ident_key) == ident_value
        ]
        if len(element) != 1:
            return default
        return element[0]

    @classmethod
    def get_filtered_elements_from_list_of_dicts(
            cls, dictionary, ident_key, ident_value, filter_key, filter_data_type):
        """ Search a list of dicts for elements with a matching value for an
            identifying key and filter on filter_key with filter_data_type """
        elements = [artifact['data'] for artifact in dictionary
            if artifact.get(ident_key) == ident_value and
                filter_key in artifact and
                isinstance(artifact[filter_key], filter_data_type)
        ]
        return elements

    @property
    def domain_artifacts(self):
        """ Returns a list of domain artifacts. """
        return self._domain_artifacts

    @property
    def hash_artifacts(self):
        """ Returns a list of hash artifacts. """
        return self._hash_artifacts

    @property
    def ip_artifacts(self):
        """ Returns a list of ip artifacts. """
        return self._ip_artifacts


class CortexAnalyzer:
    """ Cortex analyzer base class. """
    name = 'unknown'
    reportclass = CortexAnalyzerReport


class CortexFileAnalyzer:
    """ An analyzer which accepts a file as main input. """
    @staticmethod
    async def get_submit_parameters(
            sample, sample_tlp, submit_original_filename=True):
        """ Return this analyzer's submit parameters for a given sample and a
        filtered, loggable version of them. """
        filename = await sample.sha256sum

        # append file extension to aid backend analyzers in file type detection
        if sample.file_extension:
            filename = '%s.%s' % (filename, sample.file_extension)

        # override with the original file name if available
        if submit_original_filename and sample.filename:
            filename = sample.filename

        # log-friendly params prevent flooding the log with superfluous data
        # and can prevent information leakage
        params = {
            'dataType': 'file',
            'tlp': sample_tlp.value,
            # 'pap' ?
        }

        content_type = sample.type_declared

        # produce a separate set of loggable params
        # NOTE: beware of leaking sensitive or flooding with large amounts of
        # data from params
        log_params = params.copy().update({
            'data': '<%d bytes of sample data>' % sample.file_size,
            'content-type': content_type,
            'filename': filename,
        })

        # submit with declared content type as well
        payload = aiohttp.FormData()
        payload.add_field('_json', json.dumps(params))
        payload.add_field(
            'data', sample.content,
            content_type=content_type,
            filename=filename)

        # calling the callable FormData finalises it into a BytesPayload and
        # makes it reusable across retries
        return payload(), log_params


class CortexHashAnalyzer(CortexAnalyzer):
    """ An analyzer which accepts hashes as main input. """
    @staticmethod
    async def get_submit_parameters(
            sample, sample_tlp, submit_original_filename=True):
        """ Return this analyzer's submit parameters for a given sample and a
        filtered, loggable version of them. """
        del submit_original_filename

        params = {
            'data': await sample.sha256sum,
            'dataType': 'hash',
            'tlp': sample_tlp.value,
            # 'pap' ?
        }

        return aiohttp.JsonPayload(params), params


class FileInfoAnalyzerReport(CortexAnalyzerReport):
    """ Represents a Cortex FileInfo_8_0 analysis JSON report. """

    report_schema = schema.Schema({
        "summary": {
            "taxonomies": [schema.Schema({
                "level": schema.Or("info", "malicious", "safe"),
                "namespace": "FileInfo",
            #    "predicate": str,
            #    "value": str
            }, ignore_extra_keys=True)]
        },
        "full": {
            "results": [
            {
                "submodule_name": "Basic properties",
                "results": [
                    {
                        "submodule_section_header": "Hashes",
                        "submodule_section_content": {
                            "md5": schema.Regex(r'^[0-9a-z]{32}$'),
                            "sha1": schema.Regex(r'^[0-9a-z]{40}$'),
                            "sha256": schema.Regex(r'^[0-9a-z]{64}$'),
                            "ssdeep": schema.Regex(r'^[0-9A-Za-z:+/]*$'),
                        }
                    },
                    {
                        # We consume further structures submodule_sections and
                        # explicitly check the submodule_section_header to not
                        # be "Hashes" or it will accept "Hashes"-structures with
                        # malfarmed hashes.
                        "submodule_section_header": schema.And(str, lambda s: s != "Hashes"),
                        "submodule_section_content": schema.Schema({
                            }, ignore_extra_keys=True)
                    },
                ],
                "summary": {
                    "taxonomies": [schema.Schema({
                        "level": schema.Or("info", "malicious", "safe"),
                        "namespace": "FileInfo",
                    #    "predicate": str,
                    #    "value": str
                    }, ignore_extra_keys=True)]
                }
            }
            ]
        },
        "success": bool,
        "artifacts": CortexAnalyzerReport.report_schema_artifacts,
        "operations": []
    })

    def __init__(self, unvalidated_report=None):
        """
        @param report: hash with report data from Cortex FileInfo Analyzer
        """
        super().__init__(unvalidated_report)

        basic_properties = self.get_element_from_list_of_dicts(
                self.report.get('full', []).get('results', {}),
                'submodule_name', 'Basic properties').get('results', [])
        self._hashes = self.get_element_from_list_of_dicts(
                basic_properties, 'submodule_section_header', 'Hashes').get(
                    'submodule_section_content', {})

    @property
    def sha256sum(self):
        """ Return the sha256 sum. """
        return self._hashes.get('sha256')

    @property
    def md5sum(self):
        """ Return the md5 sum. """
        return self._hashes.get('md5')

    @property
    def ssdeepsum(self):
        """ Return the ssdeep sum. """
        # TODO: think about if we want to compare ssdeep hashes
        return self._hashes.get('ssdeep')


class FileInfoAnalyzer(CortexFileAnalyzer):
    """ Interfaces with Cortex Analyzer FileInfo_8_0. """
    name = 'FileInfo_8_0'
    reportclass = FileInfoAnalyzerReport


class HybridAnalysisReport(CortexAnalyzerReport):
    """ Represents a Cortex HybridAnalysis_GetReport_1_0 analysis JSON
        report. """
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
    report_schema = schema.Schema({
        "summary": {
            "taxonomies": [
                {
                    "level": schema.Or("info", "malicious", "safe"),
                    "namespace": "VT",
                    "predicate": str,
                    "value": schema.Regex(r'^[0-9/]*$')
                }
            ]
        },
        "full": {
            "response_code": int,
            "resource": str,
            "verbose_msg": str
        },
        "success": bool,
        "artifacts": CortexAnalyzerReport.report_schema_artifacts,
        "operations": []
    })

    def __init__(self, unvalidated_report):
        super().__init__(unvalidated_report)

        self.taxonomies_vt = self.get_element_from_list_of_dicts(
                self.report.get('summary', {}).get('taxonomies'),
                'namespace', 'VT', {}
            )

    @property
    def n_of_all(self):
        """ n of all Virusscanners at VirusTotal have rated this file as
            malicious. """
        return int(self.taxonomies_vt.get('value', '-1/0').split('/')[0])

    @property
    def level(self):
        """ safe, suspicious, malicious """
        return self.taxonomies_vt.get('level', None)


class VirusTotalQuery(CortexHashAnalyzer):
    """ Interfaces with Cortex Analyzer VirusTotal_GetReport_3_0. """
    name = 'VirusTotal_GetReport_3_0'
    reportclass = VirusTotalQueryReport


class CuckooSandboxFileAnalysisReport(CortexAnalyzerReport):
    """ Represents a Cortex CuckooSandbox_File_Analysis_Inet_1_2 analysis JSON
        report. """
    report_schema = schema.Schema({
        "summary": {
            "taxonomies": [schema.Or(
                {
                    "level": schema.Or("info", "malicious", "safe"),
                    "namespace": "Cuckoo",
                    "predicate": "Malscore",
                    "value": schema.Regex(r'^[0-9\./]*$')
                }, {
                    "level": schema.Or("info", "malicious", "safe"),
                    "namespace": "Cuckoo",
                    "predicate": "Malfamily",
                    "value": str,
                })
            ]
        },
        "full": schema.Schema({
            "signatures": schema.Schema([str]),
        }, ignore_extra_keys=True),
        "success": bool,
        "artifacts": CortexAnalyzerReport.report_schema_artifacts,
        "operations": []
    })

    def __init__(self, report):
        super().__init__(report)
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
        super().__init__(report)
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
        @param analyzer: Our analyzer object
        @type analyzer: CortexAnalyzer
        """
        self.__sample = sample
        self.__submission_time = datetime.datetime.now(datetime.timezone.utc)
        self.__analyzer = analyzer

    def is_older_than(self, seconds):
        """ Returns True if the difference between submission time and now,
        i.e. the age of the job, is larger than given number of seconds. """
        now = datetime.datetime.now(datetime.timezone.utc)
        max_age = datetime.timedelta(seconds=seconds)
        return now - self.__submission_time > max_age

    @property
    def sample(self):
        """ Returns the sample the job is analyzing. """
        return self.__sample

    @property
    def analyzer(self):
        """ Returns the analyzer used to analyse the sample. """
        return self.__analyzer


class PickyClientResponse(aiohttp.ClientResponse):
    """ A picky client response that only considers status 200 as ok. """
    @property
    def ok(self) -> bool:
        """ Accept only status 200 as ok because we expect all our requests to
        return that code. """
        return self.status == 200


def log_retry(retry_state):
    """ Log a warning message on retries of requests. """
    exception = retry_state.outcome.exception()
    wait = retry_state.next_action.sleep
    logger.log(logging.WARNING, "%s. Retrying in %.2f seconds.",
               exception, wait)


class Cortex:
    """ Interfaces with a Cortex installation via its REST API. """
    def __init__(self, job_queue, url="http://localhost:9001", tlp=tlp.AMBER,
                 api_token="", poll_interval=5, submit_original_filename=True,
                 max_job_age=900, retries=5, backoff=0.5):
        """ Initialize the object.

        @param job_queue: The job queue to use from now on
        @type job_queue: JobQueue object
        @param url: Where to reach the Cortex REST API
        @type url: string
        @param tlp: colour according to traffic light protocol
        @type tlp: tlp
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
        @param retries: Number of retries on API requests
        @type retries: int
        @param backoff: Backoff factor for urllib3
        @type backoff: float
        """
        self.job_queue = job_queue
        self.running_jobs = {}
        self.url = url
        self.tlp = tlp
        self.poll_interval = poll_interval
        self.submit_original_filename = submit_original_filename
        self.max_job_age = max_job_age

        self.retrier = tenacity.AsyncRetrying(
                stop=tenacity.stop_after_attempt(retries),
                wait=tenacity.wait_exponential(multiplier=backoff),
                retry=tenacity.retry_if_exception_type(aiohttp.ClientError),
                before_sleep=log_retry)

        headers = {"Authorization": f"Bearer {api_token}"}
        cookie_jar = aiohttp.DummyCookieJar()
        self.session = aiohttp.ClientSession(
            raise_for_status=True, response_class=PickyClientResponse,
            headers=headers, cookie_jar=cookie_jar)

        self.tracker = None

    async def register_running_job(self, job_id, job):
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
        if (job_id in self.running_jobs and
                self.running_jobs[job_id] is not job):
            logger.warning(
                '%d: A job with ID %s already registered as running '
                'for different sample %d will be marked failed',
                job.sample.id, job_id,
                self.running_jobs[job_id].sample.id)
            await self.resubmit_as_failed(job_id)

        self.running_jobs[job_id] = job

    def deregister_running_job(self, job_id):
        """ Deregister a running job by job id.

        @param job_id: Cortex job ID of the job do deregister.
        @type job_id: string
        @returns: Sample object of the job or None if job not found. """
        return self.running_jobs.pop(job_id, None)

    def deregister_running_job_if_too_old(self, job_id, max_age):
        """ Check if a job has gotten too old and remove it from the list of
        running jobs if so.

        @param job_id: Cortex job ID of the job do deregister.
        @type job_id: string
        @returns: Sample object of the job or None if job not found. """
        if self.running_jobs[job_id].is_older_than(max_age):
            return self.deregister_running_job(job_id)

        return None

    async def resubmit_with_analyzer_report(self, job_id, report):
        """ Resubmit a sample to the job queue after an analyzer report became
        available.

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

        try:
            # register this job's analysis report with our main report object
            job.sample.cortex_report.register_report(job.analyzer, report)
        except schema.SchemaError as error:
            logger.warning('Report returned from Cortex contained '
                           'invalid data: %s', error)
            job.sample.mark_cortex_failure()

        await self.job_queue.submit(job.sample)
        return None

    async def resubmit_as_failed(self, job_id):
        """ Resubmit a sample to the job queue with a failure report if the
        Cortex job has failed for some reason.

        @param job_id: ID of job that failed.
        @type job_id: string
        """
        job = self.deregister_running_job(job_id)
        if job is not None:
            job.sample.mark_cortex_failure()
            await self.job_queue.submit(job.sample)

    async def resubmit_as_failed_if_too_old(self, job_id, max_age):
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
            await self.job_queue.submit(job.sample)

    async def submit(self, sample, analyzer):
        """ Submit a sample to Cortex for analysis.
        @param sample: Sample to submit.
        @type sample: Sample

        @raises: CortexSubmitFailedException if submission failed
        @returns: ID of the submitted Cortex job.
        """
        request_url = urllib.parse.urljoin(
            self.url, '/api/analyzer/_search?range=0-1')
        query = {'query': {'_field': 'name', '_value': analyzer.name}}

        try:
            async for attempt in self.retrier:
                with attempt:
                    async with self.session.post(
                            request_url, json=query) as response:
                        # no check for status code here since we retry all but
                        # 200 responses and raise an exception if retries fail
                        analyzers = schema.Schema([{
                                'id': str,
                            }], ignore_extra_keys=True).validate(
                                await response.json())
        except (ValueError, schema.SchemaError) as error:
            raise CortexSubmitFailedException(
                'Invalid JSON in response when looking up analyzer '
                f'{analyzer.name}: {error}') from error
        except tenacity.RetryError as error:
            # retries expired
            raise CortexSubmitFailedException(
                f'Error looking up analyzer {analyzer.name}: '
                f'{error}') from error

        if not analyzers:
            raise CortexSubmitFailedException(
                f'Analyzer {analyzer.name} not found')

        if len(analyzers) > 1:
            raise CortexSubmitFailedException(
                f'Multiple analyzers found for {analyzer.name}')

        analyzer_id = analyzers[0]['id']
        request_url = urllib.parse.urljoin(
            self.url, f'/api/analyzer/{analyzer_id}/run')
        data, log_params = await analyzer.get_submit_parameters(
            sample, self.tlp, self.submit_original_filename)

        logger.debug("Creating Cortex job with analyzer %s and "
                     "parameters %s", analyzer.name, log_params)
        try:
            async for attempt in self.retrier:
                with attempt:
                    async with self.session.post(
                            request_url, data=data) as response:
                        job = schema.Schema({
                                'id': str,
                            }, ignore_extra_keys=True).validate(
                                await response.json())
        except (ValueError, schema.SchemaError) as error:
            raise CortexSubmitFailedException(
                f'Invalid JSON in response to job submit: {error}') from error
        except tenacity.RetryError as error:
            raise CortexSubmitFailedException(
                f'Error submitting Cortex job: {error}') from error

        job_id = job['id']
        await self.register_running_job(job_id, CortexJob(sample, analyzer))
        return job_id

    async def start_tracker(self):
        """ Start tracking running jobs in a separate thread. """
        self.tracker = asyncio.ensure_future(self.track())
        if hasattr(self.tracker, "set_name"):
            self.tracker.set_name("CortexJobTracker")
        return self.tracker

    async def track(self):
        """ Do the polling for finished jobs. """
        while True:
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
                # report is an extended version of job status, so we can
                # optimise the number of requests here
                request_url = urllib.parse.urljoin(
                    self.url, f'/api/job/{job_id}/report')
                try:
                    async for attempt in self.retrier:
                        with attempt:
                            async with self.session.get(
                                    request_url) as response:
                                json_resp = await response.json()
                                cortexjob = schema.Schema({
                                        'status': str,
                                        # only to make sure the key is there,
                                        # is status string while not finished,
                                        # dict afterwards
                                        'report': schema.Or(
                                            {}, str, ignore_extra_keys=True),
                                    }, ignore_extra_keys=True).validate(
                                        json_resp)
                except (ValueError, schema.SchemaError) as error:
                    logger.error('Invalid JSON in job status: %s', error)
                    continue
                except tenacity.RetryError as error:
                    logger.error('Querying Cortex job status failed: %s', error)
                    continue

                job_status = cortexjob['status']
                if job_status in ['Success']:
                    # pass original report element from json response for
                    # validation and storage
                    await self.resubmit_with_analyzer_report(
                        job_id, json_resp['report'])
                    continue

                if job_status in ['Failure', 'Deleted']:
                    logger.warning("Dropping job %s because it has failed "
                                   "in Cortex", job_id)
                    await self.resubmit_as_failed(job_id)
                    continue

                # drop jobs which have been running for too long. This is
                # mainly to prevent accumulation of jobs in our job list which
                # will never finish. We still want to wait for jobs to finish
                # even though our client might not be interested any more so
                # that we have the result cached for the next time we get the
                # same sample.
                await self.resubmit_as_failed_if_too_old(
                    job_id, self.max_job_age)

            await asyncio.sleep(self.poll_interval)

        logger.debug("Cortex job tracker shut down.")

    def shut_down(self):
        """ Request the module to shut down, used by the signal handler. """
        logger.debug("Cortex job tracker shutdown requested.")
        if self.tracker is not None:
            self.tracker.cancel()

    async def close_down(self):
        """ Close down tracker resources, particularly, wait for the task to
        terminate. """
        if self.tracker is not None:
            try:
                await self.tracker
            # we cancelled the task so a CancelledError is expected
            except asyncio.CancelledError:
                pass
            except Exception:
                logger.exception(
                    "Unexpected exception in Cortex job tracker")

        await self.session.close()
        logger.debug("Cortex job tracker shut down.")
