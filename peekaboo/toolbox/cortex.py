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


import logging
import time

from cortex4py.api import Api


logger = logging.getLogger(__name__)


class CortexReport():
    """ Meta class that joins Cortex analysis JSON report. """
    def __init__(self, sample=None):
        self.sample = sample

    @property
    def File_InfoReport(self):
        """ Triggers analysis and produces report on access """
        return File_InfoReport(File_Infotools(self.sample).analyse())

    @property
    def HybridAnalysisReport(self):
        """ Triggers analysis and produces report on access """
        return HybridAnalysisReport(
            HybridAnalysistools(self.sample).analyse())

    @property
    def VirusTotalQueryReport(self):
        """ Triggers analysis and produces report on access """
        return VirusTotal_QueryReport(
            VirusTotal_Querytools(self.sample).analyse())

    @property
    def CuckooSandboxFileReport(self):
        """ Triggers analysis and produces report on access """
        return CuckooSandbox_File_AnalysisReport(
            CuckooSandbox_File_Analysistools(self.sample).analyse()
        )


class Cortextools():
    """ Interfaces with a Cortex installation via its REST API. """
    def __init__(self, sample):
        self.sample = sample

        self.api = Api('http://host:9001', 'BEARERTOKEN')
        self.analyzers = self.api.analyzers.find_all({}, range='all')

    def get_report(self):
        return CortexReport(self.sample)


class File_Infotools(Cortextools):
    """ Interfaces with Cortex Analyzer FileInfo_6_0. """
    def analyse(self):
        """ Pass file to Cortex Analyzer and wait for report """
        if not self.sample:
            return {}
        job = self.api.analyzers.run_by_name('FileInfo_6_0', {
            'data': self.sample.file_path,
            'dataType': 'file',
            'tlp': 1
        }, force=1)
        report = "Waiting"
        while report in ('Waiting', 'Running'):
            logger.debug("State of File_Info report generation: %s", report)
            report = self.api.jobs.get_report(job.id).report
            time.sleep(5)
        return report


class File_InfoReport():
    """ Represents a Cortex FileInfo_6_0 analysis JSON report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
        self.report = report

    @property
    def full(self):
        return self.report.get('full', None)


class HybridAnalysistools(Cortextools):
    """ Interfaces with Cortex Analyzer HybridAnalysis_GetReport_1_0. """
    def analyse(self):
        """ Pass file to Cortex Analyzer and wait for report """
        if not self.sample:
            return {}
        job = self.api.analyzers.run_by_name('HybridAnalysis_GetReport_1_0', {
            'data': self.sample.file_path,
            'dataType': 'file',
            'tlp': 1,
            'parameters': {
                'filename': self.sample.name_declared,
            }
        }, force=1)
        report = "Waiting"
        while report in ('Waiting', 'Running'):
            logger.debug("State of HybridAnalysistools report generation: %s",
                         report)
            report = self.api.jobs.get_report(job.id).report
            time.sleep(5)
        return report


class HybridAnalysisReport():
    """ Represents a Cortex HybridAnalysis_GetReport_1_0 analysis JSON
        report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
        self.report = report

    @property
    def full(self):
        return self.report.get('full', None)


class VirusTotal_Querytools(Cortextools):
    """ Interfaces with Cortex Analyzer VirusTotal_GetReport_3_0. """
    def analyse(self):
        """ Pass file to Cortex Analyzer and wait for report """
        if not self.sample:
            return {}
        job = self.api.analyzers.run_by_name('VirusTotal_GetReport_3_0', {
            'data': self.sample.sha256sum,
            'dataType': 'hash',
            'tlp': 1,
        }, force=1)
        report = "Waiting"
        while report in ('Waiting', 'Running'):
            logger.debug("State of VirusTotal_querytools report generation: "
                         "%s", report)
            report = self.api.jobs.get_report(job.id).report
            time.sleep(5)
        return report


class VirusTotal_QueryReport():
    """ Represents a Cortex VirusTotal_GetReport_3_0 analysis JSON report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
        self.report = report
        self.taxonomies = report.get("summary", {}).get("taxonomies", [{}])[0]

    @property
    def n_of_all(self):
        """ n of all Virusscanners at VirusTotal have rated this file as
            malicious. """
        return int(self.taxonomies.get('value', '-1/0').split('/')[0])

    @property
    def level(self):
        " safe, suspicious, malicious"
        return self.taxonomies.get('level', None)


class CuckooSandbox_File_Analysistools(Cortextools):
    """ Interfaces with Cortex Analyzer CuckooSandbox_File_Analysis_Inet_1_2. """
    def analyse(self):
        """ Pass file to Cortex Analyzer and wait for report. """
        if not self.sample:
            return {}
        job = self.api.analyzers.run_by_name(
            'CuckooSandbox_File_Analysis_Inet_1_2', {
                'data': self.sample.file_path,
                'dataType': 'file',
                'tlp': 1,
                'parameters': {
                    'filename': self.sample.name_declared,
                }
            }, force=1)
        report = "Waiting"
        while report in ('Waiting', 'Running'):
            logger.debug("State of CuckooSandbox_File_Analysistools report "
                         "generation: %s", report)
            report = self.api.jobs.get_report(job.id).report
            time.sleep(5)
        return report


class CuckooSandbox_File_AnalysisReport():
    """ Represents a Cortex CuckooSandbox_File_Analysis_Inet_1_2 analysis JSON
        report. """
    def __init__(self, report=None):
        if report is None:
            report = {}
        self.report = report
        self.taxonomies = report.get("summary", {}).get("taxonomies", [{}])

    @property
    def signatures(self):
        """ Matched Cuckoo signatures. """
        return self.report.get('full', {}).get('Signatures', None)

    @property
    def malscore(self):
        """ Malscore n of 10 (might be bigger). """
        for t in self.taxonomies:
            if t.get('predicate') == 'Malscore':
                return float(t['value'])
        return -1
