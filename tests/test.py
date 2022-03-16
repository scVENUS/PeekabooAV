#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# test.py                                                                     #
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

""" The testsuite. """

import asyncio
import gettext
import sys
import os
import tempfile
import logging
import shutil
import schema
import unittest
from datetime import datetime, timedelta


# Add Peekaboo to PYTHONPATH
TESTSDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(TESTSDIR))

# pylint: disable=wrong-import-position
from peekaboo.exceptions import PeekabooConfigException, \
        PeekabooRulesetConfigError
from peekaboo.config import (
    PeekabooConfig, PeekabooConfigParser, PeekabooAnalyzerConfig)
from peekaboo.sample import Sample, JobState
from peekaboo.ruleset import RuleResult, Result
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.ruleset.rules import FileTypeOnWhitelistRule, \
        FileTypeOnGreylistRule, CuckooAnalysisFailedRule, \
        KnownRule, FileLargerThanRule, CuckooEvilSigRule, \
        CuckooScoreRule, RequestsEvilDomainRule, FinalRule, \
        OfficeMacroRule, OfficeMacroWithSuspiciousKeyword, \
        ExpressionRule
from peekaboo.ruleset.expressions import ExpressionParser, \
        IdentifierMissingException

from peekaboo.toolbox.cuckoo import CuckooReport
from peekaboo.toolbox.ole import Oletools
from peekaboo.toolbox.file import Filetools, FiletoolsReport
from peekaboo.toolbox.known import Knowntools, KnowntoolsReport
from peekaboo.db import PeekabooDatabase, PeekabooDatabaseError
from peekaboo.toolbox.cortex import CortexReport, VirusTotalQuery, \
        FileInfoAnalyzer, tlp
# pylint: enable=wrong-import-position


# unittest.IsolatedAsyncioTestCase exists only in Python 3.8+. Since earlier
# versions do not allow for easily overriding the test execution by subclassing
# we go the route of adding a decorator that handles asynchronous execution in
# those versions.
if sys.version_info[0] < 4 and sys.version_info[1] < 8:
    AsyncioTestCase = unittest.TestCase

    def asynctest(func):
        """ decorator executing async test through the loop """
        def wrapper(*args, **kwargs):
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(func(*args, **kwargs))

        return wrapper
else:
    AsyncioTestCase = unittest.IsolatedAsyncioTestCase

    def asynctest(func):
        """ no-op async test decorator """
        return func

class CreatingConfigMixIn:
    """ A class for adding config file creation logic to any other class. """
    def create_config(self, content):
        """ Create a configuration file with defined content and pass it to the
        parent constructor for parsing. """
        _, self.created_config_file = tempfile.mkstemp()
        with open(self.created_config_file, 'w') as file_desc:
            file_desc.write(content)

    def remove_config(self):
        """ Remove the configuration file we've created. """
        os.unlink(self.created_config_file)


class CreatingConfigParser(PeekabooConfigParser, CreatingConfigMixIn):
    """ A special kind of config parser that creates the configuration file
    with defined content. """
    def __init__(self, content=''):
        self.created_config_file = None
        self.create_config(content)
        super().__init__(self.created_config_file)

    def __del__(self):
        self.remove_config()


class TestConfigParser(unittest.TestCase):
    """ Test a configuration with all values different from the defaults. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingConfigParser('''#[rule0]

[rule1]
option1: foo
octal: 0717
option2.1: bar
option2.2: baz

[rules]
rule.1 : rule1
#rule.2 : rule2
rule.3 : rule3
''')

    def test_2_values(self):
        """ Test rule configuration values """
        with self.assertRaises(KeyError):
            self.config['rule0']
        self.assertEqual(self.config['rule1']['option1'], 'foo')
        self.assertEqual(self.config['rule1'].getoctal('octal'), 0o0717)
        self.assertEqual(self.config['rule1'].getlist('option2'),
                         ['bar', 'baz'])

    def test_3_type_mismatch(self):
        """ Test correct error is thrown if the option type is mismatched """
        config = '''[rule1]
option1: foo
option1.1: bar'''

        with self.assertRaisesRegex(
                PeekabooConfigException,
                'Option option1 in section rule1 is supposed to be a list but '
                'given as individual setting'):
            CreatingConfigParser(config).getlist('rule1', 'option1')

    def test_4_octal_mismatch(self):
        """ Test correct error is thrown if octal format is wrong """
        config = '''[section]
nonoctal1: 8
nonoctal2: deadbeef'''

        for nonoctal in ['nonoctal1', 'nonoctal2']:
            with self.assertRaisesRegex(
                    PeekabooConfigException,
                    'Invalid value for octal option %s in section section: '
                    % nonoctal):
                CreatingConfigParser(config).getoctal('section', nonoctal)


class CreatingPeekabooConfig(PeekabooConfig, CreatingConfigMixIn):
    """ A special kind of Peekaboo config that creates the configuration file
    with defined content. """
    def __init__(self, content=''):
        self.created_config_file = None
        self.create_config(content)
        super().__init__(self.created_config_file)

    def __del__(self):
        self.remove_config()


class TestDefaultConfig(unittest.TestCase):
    """ Test a configuration of all defaults. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingPeekabooConfig()

    def test_1_default_settings(self):
        """ Test a configuration with just defaults """
        self.assertEqual(
            self.config.config_file, self.config.created_config_file)
        self.assertEqual(self.config.user, 'peekaboo')
        self.assertEqual(self.config.group, None)
        self.assertEqual(self.config.host, '127.0.0.1')
        self.assertEqual(self.config.port, 8100)
        self.assertEqual(self.config.pid_file, None)
        self.assertEqual(self.config.worker_count, 3)
        self.assertEqual(
            self.config.processing_info_dir,
            '/var/lib/peekaboo/malware_reports')
        self.assertEqual(
            self.config.ruleset_config, '/opt/peekaboo/etc/ruleset.conf')
        self.assertEqual(self.config.log_level, logging.INFO)
        self.assertEqual(
            self.config.log_format, '%(asctime)s - %(name)s - '
            '(%(threadName)s) - %(levelname)s - %(message)s')
        self.assertEqual(self.config.db_url, 'sqlite:////var/lib/peekaboo/peekaboo.db')
        self.assertEqual(self.config.db_async_driver, None)
        self.assertEqual(self.config.db_log_level, logging.WARNING)
        self.assertEqual(self.config.cluster_instance_id, 0)
        self.assertEqual(self.config.cluster_stale_in_flight_threshold, 15*60)
        self.assertEqual(self.config.cluster_duplicate_check_interval, 60)


class TestValidConfig(unittest.TestCase):
    """ Test a configuration with all values different from the defaults. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingPeekabooConfig('''[global]
user             :    user1
group            :    group1
host: 192.168.2.3
port: 8200
pid_file         :    /pid/1
worker_count     :    18
processing_info_dir : /var/3

[ruleset]
config           :    /rules/1

[logging]
log_level        :    DEBUG
log_format       :    format%%(foo1)s

[db]
url              :    sqlite:////peekaboo.db1
async_driver     :    async
log_level        :    INFO

[cluster]
instance_id: 12
stale_in_flight_threshold: 31
duplicate_check_interval: 61
''')

    def test_1_read_settings(self):
        """ Test reading of configuration settings from file """
        self.assertEqual(
            self.config.config_file, self.config.created_config_file)
        self.assertEqual(self.config.user, 'user1')
        self.assertEqual(self.config.group, 'group1')
        self.assertEqual(self.config.host, '192.168.2.3')
        self.assertEqual(self.config.port, 8200)
        self.assertEqual(self.config.pid_file, '/pid/1')
        self.assertEqual(self.config.worker_count, 18)
        self.assertEqual(self.config.processing_info_dir, '/var/3')
        self.assertEqual(self.config.ruleset_config, '/rules/1')
        self.assertEqual(self.config.log_level, logging.DEBUG)
        self.assertEqual(self.config.log_format, 'format%(foo1)s')
        self.assertEqual(self.config.db_url, 'sqlite:////peekaboo.db1')
        self.assertEqual(self.config.db_async_driver, 'async')
        self.assertEqual(self.config.db_log_level, logging.INFO)
        self.assertEqual(self.config.cluster_instance_id, 12)
        self.assertEqual(self.config.cluster_stale_in_flight_threshold, 31)
        self.assertEqual(self.config.cluster_duplicate_check_interval, 61)


class TestInvalidConfig(unittest.TestCase):
    """ Various tests of invalid config files. """
    def test_1_section_header(self):
        """ Test correct error is thrown if section header syntax is wrong """
        with self.assertRaisesRegex(
                PeekabooConfigException,
                'Configuration file ".*" can not be parsed: File contains no '
                'section headers'):
            CreatingPeekabooConfig('''[global[
user: peekaboo''')

    def test_2_value_separator(self):
        """ Test correct error is thrown if the value separator is wrong """
        with self.assertRaisesRegex(
                PeekabooConfigException,
                'Configuration file ".*" can not be parsed: (File|Source) '
                'contains parsing errors:'):
            CreatingPeekabooConfig('''[global]
user; peekaboo''')

    def test_3_section_header(self):
        """ Test correct error is thrown if the config file is missing """
        _, config_file = tempfile.mkstemp()
        os.unlink(config_file)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                'Configuration file "%s" can not be opened for reading: '
                r'\[Errno 2\] No such file or directory' % config_file):
            PeekabooConfig(config_file)

    def test_4_unknown_section(self):
        """ Test correct error is thrown if an unknown section name is given.
        """
        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown section\(s\) found in config: globl'):
            CreatingPeekabooConfig('''[globl]''')

    def test_5_unknown_option(self):
        """ Test correct error is thrown if an unknown option name is given.
        """
        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section global: foo'):
            CreatingPeekabooConfig('''[global]
foo: bar''')

    def test_6_unknown_loglevel(self):
        """ Test with an unknown log level """
        with self.assertRaisesRegex(
                PeekabooConfigException,
                'Unknown log level FOO'):
            CreatingPeekabooConfig('''[logging]
log_level: FOO''')


class CreatingAnalyzerConfig(PeekabooAnalyzerConfig, CreatingConfigMixIn):
    """ A special kind of analyzer config that creates the configuration file
    with defined content. """
    def __init__(self, content=''):
        self.created_config_file = None
        self.create_config(content)
        super().__init__(self.created_config_file)

    def __del__(self):
        self.remove_config()


class TestDefaultAnalyzerConfig(unittest.TestCase):
    """ Test a configuration of all defaults. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingAnalyzerConfig()

    def test_1_default_settings(self):
        """ Test a configuration with just defaults """
        self.assertEqual(self.config.cuckoo_url, 'http://127.0.0.1:8090')
        self.assertEqual(self.config.cuckoo_poll_interval, 5)
        self.assertEqual(self.config.cuckoo_submit_original_filename, True)
        self.assertEqual(self.config.cuckoo_maximum_job_age, 900)
        self.assertEqual(self.config.cuckoo_api_token, '')
        self.assertEqual(self.config.cortex_url, 'http://127.0.0.1:9001')
        self.assertEqual(self.config.cortex_tlp, tlp.AMBER)
        self.assertEqual(self.config.cortex_poll_interval, 5)
        self.assertEqual(self.config.cortex_submit_original_filename, True)
        self.assertEqual(self.config.cortex_maximum_job_age, 900)
        self.assertEqual(self.config.cortex_api_token, '')


class TestValidAnalyzerConfig(unittest.TestCase):
    """ Test a configuration with all values different from the defaults. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingAnalyzerConfig('''[cuckoo]
url: http://api:1111
poll_interval: 51
submit_original_filename: no
maximum_job_age: 900
api_token: tok

[cortex]
url: http://api:2222
tlp: gReEn
poll_interval: 57
submit_original_filename: yes
maximum_job_age: 905
api_token: tok2''')

    def test_1_read_settings(self):
        """ Test reading of configuration settings from file """
        self.assertEqual(self.config.cuckoo_url, 'http://api:1111')
        self.assertEqual(self.config.cuckoo_poll_interval, 51)
        self.assertEqual(self.config.cuckoo_submit_original_filename, False)
        self.assertEqual(self.config.cuckoo_maximum_job_age, 900)
        self.assertEqual(self.config.cuckoo_api_token, 'tok')

        self.assertEqual(self.config.cortex_url, 'http://api:2222')
        self.assertEqual(self.config.cortex_tlp, tlp.GREEN)
        self.assertEqual(self.config.cortex_poll_interval, 57)
        self.assertEqual(self.config.cortex_submit_original_filename, True)
        self.assertEqual(self.config.cortex_maximum_job_age, 905)
        self.assertEqual(self.config.cortex_api_token, 'tok2')


class TestDatabase(AsyncioTestCase):
    """ Unittests for Peekaboo's database module. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = CreatingPeekabooConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db,
                                      instance_id=1,
                                      stale_in_flight_threshold=10)
        cls.no_cluster_db = PeekabooDatabase('sqlite:///' + cls.test_db,
                                             instance_id=0)
        cls.sample = Sample(b'test', 'test.py')
        result = RuleResult('Unittest',
                            Result.good,
                            'This is just a test case.',
                            further_analysis=False)
        cls.sample.add_rule_result(result)

    @asynctest
    async def test_1_analysis_add(self):
        """ Test adding a new analysis. """
        await self.db_con.analysis_add(self.sample)
        # sample now contains a job ID

    def test_2_analysis_update(self):
        """ Test updating of analysis results. """
        # mark sample done so journal and result retrieval tests can work
        self.sample.mark_done()
        self.db_con.analysis_update(self.sample)

    @asynctest
    async def test_3_analysis_journal_fetch_journal(self):
        """ Test retrieval of analysis results. """
        await self.db_con.analysis_add(self.sample)
        # sample now contains another, new job ID
        # mark sample done so journal and result retrieval tests can work
        self.sample.mark_done()
        self.db_con.analysis_update(self.sample)

        # add a failed analysis to check that it is ignored
        result = RuleResult('Unittest',
                            Result.failed,
                            'This is just a test case.',
                            further_analysis=False)
        self.sample.add_rule_result(result)
        await self.db_con.analysis_add(self.sample)
        self.sample.mark_done()
        self.db_con.analysis_update(self.sample)

        # reset the job id so this sample is not ignored when fetching the
        # journal
        self.sample.update_id(None)

        journal = self.db_con.analysis_journal_fetch_journal(self.sample)
        self.assertEqual(journal[0].result, Result.good)
        self.assertEqual(journal[0].reason, 'This is just a test case.')
        self.assertIsNotNone(journal[0].analysis_time)
        self.assertEqual(journal[1].result, Result.good)
        self.assertEqual(journal[1].reason, 'This is just a test case.')
        self.assertIsNotNone(journal[1].analysis_time)
        self.assertNotEqual(journal[0].analysis_time, journal[1].analysis_time)
        # does not contain the failed result
        self.assertEqual(len(journal), 2)

    @asynctest
    async def test_4_analysis_retrieve(self):
        """ Test retrieval of analysis results. """
        await self.db_con.analysis_add(self.sample)
        # sample now contains a job ID
        reason, result = await self.db_con.analysis_retrieve(self.sample.id)
        # does not ignore failed analyses like the journal above
        self.assertEqual(result, Result.failed)
        self.assertEqual(reason, 'This is just a test case.')

    def test_5_in_flight_no_cluster(self):
        """ Test that marking of samples as in-flight on a non-cluster-enabled
        database are no-ops. """
        self.assertTrue(self.no_cluster_db.mark_sample_in_flight(self.sample))
        self.assertTrue(self.no_cluster_db.mark_sample_in_flight(self.sample))
        self.assertIsNone(self.no_cluster_db.clear_sample_in_flight(self.sample))
        self.assertIsNone(self.no_cluster_db.clear_sample_in_flight(self.sample))
        self.assertIsNone(self.no_cluster_db.clear_in_flight_samples())

    def test_6_in_flight_cluster(self):
        """ Test marking of samples as in-flight. """
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        # re-locking the same sample should fail
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertIsNone(self.db_con.clear_sample_in_flight(self.sample, 1))
        # unlocking twice should fail
        self.assertRaisesRegex(
            PeekabooDatabaseError, "Unexpected inconsistency: Sample not "
            "recorded as in-flight upon clearing flag",
            self.db_con.clear_sample_in_flight, self.sample, 1)

    def test_7_in_flight_clear(self):
        """ Test clearing of in-flight markers. """
        sample2 = Sample(b'foo', 'foo.pyc')
        sample3 = Sample(b'bar', 'bar.pyc')

        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample3, 2))

        # should only clear samples of instance 1
        self.assertIsNone(self.db_con.clear_in_flight_samples(1))
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample3, 2))

        # should only clear samples of instance 2
        self.assertIsNone(self.db_con.clear_in_flight_samples(2))
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample3, 2))

        # should clear all samples
        self.assertIsNone(self.db_con.clear_in_flight_samples(-1))
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample3, 2))

        # should be a no-op because there will never be any entries of instance
        # 0
        self.assertIsNone(self.db_con.clear_in_flight_samples(0))
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample3, 2))

        # should be a no-op because this database is not cluster-enabled
        self.assertIsNone(self.no_cluster_db.clear_in_flight_samples())
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample3, 2))

        # leave as found
        self.assertIsNone(self.db_con.clear_in_flight_samples(-1))

    def test_8_stale_in_flight(self):
        """ Test the cleaning of stale in-flight markers. """
        stale = datetime.utcnow() - timedelta(seconds=20)
        self.assertTrue(self.db_con.mark_sample_in_flight(
            self.sample, 1, stale))
        sample2 = Sample(b'baz', 'baz.pyc')
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1))

        # should not clear anything because the database is not cluster-enabled
        self.assertTrue(self.no_cluster_db.clear_stale_in_flight_samples())
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))

        # should clear sample marker because it is stale but not sample2
        self.assertTrue(self.db_con.clear_stale_in_flight_samples())
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))

        # should not clear anything because all markers are fresh
        self.assertFalse(self.db_con.clear_stale_in_flight_samples())
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))

        # set up new constellation
        self.assertIsNone(self.db_con.clear_in_flight_samples(-1))
        self.assertTrue(self.db_con.mark_sample_in_flight(
            self.sample, 1, stale))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1, stale))

        # should clear all markers because all are stale
        self.assertTrue(self.db_con.clear_stale_in_flight_samples())
        self.assertTrue(self.db_con.mark_sample_in_flight(
            self.sample, 1, stale))
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1, stale))

        # leave as found
        self.assertTrue(self.db_con.clear_stale_in_flight_samples())

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        os.unlink(cls.test_db)


class TestSample(unittest.TestCase):
    """ Unittests for Samples. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = CreatingPeekabooConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.sample = Sample(
            b'test', 'test.py', 'text/x-python', 'inline', 'dump', 11)

    def test_3_sample_attributes(self):
        """ Test the various sample attribute getters. """
        self.assertEqual(self.sample.content, b'test')
        self.assertEqual(self.sample.filename, 'test.py')
        self.assertEqual(self.sample.name_declared, 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertEqual(self.sample.type_declared, 'text/x-python')
        self.assertEqual(
            self.sample.sha256sum,
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
        self.assertEqual(self.sample.result, Result.unchecked)
        self.assertEqual(self.sample.reason, None)
        self.assertRegex(
            self.sample.peekaboo_report[0],
            'File "%s" is considered "unchecked"'
            % self.sample.filename)
        self.assertEqual(self.sample.cuckoo_report, None)
        self.assertEqual(self.sample.state, JobState.ACCEPTED)
        self.assertEqual(self.sample.file_size, 4)

    def test_5_mark_done(self):
        """ Test the marking of a sample as done. """
        self.sample.mark_done()
        self.assertEqual(self.sample.state, JobState.FINISHED)

    def test_6_add_rule_result(self):
        """ Test the adding of a rule result. """
        reason = 'This is just a test case.'
        result = RuleResult('Unittest', Result.failed,
                            reason,
                            further_analysis=False)
        self.sample.add_rule_result(result)
        self.assertEqual(self.sample.result, Result.failed)
        self.assertEqual(self.sample.reason, reason)

    def test_sample_without_suffix(self):
        """ Test extraction of file extension from declared name. """
        sample = Sample(None, 'Report.docx')
        self.assertEqual(sample.file_extension, 'docx')
        sample = Sample(None, 'Report')
        self.assertEqual(sample.file_extension, '')
        sample = Sample(None, None)
        self.assertEqual(sample.file_extension, None)

    def test_sample_extension_multiple_dots(self):
        """ Test file extension with name containing multiple dots. """
        sample = Sample(None, 'junk..ext')
        self.assertEqual(sample.file_extension, 'ext')

    def test_sample_extension_filtering(self):
        """ Test filtering of invalid file extensions. """
        testcases = [
            # extension, accepted
            ['docx', True],
            ['docx$', True],
            ['docx~', True],
            ['docx_', True],
            ['foo1', True],
            ['foo1%', True],
            ['foo 1', False],
            ['fü', False],
            ['foo&resize=600,510', False],
            ['foo;param=5', False],
            ['foo?query=value', False],
        ]

        for ext, accepted in testcases:
            sample = Sample(None, 'junk.' + ext)
            self.assertEqual(
                sample.file_extension is not None,
                accepted,
                "File extension filtering for %s" % ext)

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        os.unlink(cls.test_db)


class FileSample(Sample):
    """ A sample that reads its content from a file. """
    def __init__(self, file_path, *args, **kwargs):
        with open(file_path, 'rb') as sample_file:
            content = sample_file.read()

        # inject a derived filename into kwargs if none is supplied in args or
        # kwargs, filename will be element 0 of args (and its length will be 1)
        # if supplied because self and file_path of this routine will have
        # consumed the two leading positional arguments
        if len(args) < 1 and kwargs.get('filename') is None:
            kwargs['filename'] = os.path.basename(file_path)

        super().__init__(content, *args, **kwargs)


class TestOletools(unittest.TestCase):
    """ Unittests for Oletools. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.office_data_dir = os.path.join(TESTSDIR, "test-data", "office")

    def test_analysis(self):
        """ Test Oletools analysis. """
        cases = [
            # file name, , vba code, , detected autoexec, , detected suspicious
            #     , has macros, , has autoexec, , is suspicious,
            ['blank.doc', False, r'^$', False, r'^\[\]$', False, r'^\[\]$'],
            ['CheckVM.xls', True, r'^Private Sub Workbook_Open\(\)',
                True, r'''^\[.*\('Workbook_Open', 'Runs when''',
                True, r'''^\[.*\('GetObject', 'May get an'''],
        ]
        for file_name, expected_has_office_macros, expected_vba_code, \
                expected_has_autoexec, expected_detected_autoexec, \
                expected_is_suspicious, expected_detected_suspicious in cases:
            file_path = os.path.join(self.office_data_dir, file_name)
            report = Oletools(FileSample(file_path)).get_report()
            self.assertEqual(
                report.has_office_macros, expected_has_office_macros,
                "Oletools has_office_macros: %s" % file_name)
            self.assertRegex(
                report.vba_code, expected_vba_code,
                "Oletools expected_vba_code: %s" % file_name)
            self.assertEqual(
                report.has_autoexec, expected_has_autoexec,
                "Oletools has_autoexec: %s" % file_name)
            self.assertRegex(
                report.detected_autoexec, expected_detected_autoexec,
                "Oletools detected_autoexec: %s" % file_name)
            self.assertEqual(
                report.is_suspicious, expected_is_suspicious,
                "Oletools is_suspicious: %s" % file_name)
            self.assertRegex(
                report.detected_suspicious, expected_detected_suspicious,
                "Oletools detected_autoexec: %s" % file_name)

    def test_caching(self):
        """ Test Oletools report caching in the sample. """
        report = object()
        sample = Sample(None)
        sample.register_oletools_report(report)
        new_report = Oletools(sample).get_report()
        self.assertIs(report, new_report)


class TestFiletools(unittest.TestCase):
    """ Unittests for Oletools. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.tests_data_dir = os.path.join(TESTSDIR, "test-data")
        cls.office_data_dir = os.path.join(cls.tests_data_dir, "office")

    def test_analysis(self):
        """ Test Filetools analysis. """
        textfile = os.path.join(self.tests_data_dir, 'textfile')
        blank_doc = os.path.join(self.office_data_dir, 'blank.doc')
        cases = [
            # file path,       , type by content,  , type as text
            #        , file name,              , type by name,
            # a file without file extension
            [textfile, 'textfile', 'text/plain', None, 'ASCII text'],
            # a file with file extension
            [textfile, 'textfile.txt', 'text/plain', 'text/plain',
                'ASCII text'],
            # a file with a file extension that belies its actual content
            [textfile, 'textfile.py', 'text/plain', 'text/x-python',
                'ASCII text'],
            # a word document - just because we can
            # interesting conundrum here: magic output depends on local timezone
            [blank_doc, blank_doc,
             'application/msword', 'application/msword',
             '^Composite Document File V2 Document, '
             'Little Endian, Os: MacOS, Version 14.10, Code page: 10000, '
             'Author: Microsoft Office User, Template: Normal.dotm, Last '
             'Saved By: Microsoft Office User, Revision Number: 2, Name of '
             'Creating Application: Microsoft Office Word, Create '
             'Time/Date: Fri Jun  7 [0-2][0-9]:55:00 2019, Last Saved '
             'Time/Date: Tue Jun 25 [0-2][0-9]:07:00 2019, Number of Pages: '
             '1, Number of Words: 0, Number of Characters: 0, Security: 0$'],
        ]
        for sample_path, file_name, expected_type_by_content, \
                expected_type_by_name, expected_type_as_text in cases:
            sample = FileSample(sample_path, file_name)
            report = Filetools(sample).get_report()
            self.assertEqual(
                report.type_by_content, expected_type_by_content,
                "Filetools type_by_content: %s" % file_name)
            self.assertEqual(
                report.type_by_name, expected_type_by_name,
                "Filetools type_by_name: %s" % file_name)
            self.assertRegex(
                report.type_as_text, expected_type_as_text,
                "Filetools type_as_text: %s" % file_name)

    def test_caching(self):
        """ Test Filetools report caching in the sample. """
        report = object()
        sample = Sample(None)
        sample.register_filetools_report(report)
        new_report = Filetools(sample).get_report()
        self.assertIs(report, new_report)


class TestCuckoo(unittest.TestCase):
    """ Unittests for the Cuckoo analyzer. """
    def test_report(self):
        """ Test that the report is accepted and correct values returned by the
        properties. """
        report = {
            "network": {
                "dns": [
                    {"request": "dom1"},
                    {"request": "dom2"},
                ],
                "apples": tuple([7]),
            },
            "signatures": (
                {"description": "desc1", "pears": [1]},
                {"description": "desc2"}
            ),
            "info": {
                "score": 1.1,
                "oranges": {"count": 10},
            },
            "debug": {
                "errors": ["error1", "error2"],
                "cuckoo": ("msg1", "msg2"),
                "peaches": "none",
            },
            "bananas": 5,
        }

        cuckooreport = CuckooReport(report, "some://where")
        self.assertEqual(cuckooreport.requested_domains[0], "dom1")
        self.assertEqual(cuckooreport.requested_domains[1], "dom2")
        self.assertEqual(cuckooreport.signature_descriptions[0], "desc1")
        self.assertEqual(cuckooreport.signature_descriptions[1], "desc2")
        self.assertEqual(cuckooreport.score, 1.1)
        self.assertEqual(cuckooreport.errors[0], "error1")
        self.assertEqual(cuckooreport.errors[1], "error2")
        self.assertEqual(cuckooreport.server_messages[0], "msg1")
        self.assertEqual(cuckooreport.server_messages[1], "msg2")
        self.assertEqual(cuckooreport.url, "some://where")

    def test_report_dumping(self):
        """ Test that a dump of a report matches the input. """
        url = "some://where"
        report = {
            "x-peekaboo": {"origin-url": url},
            "network": {
                "dns": [
                    {"request": "dom1"},
                    {"request": "dom2"},
                ]
            },
            "signatures": [
                {"description": "desc1"},
                {"description": "desc2"}
            ],
            "info": {
                "score": 1.1,
            },
            "debug": {
                "errors": ["error1", "error2"],
                "cuckoo": ["msg1", "msg2"],
            }
        }

        cuckooreport = CuckooReport(report, url)
        self.assertEqual(cuckooreport.dump, report)

    def test_invalid_report(self):
        """ Test that invalid report values are rejected. """
        with self.assertRaisesRegex(schema.SchemaError, r'\[\].*dict'):
            CuckooReport([])

        # schema errors are multi-line (?m), so we need to make dot match
        # whitspace as well (?s)
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)network.*'dict'"):
            CuckooReport({"network": []})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)network.*dns.*'list'.*'tuple'"):
            CuckooReport({"network": {"dns": {}}})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)network.*dns.*'dict'"):
            CuckooReport({"network": {"dns": [[]]}})
        with self.assertRaisesRegex(
                schema.SchemaError,
                r"(?ms)network.*dns.*Missing key.*'request'"):
            CuckooReport({"network": {"dns": [{"not-request": 1}]}})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)network.*dns.*request.*'str'"):
            CuckooReport({"network": {"dns": [{"request": 1}]}})

        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)signatures.*'list'.*'tuple'"):
            CuckooReport({"signatures": {}})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)signatures.*'dict'"):
            CuckooReport({"signatures": [1]})
        with self.assertRaisesRegex(
                schema.SchemaError,
                r"(?ms)signatures.*Missing key.*'description'"):
            CuckooReport({"signatures": [{"not-description": 1}]})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)signatures.*description.*'str'"):
            CuckooReport({"signatures": [{"description": 1}]})

        with self.assertRaisesRegex(schema.SchemaError, r"(?ms)info.*'dict'"):
            CuckooReport({"info": 1})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)score.*'int'.*'float'"):
            CuckooReport({"info": {"score": "onepointtwo"}})

        with self.assertRaisesRegex(schema.SchemaError, r"(?ms)debug.*'dict'"):
            CuckooReport({"debug": 1})
        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)errors.*'list'.*'tuple'"):
            CuckooReport({"debug": {"errors": {}}})
        with self.assertRaisesRegex(schema.SchemaError, r"(?ms)errors.*'str'"):
            CuckooReport({"debug": {"errors": [1]}})

        with self.assertRaisesRegex(
                schema.SchemaError, r"(?ms)cuckoo.*'list'.*'tuple'"):
            CuckooReport({"debug": {"cuckoo": {}}})
        with self.assertRaisesRegex(schema.SchemaError, r"(?ms)cuckoo.*'str'"):
            CuckooReport({"debug": {"cuckoo": [1]}})


class TestRulesetEngine(unittest.TestCase):
    """ Unittests for the Ruleset Engine. """
    def test_no_rules_configured(self):
        """ Test that correct error is shown if no rules are configured. """
        config = CreatingConfigParser()
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'No enabled rules found, check ruleset config.'):
            RulesetEngine(config, None, None, None).start()

    def test_unknown_rule_enabled(self):
        """ Test that correct error is shown if an unknown rule is enabled. """
        config = CreatingConfigParser('''[rules]
rule.1: foo''')
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'Unknown rule\(s\) enabled: foo'):
            RulesetEngine(config, None, None, None).start()

    def test_invalid_type(self):
        """ Test that correct error is shown if rule config option has wrong
        type. """

        config = CreatingConfigParser('''[rules]
rule.1: cuckoo_score

[cuckoo_score]
higher_than: foo''')
        with self.assertRaisesRegex(
                ValueError,
                r"could not convert string to float: '?foo'?"):
            RulesetEngine(config, None, None, None).start()

    def test_disabled_config(self):
        """ Test that no error is shown if disabled rule has config. """

        config = CreatingConfigParser('''[rules]
rule.1: known
#rule.2: cuckoo_score

[cuckoo_score]
higher_than: 4.0''')
        RulesetEngine(config, None, None, None).start()


class MimetypeSample:  # pylint: disable=too-few-public-methods
    """ A dummy sample class that only contains a set of MIME types for testing
    whitelist and greylist rules with it. """
    def __init__(self, types):
        # don't even need to make it a property
        self.type_declared = None
        self.filetools_report = FiletoolsReport(types)


class CuckooReportSample:  # pylint: disable=too-few-public-methods
    """ A dummy sample that only contains a configurable cuckoo report. """
    def __init__(self, report, failed=False):
        self.cuckoo_report = CuckooReport(report)
        self.cuckoo_failed = failed


class TestRules(AsyncioTestCase):
    """ Unittests for Rules. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config = CreatingConfigParser('''[file_type_on_whitelist]
whitelist.1 : text/plain

[file_type_on_greylist]
greylist.1 : application/x-dosexec
greylist.2 : application/zip
greylist.3 : application/msword

[cuckoo_analysis_failed]
failure.1: end of analysis reached!
success.1: analysis completed successfully''')

        cls.tests_data_dir = os.path.join(TESTSDIR, "test-data")
        cls.office_data_dir = os.path.join(cls.tests_data_dir, 'office')

    def test_config_known(self):  # pylint: disable=no-self-use
        """ Test the known rule configuration. """
        config = '''[known]
unknown : baz'''
        # there is no exception here since empty config is acceptable
        KnownRule(CreatingConfigParser(), None)
        # there is no exception here since the known rule simply does
        # not look at the configuration at all - maybe we should have a
        # 'unknown section' error here
        KnownRule(CreatingConfigParser(config), None)

    def test_config_file_larger_than(self):
        """ Test the file larger than rule configuration. """
        config = '''[file_larger_than]
bytes : 10
unknown : baz'''
        # there is no exception here since empty config is acceptable
        FileLargerThanRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_larger_than: unknown'):
            FileLargerThanRule(CreatingConfigParser(config), None)

    def test_rule_file_type_on_whitelist(self):
        """ Test whitelist rule. """
        combinations = [
            [False, {'type_by_content': 'text/plain'}],
            [True, {'type_by_content': 'application/vnd.ms-excel'}],
            [True, {
                'type_by_content': 'text/plain',
                'type_by_name': 'application/vnd.ms-excel'
            }],
            [True, {
                'type_by_content': 'image/png',
                'type_by_name': 'application/zip'
            }],
            [True, {'type_by_content': '', 'type_by_name': 'asdfjkl'}],
            [True, {'type_by_content':  None}]
        ]
        rule = FileTypeOnWhitelistRule(self.config, None)
        for expected, types in combinations:
            result = rule.evaluate(MimetypeSample(types))
            self.assertEqual(result.further_analysis, expected,
                             "FiletoolsReport: %s" % types)

    def test_rule_office_ole(self):
        """ Test rule office_ole. """
        config = '''[office_macro_with_suspicious_keyword]
            keyword.1 : AutoOpen
            keyword.2 : AutoClose
            keyword.3 : suSPi.ious'''

        parsed_config = CreatingConfigParser(config)

        # test if macro with suspicious keyword
        combinations = [
            # no office document file extension
            [Result.unknown, Sample(b'test', 'test.nodoc')],
            # test with empty file
            [Result.unknown, FileSample(os.path.join(
                self.office_data_dir, 'empty.doc'))],
            # office document with 'suspicious' in macro code
            [Result.bad, FileSample(os.path.join(
                self.office_data_dir, 'suspiciousMacro.doc'))],
            # test with blank word doc
            [Result.unknown, FileSample(os.path.join(
                self.office_data_dir, 'blank.doc'))],
            # test with legitimate macro
            [Result.unknown, FileSample(os.path.join(
                self.office_data_dir, 'legitmacro.xls'))]
        ]
        rule = OfficeMacroWithSuspiciousKeyword(parsed_config, None)
        for expected, sample in combinations:
            result = rule.evaluate(sample)
            self.assertEqual(result.result, expected)

        # test if macro present
        combinations = [
            # no office document file extension
            [Result.unknown, Sample(b'test', 'test.nodoc')],
            # test with empty file
            [Result.unknown, FileSample(os.path.join(
                self.office_data_dir, 'empty.doc'))],
            # office document with 'suspicious' in macro code
            [Result.bad, FileSample(os.path.join(
                self.office_data_dir, 'suspiciousMacro.doc'))],
            # test with blank word doc
            [Result.unknown, FileSample(os.path.join(
                self.office_data_dir, 'blank.doc'))],
            # test with legitimate macro
            [Result.bad, FileSample(os.path.join(
                self.office_data_dir, 'legitmacro.xls'))]
        ]
        rule = OfficeMacroRule(parsed_config, None)
        for expected, sample in combinations:
            result = rule.evaluate(sample)
            self.assertEqual(result.result, expected)

    def test_rule_ignore_generic_whitelist(self):
        """ Test rule to ignore file types on whitelist. """
        config = '''[expressions]
            expression.4: {sample.type_declared}|filereport.mime_types <= {
                              'text/plain', 'inode/x-empty', 'image/jpeg'
                          } -> ignore
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        sample = Sample(b'abc', 'file.txt')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = Sample(b'<html', 'file.html')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # bzip2 compressed data
        sample = Sample(b'BZh91AY=', 'file.txt')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

    def test_rule_ignore_no_name_declared(self):
        """ Test rule to ignore file with no name_declared. """
        config = '''[expressions]
            expression.3  : not sample.name_declared -> ignore
        '''

        sample_kwargs = {
            'content_type': 'image/gif',
        }

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        sample = Sample(b'GIF87...', 'file1.gif', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(b'GIF87...')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        config = '''[expressions]
            expression.3  : sample.name_declared is None -> ignore
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        sample = Sample(b'GIF87...')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

    def test_rule_ignore_mail_signatures(self):
        """ Test rule to ignore cryptographic mail signatures. """
        config = '''[expressions]
            expression.1  : sample.name_declared == /smime.p7[mcs]/
                and sample.type_declared in {
                    'application/pkcs7-signature',
                    'application/x-pkcs7-signature',
                    'application/pkcs7-mime',
                    'application/x-pkcs7-mime'
                } -> ignore
            expression.2  : sample.name_declared == 'signature.asc'
                and sample.type_declared in {
                    'application/pgp-signature'
                } -> ignore
            '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        sample = Sample(None, 'file.1')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # test smime signatures
        sample_kwargs = {
            'content_type': 'application/pkcs7-signature'
        }

        sample = Sample(None, filename='smime.p7s', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = Sample(None, filename='asmime.p7s', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(None, filename='smime.p7m', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = Sample(None, filename='smime.p7o', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(None, filename='smime.p7', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(None, filename='smime.p7sm', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(None, filename='file', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # test gpg signatures
        # test with wrong content type
        sample = Sample(None, filename='signature.asc', **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = Sample(None, filename='signature.asc',
                        content_type="application/pgp-signature")
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

    def test_rule_expressions(self):
        """ Test generic rule on cuckoo report. """
        config = '''[expressions]
            expression.1  : /DDE/ in cuckooreport.signature_descriptions -> bad
        '''

        report = {
            "signatures": [
                { "description": "Malicious document featuring Office DDE has been identified" }
            ]
        }
        cuckooreport = CuckooReport(report)

        sample = Sample(None)
        sample.register_cuckoo_report(cuckooreport)
        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_empty_set(self):
        """ Test generic rule with empty set. """
        config = '''[expressions]
            expression.5: {sample.type_declared} & {
                              'text/plain', 'inode/x-empty'} != {} -> ignore
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        sample = Sample(None, content_type="text/plain")
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = Sample(None, content_type="text/plan")
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

    def test_rule_expressions_rtf(self):
        """ Test generic rule on rtf docs and types. """
        config = r'''[expressions]
            expression.0  : sample.file_extension in {"doc", "docx"}
                and /.*\/(rtf|richtext)/ in (
                    {sample.type_declared} | filereport.mime_types) -> bad
        '''

        kwargs = {
            'filename': 'file1.doc',
            'content_type': 'application/word'
        }

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(path, **kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = FileSample(path, **kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expression_filetools(self):
        """ Test generic rule on filetoolsreport. """
        config = r'''[expressions]
            expression.0  : filereport.type_as_text
                == "AppleDouble encoded Macintosh file" -> ignore
            expression.1  : sample.file_extension in {"doc", "docx"}
                and filereport.type_by_content != /application\/.*word/ -> bad
            expression.2: "text" in filereport.type_by_name -> ignore
        '''

        sample_kwargs = {
            'filename': 'file1.doc',
            'content_type': 'application/word',
        }

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(path, **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = FileSample(path, **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(
            self.office_data_dir,
            'AppleDoubleencodedMacintoshfileCheckVM.xls')
        sample = FileSample(path, **sample_kwargs)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        # expression.2 should not raise a 'NoneType not iterable' exception due
        # to type_by_name being None (and it should not match). This happens if
        # the file name is empty, for example.
        sample = Sample(b'dummy')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

    @asynctest
    async def test_rule_expression_knowntools(self):
        """ Test generic rule on knowntoolsreport. """
        config = r'''[expressions]
            expression.0  : sample.filename == "first.a" and knownreport.known -> bad
            expression.1  : knownreport.known and knownreport.worst_result < unknown -> unknown
            expression.2  : knownreport.known -> knownreport.worst_result
            expression.3  : knownreport.known -> knownreport.last_result
            expression.4  : knownreport.first == 0 and knownreport.last == 0 -> ignore
        '''

        test_db = os.path.abspath('./test.db')
        conf = CreatingPeekabooConfig()
        db_con = PeekabooDatabase('sqlite:///' + test_db,
                                      instance_id=1,
                                      stale_in_flight_threshold=10)

        sample = Sample(b'test', 'test.py')
        good_result = RuleResult(
            'Unittest', Result.good, 'This is just a test case.',
            further_analysis=False)
        sample.add_rule_result(good_result)
        await db_con.analysis_add(sample)
        sample.mark_done()
        db_con.analysis_update(sample)

        # add a failed analysis to check that it is ignored
        result = RuleResult('Unittest',
                            Result.failed,
                            'This is just a test case.',
                            further_analysis=False)
        sample.add_rule_result(result)
        await db_con.analysis_add(sample)
        sample.mark_done()
        db_con.analysis_update(sample)

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, db_con)

        sample = Sample(b'test', 'test.py')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.good)

        sample = Sample(b'firsttest', 'first.a')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample.add_rule_result(result)
        await db_con.analysis_add(sample)
        sample.mark_done()
        db_con.analysis_update(sample)

        sample = Sample(b'firsttest', 'first.a')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        sample = Sample(b'secondtest', 'second.b')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample.add_rule_result(result)
        await db_con.analysis_add(sample)
        sample.mark_done()
        db_con.analysis_update(sample)

        sample = Sample(b'secondtest', 'second.b')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample.add_rule_result(good_result)
        await db_con.analysis_add(sample)
        sample.mark_done()
        db_con.analysis_update(sample)

        sample = Sample(b'secondtest', 'second.b')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.good)

        os.unlink(test_db)

    def test_rule_expressions_cuckooreport_context(self):
        """ Test generic rule cuckooreport context """
        config = '''[expressions]
            expression.3  : "EVIL" in cuckooreport.signature_descriptions
                and cuckooreport.score > 4 -> bad
        '''

        report = {
            "signatures": [
                {"description": "EVIL"}
            ],
            "info": {"score": 4.2}
        }

        blank_doc = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(blank_doc)
        sample.register_cuckoo_report(CuckooReport(report))
        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_cortexreport_fileinfoanalyzerreport_context(self):
        """ Test generic rule cortexreport.FileInfoAnalyzerReport context """
        config = '''[expressions]
                expression.2  : cortexreport.FileInfoReport.md5sum == '78576e618aff135f320601e49bd8fe7e' -> good
                expression.4  : '.day.um' in cortexreport.FileInfoReport.domain_artifacts -> unknown
                expression.6  : '8.8.8.8' in cortexreport.FileInfoReport.ip_artifacts -> bad
        '''

        taxonomies = [
            {
            "level": "info",
            "namespace": "FileInfo",
            "predicate": "Filetype",
            "value": "JPEG"
            }
        ]

        report = {
            "summary": {
                "taxonomies": taxonomies
            },
            "full": {
                "results": [
                    {
                        "submodule_name": "Basic properties",
                        "results": [
                            {
                                "submodule_section_header": "Hashes",
                                "submodule_section_content": {
                                    "md5": "78576e618aff135f320601e49bd8fe7e",
                                    "sha1": "2520dcd603b851846fa27035807adc4df83a7519",
                                    "sha256": "42690cc82dd1f56fd6ec315723b8e1f27fdd42e670c7752477e91afb62ea2c6b",
                                    "ssdeep": "768:GaqFVZh8KI4mF0xJcXmwE6ONpHOhbPOobiSp3ug06GnzAjUaq:NK3bI4s0xJCmwE7HEbf7ozf"
                                }
                            },
                        ],
                        "summary": {
                            "taxonomies": taxonomies
                        }
                    }
                ]
            },
            "success": True,
            "artifacts": [
                {
                "data": "42690cc82dd1f56fd6ec315723b8e1f27fdd42e670c7752477e91afb62ea2c6b",
                "dataType": "hash",
                "message": None,
                "tags": [],
                "tlp": 2
                },
                {
                "data": "2520dcd603b851846fa27035807adc4df83a7519",
                "dataType": "hash",
                "message": None,
                "tags": [],
                "tlp": 2
                },
                {
                "data": "78576e618aff135f320601e49bd8fe7e",
                "dataType": "hash",
                "message": None,
                "tags": [],
                "tlp": 2
                }
            ],
            "operations": []
            }

        cortexreport = CortexReport()
        cortexreport.register_report(FileInfoAnalyzer, report)

        blank_doc = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.good)

        report["full"]["results"][0]["results"][0]["submodule_section_content"]["md5"] = "a"*32
        report["artifacts"] = [{
            "data": "8.8.8.8",
            "dataType": "ip",
        }]

        cortexreport = CortexReport()
        cortexreport.register_report(FileInfoAnalyzer, report)

        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)

        # re-use rule
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        report["artifacts"] = [{
            "data": "oh.my.day.um",
            "dataType": "domain",
        }]
        cortexreport = CortexReport()
        cortexreport.register_report(FileInfoAnalyzer, report)
        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        report["full"]["results"][0]["results"][0]["submodule_section_content"]["md5"] = ""
        cortexreport = CortexReport()
        with self.assertRaises(schema.SchemaError):
            cortexreport.register_report(FileInfoAnalyzer, report)

    def test_rule_expressions_cortexreport_virustotalqueryreport_context(self):
        """ Test generic rule cortexreport.VirusTotalQueryReport context """
        config = '''[expressions]
            expression.5  : cortexreport.VirusTotalQueryReport.n_of_all > 0
                or cortexreport.VirusTotalQueryReport.level != 'safe'
                ->  bad
        '''
        tax = {
            "level": "malicious",
            "namespace": "VT",
            "predicate": "GetReport",
            "value": "37/68"
        }
        report = {
            "summary": {
                "taxonomies": [
                     tax
                ]
            },
            "full": {
                "response_code": 0,
                "resource": "Foo",
                "verbose_msg": "AAA"
            },
            "success": True,
            "artifacts": [],
            "operations": []
        }

        cortexreport = CortexReport()
        cortexreport.register_report(VirusTotalQuery, report)

        blank_doc = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)

        self.assertEqual(result.result, Result.bad)

        # patch report for different outcome
        tax["level"] = "safe"
        tax["value"] = "0/86"
        report["summary"]["taxonomies"].append(tax)

        cortexreport = CortexReport()
        cortexreport.register_report(VirusTotalQuery, report)

        # re-use rule
        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        # patch report for different outcome
        report["summary"]["taxonomies"].pop(0)

        cortexreport = CortexReport()
        cortexreport.register_report(VirusTotalQuery, report)

        # re-use rule
        sample = FileSample(blank_doc)
        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)

        self.assertEqual(result.result, Result.unknown)

        report["summary"]["taxonomies"][0]["value"] = "NAN"
        with self.assertRaises(schema.SchemaError):
            cortexreport = CortexReport()
            cortexreport.register_report(VirusTotalQuery, report)

    def test_rule_expressions_olereport_context(self):
        """ Test generic rule olereport context """
        config = '''[expressions]
            expression.3: sample.file_extension in {'doc', 'rtf', 'rtx'}
                              and olereport.has_office_macros == True -> bad
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        path = os.path.join(self.office_data_dir, 'empty.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'file.txt')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.rtf')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.doc')
        sample = FileSample(path, filename='foo.rtx')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        config = '''[expressions]
            expression.3  : /suspicious/ in olereport.vba_code -> bad
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_olereport_autoexec_suspicious(self):
        """ Test generic rule olereport with autoexec and suspicious """
        config = '''[expressions]
            expression.3  : olereport.has_autoexec == True -> bad
            expression.4  : olereport.is_suspicious == True -> bad
            expression.5  : "suspicious" in olereport.vba_code -> bad
        '''

        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)

        path = os.path.join(self.office_data_dir, 'empty.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'file.txt')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.rtf')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.doc')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'CheckVM.xls')
        sample = FileSample(path)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        config = '''[expressions]
            expression.5  : "VBOX" in olereport.detected_suspicious -> bad
        '''

        path = os.path.join(self.office_data_dir, 'CheckVM.xls')
        sample = FileSample(path)
        parsed_config = CreatingConfigParser(config)
        rule = ExpressionRule(parsed_config, None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_config_file_type_on_whitelist(self):
        """ Test whitelist rule configuration. """
        config = '''[file_type_on_whitelist]
whitelist.1 : foo/bar
unknown : baz'''
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'Empty whitelist, check file_type_on_whitelist rule config.'):
            FileTypeOnWhitelistRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_type_on_whitelist: unknown'):
            FileTypeOnWhitelistRule(CreatingConfigParser(config), None)

    def test_rule_file_type_on_greylist(self):
        """ Test greylist rule. """
        combinations = [
            [False, {'type_by_content': 'text/plain'}],
            [True, {'type_by_content': 'application/msword'}],
            [True, {
                'type_by_content': 'text/plain',
                'type_by_name': 'application/x-dosexec'
            }],
            [True, {
                'type_by_content': 'image/png',
                'type_by_name': 'application/zip'
            }],
            [False, {'type_by_content': '', 'type_by_name': 'asdfjkl'}],
            # Files without any mime type are inherently suspicious and
            # therefore analysed
            [True, dict()],
            [True, {'type_by_content': None}],
        ]
        rule = FileTypeOnGreylistRule(self.config, None)
        for expected, types in combinations:
            result = rule.evaluate(MimetypeSample(types))
            self.assertEqual(result.further_analysis, expected,
                             "FiletoolsReport: %s" % types)

    def test_config_file_type_on_greylist(self):
        """ Test greylist rule configuration. """
        config = '''[file_type_on_greylist]
greylist.1 : foo/bar
unknown : baz'''
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'Empty greylist, check file_type_on_greylist rule config.'):
            FileTypeOnGreylistRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_type_on_greylist: unknown'):
            FileTypeOnGreylistRule(CreatingConfigParser(config), None)

    def test_rule_analysis_failed(self):
        """ Test the Cuckoo analysis failed rule """
        # create some test samples
        successful_sample = CuckooReportSample(
            {'debug': {'cuckoo': ['analysis completed successfully']}})
        failed_sample = CuckooReportSample(
            {'debug': {'cuckoo': ['analysis failed']}})
        reached_sample = CuckooReportSample(
            {'debug': {'cuckoo': ['end of analysis reached!']}})
        everything_sample = CuckooReportSample(
            {'debug': {'cuckoo': [
                'end of analysis reached!',
                'analysis failed',
                'analysis completed successfully']}})

        # test defaults
        rule = CuckooAnalysisFailedRule(CreatingConfigParser(''), None)
        result = rule.evaluate(successful_sample)
        self.assertEqual(result.result, Result.unknown)
        self.assertEqual(result.further_analysis, True)
        result = rule.evaluate(reached_sample)
        self.assertEqual(result.result, Result.failed)
        self.assertEqual(result.further_analysis, False)
        result = rule.evaluate(failed_sample)
        self.assertEqual(result.result, Result.failed)
        self.assertEqual(result.further_analysis, False)
        result = rule.evaluate(everything_sample)
        self.assertEqual(result.result, Result.unknown)
        self.assertEqual(result.further_analysis, True)

        # test with config
        rule = CuckooAnalysisFailedRule(self.config, None)
        result = rule.evaluate(successful_sample)
        self.assertEqual(result.result, Result.unknown)
        self.assertEqual(result.further_analysis, True)
        result = rule.evaluate(reached_sample)
        self.assertEqual(result.result, Result.failed)
        self.assertEqual(result.further_analysis, False)
        result = rule.evaluate(failed_sample)
        self.assertEqual(result.result, Result.failed)
        self.assertEqual(result.further_analysis, False)
        result = rule.evaluate(everything_sample)
        self.assertEqual(result.result, Result.failed)
        self.assertEqual(result.further_analysis, False)

    def test_config_evil_sig(self):
        """ Test the Cuckoo evil signature rule configuration. """
        config = '''[cuckoo_evil_sig]
signature.1  : foo
unknown : baz'''
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'Empty bad signature list, check cuckoo_evil_sig rule '
                r'config.'):
            CuckooEvilSigRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_evil_sig: unknown'):
            CuckooEvilSigRule(CreatingConfigParser(config), None)

    def test_config_score(self):
        """ Test the Cuckoo score rule configuration. """
        config = '''[cuckoo_score]
higher_than : 10
unknown : baz'''
        CuckooScoreRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_score: unknown'):
            CuckooScoreRule(CreatingConfigParser(config), None)

    def test_config_evil_domain(self):
        """ Test the Cuckoo requests evil domain rule configuration. """
        config = '''[requests_evil_domain]
domain.1 : foo
unknown : baz'''
        with self.assertRaisesRegex(
                PeekabooRulesetConfigError,
                r'Empty evil domain list, check requests_evil_domain rule '
                r'config.'):
            RequestsEvilDomainRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'requests_evil_domain: unknown'):
            RequestsEvilDomainRule(CreatingConfigParser(config), None)

    def test_config_analysis_failed(self):
        """ Test the Cuckoo analysis failed rule configuration. """
        config = '''[cuckoo_analysis_failed]
failure.1: end of analysis reached!
success.1: analysis completed successfully
unknown : baz'''
        # there should be no exception here since empty config is acceptable
        CuckooAnalysisFailedRule(CreatingConfigParser(), None)

        with self.assertRaisesRegex(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_analysis_failed: unknown'):
            CuckooAnalysisFailedRule(CreatingConfigParser(config), None)

    def test_config_final(self):  # pylint: disable=no-self-use
        """ Test the final rule configuration. """
        config = '''[final]
unknown : baz'''
        # there is no exception here since empty config is acceptable
        FinalRule(CreatingConfigParser(), None)
        # there is no exception here since the final rule simply does
        # not look at the configuration at all - maybe we should have a
        # 'unknown section' error here
        FinalRule(CreatingConfigParser(config), None)


class TestExpressionParser(unittest.TestCase):
    """ Unittests for the expression parser. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.parser = ExpressionParser()

    def test_basic_expressions(self):
        """ Test basic expressions. """
        combinations = [
            ["True", True],
            ["False", False],
            # these two would break if bitwise operators were used
            ["True and 2", True],
            ["True or 2", True],
            ["False and True", False],
            ["True or False", True],
            ["True and False", False],
            ["False or True", True],
            ["1 < 2 < 3", True],
            ["1 < 2 < 2", False],
            ["1 == 2 == 2", False],
            ["1 == 1 == 2", False],
            ["1 != 2 != 2", False],
            ["1 != 1 != 2", False],
            ["'a' in 'aa' in 'aaa'", True],
            ["True and True and False", False],
            ["True and False and True", False],
            ["False or False or True", True],
            ["1 and 2 and 0", False],
            ["1 and 0 and 2", False],
            ["0 or 0 or 2", True],
            # this would raise a NoneType exception if the second operand was
            # evaluated
            ["False and 'foo' in None", False],
            ["True or 'foo' in None", True],
            ["5", 5],
            ["5 == 5", True],
            ["5 == 7", False],
            ["5+2 == 7", True],
            ["(5+2)*2==14", True],
            ["'foo' == 'bar'", False],
            ["'foo' == 'foo'", True],
            ["'foo' in 'bar'", False],
            # we swallow None being non-iterable
            ["'foo' in None", False],
            ["'foo' not in None", False],
            # re.search() for "match anywhere in operand"
            ["'foo' in 'foobar'", True],
            ["/foo/ in 'afoobar'", True],
            # re.match() is implicit /^<pattern>/. We add $ at the end to have
            # "match from beginning to end"
            ["/foo/ == 'afoobar'", False],
            ["/foo/ == 'foo'", True],
            ["/foo/ == 'foobar'", False],
            ["/foo/ == 'fo'", False],
            ["/foo/ == 'foob'", False],
            ["/foo/ == 'fobar'", False],
            ["/foo/ != 'afoobar'", True],
            ["/foo/ != 'foo'", False],
            ["/foo/ != 'foobar'", True],
            ["/foo/ != 'fo'", True],
            ["/foo/ != 'foob'", True],
            ["/foo/ != 'fobar'", True],
            ["/[fb][oa][or]/ in 'foo'", True],
            ["/[fb][oa][or]/ in 'bar'", True],
            ["/[fb][oa][or]/ in 'snafu'", False],
            ["/[fb][oa][or]/ in ['afoob', 'snafu']", True],
            ["/[fb][oa][or]/ not in ['afoob', 'snafu']", False],
            ["/[fb][oa][or]/ == ['foo', 'snafu']", True],
            ["/[fb][oa][or]/ == ['foob', 'snafu']", False],
            ["/[fb][oa][or]/ == ['afoob', 'snafu']", False],
            ["/[fb][oa][or]/ != ['afoob', 'snafu']", True],
            ["[/foo/, /bar/] in ['snafu', 'fuba']", False],
            ["[/foo/, /bar/, /ub/] in ['snafu', 'fuba']", True],
            ["[/foo/, /bar/, /naf/] in ['snafu', 'fuba']", True],
            ["{'text/plain'}|{'test/mime','inode/empty'}",
             {'text/plain', 'test/mime', 'inode/empty'}],
            ["{}", set()],
            ["{1} <= {1}", True],
            ["{1} <= {2}", False],
            ["{1} <= {2,3}", False],
            ["{1,2} <= {1,2,3}", True],
            ["{1}|{2}", {1, 2}],
            ["{1}|{2} <= {1,2}", True],
            ["{'1'}|{'2','3'} <= {'1','2'}", False],
            ["{'text/plain'}|{'test/mime','inode/empty'} <="
             "{'text/plain', 'test/mime', 'inode/empty'}", True],
            ["[]", []],
        ]
        for rule, expected in combinations:
            parsed = self.parser.parse(rule)
            self.assertEqual(parsed.eval({}), expected, "Rule: %s" % rule)

    def test_identifier_missing(self):
        """ Missing identifier exceptions. """
        parsed = self.parser.parse("foo == 'bar'")
        with self.assertRaisesRegex(KeyError, "variables") as keyerr:
            parsed.eval({})
        # make sure this really is a key error and no subclass of it
        self.assertNotIsInstance(keyerr.exception, IdentifierMissingException)

        with self.assertRaisesRegex(
                IdentifierMissingException,
                "Identifier 'foo' is missing") as iderr:
            parsed.eval({"variables": {}})
        self.assertEqual(iderr.exception.name, "foo")

        # now that really should work
        parsed.eval({"variables": {"foo": "bar"}})


class PeekabooTestResult(unittest.TextTestResult):
    """ Subclassed test result for custom formatting. """
    def getDescription(self, test):
        """ Print only the first docstring line and not the test name as well
        as the parent class does. """
        doc_first_line = test.shortDescription()
        if self.descriptions and doc_first_line:
            return doc_first_line

        return str(test)


def enable_debug():
    """ Allow to enable debug messages by calling this function anywhere. """
    logging.disable(logging.NOTSET)
    _logger = logging.getLogger()
    to_console_log_handler = logging.StreamHandler(sys.stdout)
    _logger.addHandler(to_console_log_handler)
    _logger.setLevel(logging.DEBUG)


def main():
    """ Run the testsuite. """
    gettext.NullTranslations().install()

    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestConfigParser))
    suite.addTest(unittest.makeSuite(TestDefaultConfig))
    suite.addTest(unittest.makeSuite(TestValidConfig))
    suite.addTest(unittest.makeSuite(TestInvalidConfig))
    suite.addTest(unittest.makeSuite(TestDefaultAnalyzerConfig))
    suite.addTest(unittest.makeSuite(TestValidAnalyzerConfig))
    suite.addTest(unittest.makeSuite(TestSample))
    suite.addTest(unittest.makeSuite(TestDatabase))
    suite.addTest(unittest.makeSuite(TestOletools))
    suite.addTest(unittest.makeSuite(TestFiletools))
    suite.addTest(unittest.makeSuite(TestCuckoo))
    suite.addTest(unittest.makeSuite(TestRulesetEngine))
    suite.addTest(unittest.makeSuite(TestRules))
    suite.addTest(unittest.makeSuite(TestExpressionParser))
    # TODO: We need more tests!!!

    # Disable all logging to avoid spurious messages.
    logging.disable(logging.ERROR)

    runner = unittest.TextTestRunner(
        verbosity=2, resultclass=PeekabooTestResult)
    result = runner.run(suite)

    logging.disable(logging.NOTSET)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
