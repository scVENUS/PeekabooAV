#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# test.py                                                                     #
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

""" The testsuite. """

import gettext
import sys
import os
import tempfile
import logging
import shutil
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
from peekaboo.sample import SampleFactory
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
from peekaboo.toolbox.cortex import CortexReport, VirusTotalQuery
# pylint: enable=wrong-import-position


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
        self.assertEqual(
            self.config.sock_file, '/var/run/peekaboo/peekaboo.sock')
        self.assertEqual(self.config.sock_group, None)
        self.assertEqual(self.config.sock_mode, 0o0660)
        self.assertEqual(
            self.config.pid_file, '/var/run/peekaboo/peekaboo.pid')
        self.assertEqual(self.config.worker_count, 3)
        self.assertEqual(self.config.sample_base_dir, '/tmp')
        self.assertEqual(
            self.config.job_hash_regex, '/amavis/tmp/([^/]+)/parts/')
        self.assertEqual(self.config.keep_mail_data, False)
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
socket_file      :    /socket/1
socket_group     :    riddlers
socket_mode      :    0141
pid_file         :    /pid/1
worker_count     :    18
sample_base_dir  :    /tmp/1
job_hash_regex   :    /var/2
keep_mail_data   :    yes
processing_info_dir : /var/3

[ruleset]
config           :    /rules/1

[logging]
log_level        :    DEBUG
log_format       :    format%%(foo1)s

[db]
url              :    sqlite:////peekaboo.db1

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
        self.assertEqual(self.config.sock_file, '/socket/1')
        self.assertEqual(self.config.sock_group, 'riddlers')
        self.assertEqual(self.config.sock_mode, 0o0141)
        self.assertEqual(self.config.pid_file, '/pid/1')
        self.assertEqual(self.config.worker_count, 18)
        self.assertEqual(self.config.sample_base_dir, '/tmp/1')
        self.assertEqual(self.config.job_hash_regex, '/var/2')
        self.assertEqual(self.config.keep_mail_data, True)
        self.assertEqual(self.config.processing_info_dir, '/var/3')
        self.assertEqual(self.config.ruleset_config, '/rules/1')
        self.assertEqual(self.config.log_level, logging.DEBUG)
        self.assertEqual(self.config.log_format, 'format%(foo1)s')
        self.assertEqual(self.config.db_url, 'sqlite:////peekaboo.db1')
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
        self.assertEqual(self.config.cortex_poll_interval, 57)
        self.assertEqual(self.config.cortex_submit_original_filename, True)
        self.assertEqual(self.config.cortex_maximum_job_age, 905)
        self.assertEqual(self.config.cortex_api_token, 'tok2')


class CreatingSampleFactory(SampleFactory):
    """ A special kind of sample factory that creates the sample files with
    defined content in a temporary directory and cleans up after itself. """
    def __init__(self, *args, **kwargs):
        self.directory = tempfile.mkdtemp()
        super().__init__(*args, **kwargs)

    def create_sample(self, relpath, content, *args, **kwargs):
        """ Make a new sample with defined base name and content in the
        previously created temporary directory. The given basename can
        optionally be a path relative to the temporary directory and the
        subdirectory will be created automatically. """
        file_path = os.path.join(self.directory, relpath)
        subdir = os.path.dirname(file_path)
        if subdir != self.directory:
            os.makedirs(subdir)
        with open(file_path, 'w') as file_desc:
            file_desc.write(content)

        return super().make_sample(file_path, *args, **kwargs)

    def __del__(self):
        """ Remove the sample files we've created and the temporary directory
        itself. """
        shutil.rmtree(self.directory)


class TestDatabase(unittest.TestCase):
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
        cls.factory = CreatingSampleFactory(
            base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False,
            processing_info_dir=None)
        cls.sample = cls.factory.create_sample('test.py', 'test')
        result = RuleResult('Unittest',
                            Result.failed,
                            'This is just a test case.',
                            further_analysis=False)
        cls.sample.add_rule_result(result)

    def test_1_analysis_save(self):
        """ Test saving of analysis results. """
        self.db_con.analysis_save(self.sample)
        self.db_con.analysis_save(self.sample)

    def test_3_analysis_journal_fetch_journal(self):
        """ Test retrieval of analysis results. """
        journal = self.db_con.analysis_journal_fetch_journal(self.sample)
        self.assertEqual(journal[0].result, Result.failed)
        self.assertEqual(journal[0].reason, 'This is just a test case.')
        self.assertIsNotNone(journal[0].analysis_time)
        self.assertEqual(journal[1].result, Result.failed)
        self.assertEqual(journal[1].reason, 'This is just a test case.')
        self.assertIsNotNone(journal[1].analysis_time)
        self.assertNotEqual(journal[0].analysis_time, journal[1].analysis_time)

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
            PeekabooDatabaseError, "Unexpected inconsistency: Sample .* not "
            "recoreded as in-flight upon clearing flag",
            self.db_con.clear_sample_in_flight, self.sample, 1)

    def test_7_in_flight_clear(self):
        """ Test clearing of in-flight markers. """
        sample2 = self.factory.create_sample('foo.pyc', 'foo')
        sample3 = self.factory.create_sample('bar.pyc', 'bar')

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
        sample2 = self.factory.create_sample('baz.pyc', 'baz')
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
        # test framework doesn't seem to give up reference so that __del__ is
        # never run
        del cls.factory


class TestSample(unittest.TestCase):
    """ Unittests for Samples. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = CreatingPeekabooConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.factory = CreatingSampleFactory(
            base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False,
            processing_info_dir=None)
        part = {
            "name_declared": "text.py",
            "type_declared": "text/x-python"
        }
        cls.sample = cls.factory.create_sample('test.py', 'test', metainfo=part)

    def test_job_hash_regex(self):
        """ Test extraction of the job hash from the working directory path.
        """
        # class sample has no job hash in path and therefore generates one
        # itself
        self.assertIn('peekaboo-run_analysis', self.sample.job_hash)

        # a new sample with a job hash in it's path should return it
        job_hash = 'amavis-20170831T132736-07759-iSI0rJ4b'
        path_with_job_hash = 'd/var/lib/amavis/tmp/%s/parts/file' % job_hash
        sample = self.factory.make_sample(path_with_job_hash, 'file')
        self.assertEqual(job_hash, sample.job_hash,
                         'Job hash regex is not working')

        legacy_factory = CreatingSampleFactory(
            base_dir=self.conf.sample_base_dir,
            job_hash_regex=r'/var/lib/amavis/tmp/([^/]+)/parts.*',
            keep_mail_data=False, processing_info_dir=None)
        sample = legacy_factory.make_sample(path_with_job_hash, 'file')
        self.assertEqual(job_hash, sample.job_hash,
                         'Job hash regex is not working')

    def test_3_sample_attributes(self):
        """ Test the various sample attribute getters. """
        self.assertEqual(self.sample.file_path,
                         os.path.join(self.factory.directory, 'test.py'))
        self.assertEqual(self.sample.filename, 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertEqual('text/x-python', self.sample.type_declared)
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
        self.assertEqual(self.sample.done, False)
        self.assertEqual(self.sample.submit_path, None)
        self.assertEqual(self.sample.file_size, 4)

    def test_4_initialised_sample_attributes(self):
        """ Test the various sample attributes of an initialised sample. """
        self.sample.init()
        self.assertEqual(self.sample.file_path,
                         os.path.join(self.factory.directory, 'test.py'))
        self.assertEqual(self.sample.filename, 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertEqual('text/x-python', self.sample.type_declared)
        self.assertEqual(
            self.sample.sha256sum,
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
        self.assertEqual(self.sample.result, Result.unchecked)
        self.assertEqual(self.sample.reason, None)
        self.assertRegex(
            self.sample.peekaboo_report[0], 'File "%s" %s is being analyzed'
            % (self.sample.filename, self.sample.sha256sum))
        self.assertRegex(
            self.sample.peekaboo_report[1],
            'File "%s" is considered "unchecked"'
            % self.sample.filename)
        self.assertEqual(self.sample.cuckoo_report, None)
        self.assertEqual(self.sample.done, False)
        self.assertRegex(
            self.sample.submit_path, '/%s.py$' % self.sample.sha256sum)
        self.assertEqual(self.sample.file_size, 4)

    def test_5_mark_done(self):
        """ Test the marking of a sample as done. """
        self.sample.mark_done()
        self.assertEqual(self.sample.done, True)

    def test_6_add_rule_result(self):
        """ Test the adding of a rule result. """
        reason = 'This is just a test case.'
        result = RuleResult('Unittest', Result.failed,
                            reason,
                            further_analysis=False)
        self.sample.add_rule_result(result)
        self.assertEqual(self.sample.result, Result.failed)
        self.assertEqual(self.sample.reason, reason)

    def test_sample_attributes_with_meta_info(self):
        """ Test use of optional meta data. """
        sample = self.factory.make_sample(
            'test.pyc', metainfo={
                'full_name': '/tmp/test.pyc',
                'name_declared': 'test.pyc',
                'type_declared': 'application/x-bytecode.python',
                'content_disposition': 'angry',
                'type_long': 'application/x-python-bytecode',
                'type_short': 'pyc',
                'size': '200'})
        self.assertEqual(sample.file_extension, 'pyc')
        self.assertEqual(sample.content_disposition, 'angry')

    def test_sample_without_suffix(self):
        """ Test extraction of file extension from declared name. """
        sample = self.factory.make_sample(
            'junk', metainfo={
                'full_name': '/tmp/junk',
                'name_declared': 'Report.docx',
                'type_declared': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'type_long': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'type_short': 'docx',
                'size': '212'})
        self.assertEqual(sample.file_extension, 'docx')

    def test_sample_extension_multiple_dots(self):
        """ Test file extension with name containing multiple dots. """
        sample = self.factory.make_sample('junk..ext')
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
            sample = self.factory.make_sample('junk.' + ext)
            self.assertEqual(
                sample.file_extension is not None,
                accepted,
                "File extension filtering for %s" % ext)

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        os.unlink(cls.test_db)
        del cls.factory


class OletoolsSample:  # pylint: disable=too-few-public-methods
    """ A dummy sample class that only contains a file_path and a dummy report
    registration callback for testing the Oletools analyser. """
    def __init__(self, file_path, report=None):
        # don't even need to make it a property
        self.file_path = file_path
        self.oletools_report = report

    def register_oletools_report(self, report):
        """ Dummy report registration. """
        self.oletools_report = report


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
            report = Oletools(OletoolsSample(file_path)).get_report()
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
        sample = OletoolsSample("dummy", report)
        new_report = Oletools(sample).get_report()
        self.assertIs(report, new_report)


class FiletoolsSample:  # pylint: disable=too-few-public-methods
    """ A dummy sample class that only contains a file_path and a dummy report
    registration callback for testing the Filetools analyser. """
    def __init__(self, filename, file_path=None, name_declared=None,
                 report=None):
        # don't even need to make it a property
        self.filename = filename
        self.file_path = file_path
        self.name_declared = name_declared
        self.filetools_report = report

    def register_filetools_report(self, report):
        """ Dummy report registration. """
        self.filetools_report = report


class TestFiletools(unittest.TestCase):
    """ Unittests for Oletools. """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.tests_data_dir = os.path.join(TESTSDIR, "test-data")

    def test_analysis(self):
        """ Test Filetools analysis. """
        cases = [
            # subdir, , declared name, , type by name
            # , file name, , type by content, , type as text
            # a file without declared name
            ['', 'textfile', None, 'text/plain', None, 'ASCII text'],
            # a file with declared name but without file extension
            ['', 'textfile', 'textfile', 'text/plain', None, 'ASCII text'],
            # a file with declared name and file extension
            ['', 'textfile', 'textfile.txt',
             'text/plain', 'text/plain', 'ASCII text'],
            # a file with declared name and a file extension that belies its
            # actual content
            ['', 'textfile', 'textfile.py',
             'text/plain', 'text/x-python', 'ASCII text'],
            # a word document - just because we can
            # interesting conundrum here: magic output depends on local timezone
            ['office', 'blank.doc', None, 'application/msword',
             'application/msword', '^Composite Document File V2 Document, '
             'Little Endian, Os: MacOS, Version 14.10, Code page: 10000, '
             'Author: Microsoft Office User, Template: Normal.dotm, Last '
             'Saved By: Microsoft Office User, Revision Number: 2, Name of '
             'Creating Application: Microsoft Office Word, Create '
             'Time/Date: Fri Jun  7 [0-2][0-9]:55:00 2019, Last Saved '
             'Time/Date: Tue Jun 25 [0-2][0-9]:07:00 2019, Number of Pages: '
             '1, Number of Words: 0, Number of Characters: 0, Security: 0$'],
        ]
        for subdir, file_name, name_declared, expected_type_by_content, \
                expected_type_by_name, expected_type_as_text in cases:
            file_path = os.path.join(self.tests_data_dir, subdir, file_name)
            sample = FiletoolsSample(file_name, file_path, name_declared)
            report = Filetools(sample).get_report()
            self.assertEqual(
                report.type_by_content, expected_type_by_content,
                "Filetools type_by_content: %s:%s" % (file_name, name_declared))
            self.assertEqual(
                report.type_by_name, expected_type_by_name,
                "Filetools type_by_name: %s:%s" % (file_name, name_declared))
            self.assertRegex(
                report.type_as_text, expected_type_as_text,
                "Filetools type_as_text: %s:%s" % (file_name, name_declared))

    def test_caching(self):
        """ Test Filetools report caching in the sample. """
        report = object()
        sample = FiletoolsSample("dummy", report=report)
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

        # assumes above report is a minimal report
        expected_dump = report.copy()
        expected_dump.update(
            {"x-peekaboo": {"origin-url": cuckooreport.url}})
        self.assertEqual(cuckooreport.dump, expected_dump)

    def test_invalid_report(self):
        """ Test that invalid report values are rejected. """
        with self.assertRaisesRegex(TypeError, r'report.*dict'):
            CuckooReport([])

        with self.assertRaisesRegex(TypeError, r'network.*dict'):
            CuckooReport({"network": []})
        with self.assertRaisesRegex(TypeError, r'dns.*list or tuple'):
            CuckooReport({"network": {"dns": {}}})
        with self.assertRaisesRegex(TypeError, r'domains.*dicts'):
            CuckooReport({"network": {"dns": [[]]}})
        with self.assertRaisesRegex(KeyError, r'dns.*missing.*element'):
            CuckooReport({"network": {"dns": [{"not-request": 1}]}})
        with self.assertRaisesRegex(TypeError, r'dns.*string'):
            CuckooReport({"network": {"dns": [{"request": 1}]}})

        with self.assertRaisesRegex(TypeError, r'signatures.*list or tuple'):
            CuckooReport({"signatures": {}})
        with self.assertRaisesRegex(TypeError, r'signatures.*dicts'):
            CuckooReport({"signatures": [1]})
        with self.assertRaisesRegex(KeyError, r'signatures.*description'):
            CuckooReport({"signatures": [{"not-description": 1}]})
        with self.assertRaisesRegex(TypeError, r'signature.*strings'):
            CuckooReport({"signatures": [{"description": 1}]})

        with self.assertRaisesRegex(TypeError, r'info.*dict'):
            CuckooReport({"info": 1})
        with self.assertRaisesRegex(TypeError, r'score.*number'):
            CuckooReport({"info": {"score": "onepointtwo"}})

        with self.assertRaisesRegex(TypeError, r'debug.*dict'):
            CuckooReport({"debug": 1})
        with self.assertRaisesRegex(TypeError, r'error message.*list or tuple'):
            CuckooReport({"debug": {"errors": {}}})
        with self.assertRaisesRegex(TypeError, r'error messages.*strings'):
            CuckooReport({"debug": {"errors": [1]}})

        with self.assertRaisesRegex(
                TypeError, r'server message.*list or tuple'):
            CuckooReport({"debug": {"cuckoo": {}}})
        with self.assertRaisesRegex(TypeError, r'server messages.*strings'):
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


class TestRules(unittest.TestCase):
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

        # sampe factory to create samples
        factory = CreatingSampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        # test if macro with suspicious keyword
        rule = OfficeMacroWithSuspiciousKeyword(
            CreatingConfigParser(config), None)
        combinations = [
            # no office document file extension
            [Result.unknown, factory.create_sample('test.nodoc', 'test')],
            # test with empty file
            [Result.unknown, factory.make_sample(os.path.join(
                self.office_data_dir, 'empty.doc'))],
            # office document with 'suspicious' in macro code
            [Result.bad, factory.make_sample(os.path.join(
                self.office_data_dir, 'suspiciousMacro.doc'))],
            # test with blank word doc
            [Result.unknown, factory.make_sample(os.path.join(
                self.office_data_dir, 'blank.doc'))],
            # test with legitimate macro
            [Result.unknown, factory.make_sample(os.path.join(
                self.office_data_dir, 'legitmacro.xls'))]
        ]
        for expected, sample in combinations:
            result = rule.evaluate(sample)
            self.assertEqual(result.result, expected)

        # test if macro present
        rule = OfficeMacroRule(CreatingConfigParser(config), None)
        combinations = [
            # no office document file extension
            [Result.unknown, factory.create_sample('test.nodoc', 'test')],
            # test with empty file
            [Result.unknown, factory.make_sample(os.path.join(
                self.office_data_dir, 'empty.doc'))],
            # office document with 'suspicious' in macro code
            [Result.bad, factory.make_sample(os.path.join(
                self.office_data_dir, 'suspiciousMacro.doc'))],
            # test with blank word doc
            [Result.unknown, factory.make_sample(os.path.join(
                self.office_data_dir, 'blank.doc'))],
            # test with legitimate macro
            [Result.bad, factory.make_sample(os.path.join(
                self.office_data_dir, 'legitmacro.xls'))]
        ]
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
        factory = CreatingSampleFactory(
            base_dir="",
            job_hash_regex="", keep_mail_data=False,
            processing_info_dir=None)

        sample = factory.create_sample('file.txt', 'abc')
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = factory.create_sample('file.html', '<html')
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # bzip2 compressed data
        sample = factory.create_sample('file.txt', 'BZh91AY=')
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

    def test_rule_ignore_no_name_declared(self):
        """ Test rule to ignore file with no name_declared. """
        config = '''[expressions]
            expression.3  : not sample.name_declared -> ignore
        '''

        factory = CreatingSampleFactory(
            base_dir="",
            job_hash_regex="", keep_mail_data=False,
            processing_info_dir=None)

        part = {"full_name": "file1.gif",
                "name_declared": "file1.gif",
                "type_declared": "image/gif"
               }

        sample = factory.create_sample('file1.gif', 'GIF87...', metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = factory.create_sample('file2.gif', 'GIF87...')
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        config = '''[expressions]
            expression.3  : sample.name_declared is None -> ignore
        '''

        sample = factory.create_sample('file2.gif', 'GIF87...')
        rule = ExpressionRule(CreatingConfigParser(config), None)
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
        rule = ExpressionRule(CreatingConfigParser(config), None)

        factory = SampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        sample = factory.make_sample('file.1')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # test smime signatures
        part = {
            "full_name": "p001",
            "name_declared": "smime.p7s",
            "type_declared": "application/pkcs7-signature"
        }

        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        part["name_declared"] = "asmime.p7m"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        part["name_declared"] = "smime.p7m"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        part["name_declared"] = "smime.p7o"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        part["name_declared"] = "smime.p7"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        part["name_declared"] = "smime.p7sm"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        part["name_declared"] = "file"
        sample = factory.make_sample('', metainfo=part)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # test gpg signatures
        part["name_declared"] = "signature.asc"
        sample = factory.make_sample('', metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        part["type_declared"] = "application/pgp-signature"
        sample = factory.make_sample('', metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
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

        factory = SampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        sample = factory.make_sample('')
        sample.register_cuckoo_report(cuckooreport)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_rtf(self):
        """ Test generic rule on rtf docs and types. """
        config = r'''[expressions]
            expression.0  : sample.file_extension in {"doc", "docx"}
                and /.*\/(rtf|richtext)/ in (
                    {sample.type_declared} | filereport.mime_types) -> bad
        '''

        factory = SampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        part = {
            "full_name": "p001",
            "name_declared": "file1.doc",
            "type_declared": "application/word"
        }

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = factory.make_sample(path, metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = factory.make_sample(path, metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expression_filetools(self):
        """ Test generic rule on filetoolsreport. """
        config = r'''[expressions]
            expression.0  : filereport.type_as_text
                == "AppleDouble encoded Macintosh file" -> ignore
            expression.1  : sample.file_extension in {"doc", "docx"}
                and filereport.type_by_content != /application\/.*word/ -> bad
        '''

        factory = SampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        part = {
            "full_name": "p001",
            "name_declared": "file1.doc",
            "type_declared": "application/word"
        }

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = factory.make_sample(path, metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = factory.make_sample(path, metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(
            self.office_data_dir,
            'AppleDoubleencodedMacintoshfileCheckVM.xls')
        sample = factory.make_sample(path, metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

    def test_rule_expression_knowntools(self):
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
        factory = CreatingSampleFactory(
            base_dir=conf.sample_base_dir,
            job_hash_regex=conf.job_hash_regex, keep_mail_data=False,
            processing_info_dir=None)

        sample = factory.create_sample('test.py', 'test')
        result = RuleResult('Unittest',
                            Result.failed,
                            'This is just a test case.',
                            further_analysis=False)
        sample.add_rule_result(result)
        db_con.analysis_save(sample)

        rule = ExpressionRule(CreatingConfigParser(config), db_con)

        sample = factory.create_sample('test.py', 'test')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.failed)

        sample = factory.create_sample('first.a', 'firsttest')
        result = rule.evaluate(sample)
        sample.add_rule_result(result)
        db_con.analysis_save(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = factory.create_sample('first.a', 'firsttest')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        sample = factory.create_sample('second.b', 'secondtest')
        result = rule.evaluate(sample)
        sample.add_rule_result(result)
        db_con.analysis_save(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = factory.create_sample('second.b', 'secondtest')
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        os.unlink(test_db)

    def test_rule_expressions_cuckooreport_context(self):
        """ Test generic rule cuckooreport context """
        config = '''[expressions]
            expression.3  : "EVIL" in cuckooreport.signature_descriptions
                and cuckooreport.score > 4 -> bad
        '''

        factory = CreatingSampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        report = {
            "signatures": [
                {"description": "EVIL"}
            ],
            "info": {"score": 4.2}
        }
        cuckooreport = CuckooReport(report)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'blank.doc'))
        sample.register_cuckoo_report(cuckooreport)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_cortexreport_virustotalqueryreport_context(self):
        """ Test generic rule cortexreport.VirusTotalQueryReport context """
        config = '''[expressions]
            expression.5  : cortexreport.VirusTotalQueryReport.n_of_all > 0
                or cortexreport.VirusTotalQueryReport.level != 'safe'
                ->  bad
        '''
        rule = ExpressionRule(CreatingConfigParser(config), None)

        factory = CreatingSampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'blank.doc'))

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
            "success": True,
            "artifacts": [],
            "operations": []
        }
        cortexreport = CortexReport()
        cortexreport.register_report(VirusTotalQuery, report)

        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        tax["level"] = "safe"
        tax["value"] = "0/86"
        report["summary"]["taxonomies"].append(tax)
        cortexreport.register_report(VirusTotalQuery, report)
        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        report["summary"]["taxonomies"].pop(0)
        cortexreport.register_report(VirusTotalQuery, report)
        sample.register_cortex_report(cortexreport)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        report["summary"]["taxonomies"][0]["value"] = "NAN"
        cortexreport.register_report(VirusTotalQuery, report)
        sample.register_cortex_report(cortexreport)
        with self.assertRaises(ValueError):
            result = rule.evaluate(sample)

    def test_rule_expressions_olereport_context(self):
        """ Test generic rule olereport context """
        config = '''[expressions]
            expression.3: sample.file_extension in {'doc', 'rtf', 'rtx'}
                              and olereport.has_office_macros == True -> bad
        '''

        factory = CreatingSampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        path = os.path.join(self.office_data_dir, 'empty.doc')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'file.txt')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'blank.doc')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'example.rtf')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.rtf')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.doc')
        sample = factory.make_sample(path)
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        path = os.path.join(self.office_data_dir, 'suspiciousMacro.doc')
        sample = factory.make_sample(path, metainfo={
            'name_declared': 'foo.rtx'})
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        config = '''[expressions]
            expression.3  : /suspicious/ in olereport.vba_code -> bad
        '''
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_rule_expressions_olereport_autoexec_suspicious(self):
        """ Test generic rule olereport with autoexec and suspicious """
        config = '''[expressions]
            expression.3  : olereport.has_autoexec == True -> bad
            expression.4  : olereport.is_suspicious == True -> bad
            expression.5  : "suspicious" in olereport.vba_code -> bad
        '''

        factory = CreatingSampleFactory(
            base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)
        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'empty.doc'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'file.txt'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'blank.doc'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'example.rtf'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'suspiciousMacro.rtf'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'suspiciousMacro.doc'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'CheckVM.xls'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

        config = '''[expressions]
            expression.5  : "VBOX" in olereport.detected_suspicious -> bad
        '''
        sample = factory.make_sample(os.path.join(
            self.office_data_dir, 'CheckVM.xls'))
        rule = ExpressionRule(CreatingConfigParser(config), None)
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
            ["5", 5],
            ["5 == 5", True],
            ["5 == 7", False],
            ["5+2 == 7", True],
            ["(5+2)*2==14", True],
            ["'foo' == 'bar'", False],
            ["'foo' == 'foo'", True],
            ["'foo' in 'bar'", False],
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
            ["{1} <= {1}", True],
            ["{1} <= {2}", False],
            ["{1} <= {2,3}", False],
            ["{1,2} <= {1,2,3}", True],
            ["{1}|{2}", {1, 2}],
            ["{1}|{2} <= {1,2}", True],
            ["{'1'}|{'2','3'} <= {'1','2'}", False],
            ["{'text/plain'}|{'test/mime','inode/empty'} <="
             "{'text/plain', 'test/mime', 'inode/empty'}", True],
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
