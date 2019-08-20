#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# test.py                                                                     #
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

""" The testsuite. """

from future.builtins import super  # pylint: disable=wrong-import-order

import gettext
import sys
import os
import tempfile
import logging
import shutil
import unittest
from datetime import datetime, timedelta


# Add Peekaboo to PYTHONPATH
# pylint: disable=wrong-import-position
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peekaboo.exceptions import PeekabooConfigException, \
        PeekabooRulesetConfigError
from peekaboo.config import PeekabooConfig, PeekabooConfigParser
from peekaboo.sample import SampleFactory
from peekaboo.ruleset import RuleResult, Result
from peekaboo.ruleset.engine import RulesetEngine
from peekaboo.ruleset.rules import FileTypeOnWhitelistRule, \
        FileTypeOnGreylistRule, CuckooAnalysisFailedRule, \
        KnownRule, FileLargerThanRule, CuckooEvilSigRule, \
        CuckooScoreRule, RequestsEvilDomainRule, FinalRule, \
        OfficeMacroRule, OfficeMacroWithSuspiciousKeyword, \
        ExpressionRule

from peekaboo.toolbox.cuckoo import CuckooReport
from peekaboo.db import PeekabooDatabase, PeekabooDatabaseError
# pylint: enable=wrong-import-position


class CreatingConfigMixIn(object):
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
        PeekabooConfigParser.__init__(self, self.created_config_file)

    def __del__(self):
        self.remove_config()


class CreatingPeekabooConfig(PeekabooConfig, CreatingConfigMixIn):
    """ A special kind of Peekaboo config that creates the configuration file
    with defined content. """
    def __init__(self, content=''):
        self.created_config_file = None
        self.create_config(content)
        PeekabooConfig.__init__(self, self.created_config_file)

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
        self.assertEqual(self.config['rule1'].getlist('option2'),
                         ['bar', 'baz'])

    def test_3_type_mismatch(self):
        """ Test correct error is thrown if the option type is mismatched """
        config = '''[rule1]
option1: foo
option1.1: bar'''

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                'Option option1 in section rule1 is supposed to be a list but '
                'given as individual setting'):
            CreatingConfigParser(config).getlist('rule1', 'option1')



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
        self.assertEqual(self.config.group, 'peekaboo')
        self.assertEqual(
            self.config.sock_file, '/var/run/peekaboo/peekaboo.sock')
        self.assertEqual(
            self.config.pid_file, '/var/run/peekaboo/peekaboo.pid')
        self.assertEqual(self.config.interpreter, '/usr/bin/python2 -u')
        self.assertEqual(self.config.worker_count, 3)
        self.assertEqual(self.config.sample_base_dir, '/tmp')
        self.assertEqual(
            self.config.job_hash_regex, '/amavis/tmp/([^/]+)/parts/')
        self.assertEqual(self.config.use_debug_module, False)
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
        self.assertEqual(self.config.cuckoo_mode, 'api')
        self.assertEqual(self.config.cuckoo_exec, '/opt/cuckoo/bin/cuckoo')
        self.assertEqual(self.config.cuckoo_submit, '/opt/cuckoo/bin/cuckoo submit')
        self.assertEqual(self.config.cuckoo_storage, '/var/lib/peekaboo/.cuckoo/storage')
        self.assertEqual(self.config.cuckoo_url, 'http://127.0.0.1:8090')
        self.assertEqual(self.config.cuckoo_poll_interval, 5)
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
pid_file         :    /pid/1
interpreter      :    /inter/1
worker_count     :    18
sample_base_dir  :    /tmp/1
job_hash_regex   :    /var/2
use_debug_module :    yes
keep_mail_data   :    yes
processing_info_dir : /var/3

[ruleset]
config           :    /rules/1

[logging]
log_level        :    DEBUG
log_format       :    format%%foo1

[db]
url              :    sqlite:////peekaboo.db1

[cuckoo]
mode             :    api1
exec             :    /cuckoo/1
submit           :    /submit/1
storage_path     :    /storage/1
url              :    http://api:1111
poll_interval    :    51

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
        self.assertEqual(self.config.pid_file, '/pid/1')
        self.assertEqual(self.config.interpreter, '/inter/1')
        self.assertEqual(self.config.worker_count, 18)
        self.assertEqual(self.config.sample_base_dir, '/tmp/1')
        self.assertEqual(self.config.job_hash_regex, '/var/2')
        self.assertEqual(self.config.use_debug_module, True)
        self.assertEqual(self.config.keep_mail_data, True)
        self.assertEqual(self.config.processing_info_dir, '/var/3')
        self.assertEqual(self.config.ruleset_config, '/rules/1')
        self.assertEqual(self.config.log_level, logging.DEBUG)
        self.assertEqual(self.config.log_format, 'format%foo1')
        self.assertEqual(self.config.db_url, 'sqlite:////peekaboo.db1')
        self.assertEqual(self.config.cuckoo_mode, 'api1')
        self.assertEqual(self.config.cuckoo_exec, '/cuckoo/1')
        self.assertEqual(self.config.cuckoo_submit, '/submit/1')
        self.assertEqual(self.config.cuckoo_storage, '/storage/1')
        self.assertEqual(self.config.cuckoo_url, 'http://api:1111')
        self.assertEqual(self.config.cuckoo_poll_interval, 51)
        self.assertEqual(self.config.cluster_instance_id, 12)
        self.assertEqual(self.config.cluster_stale_in_flight_threshold, 31)
        self.assertEqual(self.config.cluster_duplicate_check_interval, 61)


class TestInvalidConfig(unittest.TestCase):
    """ Various tests of invalid config files. """
    def test_1_section_header(self):
        """ Test correct error is thrown if section header syntax is wrong """
        with self.assertRaisesRegexp(
                PeekabooConfigException,
                'Configuration file ".*" can not be parsed: File contains no '
                'section headers'):
            CreatingPeekabooConfig('''[global[
user: peekaboo''')

    def test_2_value_separator(self):
        """ Test correct error is thrown if the value separator is wrong """
        with self.assertRaisesRegexp(
                PeekabooConfigException,
                'Configuration file ".*" can not be parsed: (File|Source) '
                'contains parsing errors:'):
            CreatingPeekabooConfig('''[global]
user; peekaboo''')

    def test_3_section_header(self):
        """ Test correct error is thrown if the config file is missing """
        _, config_file = tempfile.mkstemp()
        os.unlink(config_file)

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                'Configuration file "%s" can not be opened for reading: '
                r'\[Errno 2\] No such file or directory' % config_file):
            PeekabooConfig(config_file)

    def test_4_unknown_section(self):
        """ Test correct error is thrown if an unknown section name is given.
        """
        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown section\(s\) found in config: globl'):
            CreatingPeekabooConfig('''[globl]''')

    def test_5_unknown_option(self):
        """ Test correct error is thrown if an unknown option name is given.
        """
        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section global: foo'):
            CreatingPeekabooConfig('''[global]
foo: bar''')

    def test_6_unknown_loglevel(self):
        """ Test with an unknown log level """
        with self.assertRaisesRegexp(
                PeekabooConfigException,
                'Unknown log level FOO'):
            CreatingPeekabooConfig('''[logging]
log_level: FOO''')


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
            cuckoo=None, base_dir=cls.conf.sample_base_dir,
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

    def test_2_sample_info_fetch(self):
        """ Test retrieval of analysis results. """
        sample_info = self.db_con.sample_info_fetch(self.sample)
        self.assertEqual(sample_info.sha256sum, self.sample.sha256sum)
        self.assertEqual(sample_info.result, Result.failed)
        self.assertEqual(sample_info.reason, 'This is just a test case.')

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
        self.assertRaisesRegexp(
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
            cuckoo=None, base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False,
            processing_info_dir=None)
        cls.sample = cls.factory.create_sample('test.py', 'test')

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
            cuckoo=None, base_dir=self.conf.sample_base_dir,
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
        self.assertTrue(set(['text/x-python']).issubset(self.sample.mimetypes))
        self.assertEqual(
            self.sample.sha256sum,
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.result, Result.unchecked)
        self.assertEqual(self.sample.reason, None)
        self.assertRegexpMatches(
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
        self.assertTrue(set(['text/x-python']).issubset(self.sample.mimetypes))
        self.assertEqual(
            self.sample.sha256sum,
            '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.result, Result.unchecked)
        self.assertEqual(self.sample.reason, None)
        self.assertRegexpMatches(
            self.sample.peekaboo_report[0], 'File "%s" %s is being analyzed'
            % (self.sample.filename, self.sample.sha256sum))
        self.assertRegexpMatches(
            self.sample.peekaboo_report[1],
            'File "%s" is considered "unchecked"'
            % self.sample.filename)
        self.assertEqual(self.sample.cuckoo_report, None)
        self.assertEqual(self.sample.done, False)
        self.assertRegexpMatches(
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
                'type_long': 'application/x-python-bytecode',
                'type_short': 'pyc',
                'size': '200'})
        self.assertEqual(sample.file_extension, 'pyc')

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

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        os.unlink(cls.test_db)
        del cls.factory


class TestRulesetEngine(unittest.TestCase):
    """ Unittests for the Ruleset Engine. """
    def test_no_rules_configured(self):
        """ Test that correct error is shown if no rules are configured. """
        config = CreatingConfigParser()
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'No enabled rules found, check ruleset config.'):
            RulesetEngine(ruleset_config=config, db_con=None)

    def test_unknown_rule_enabled(self):
        """ Test that correct error is shown if an unknown rule is enabled. """
        config = CreatingConfigParser('''[rules]
rule.1: foo''')
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'Unknown rule\(s\) enabled: foo'):
            RulesetEngine(ruleset_config=config, db_con=None)

    def test_invalid_type(self):
        """ Test that correct error is shown if rule config option has wrong
        type. """

        config = CreatingConfigParser('''[rules]
rule.1: cuckoo_score

[cuckoo_score]
higher_than: foo''')
        with self.assertRaisesRegexp(
                ValueError,
                r"could not convert string to float: '?foo'?"):
            RulesetEngine(ruleset_config=config, db_con=None)

    def test_disabled_config(self):
        """ Test that no error is shown if disabled rule has config. """

        config = CreatingConfigParser('''[rules]
rule.1: known
#rule.2: cuckoo_score

[cuckoo_score]
higher_than: 4.0''')
        RulesetEngine(ruleset_config=config, db_con=None)


class MimetypeSample(object):  # pylint: disable=too-few-public-methods
    """ A dummy sample class that only contains a set of MIME types for testing
    whitelist and greylist rules with it. """
    def __init__(self, types):
        # don't even need to make it a property
        self.mimetypes = set(types)


class CuckooReportSample(object):  # pylint: disable=too-few-public-methods
    """ A dummy sample that only contains a configurable cuckoo report. """
    def __init__(self, report):
        self.cuckoo_report = CuckooReport(report)


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

    def test_config_known(self):  # pylint: disable=no-self-use
        """ Test the known rule configuration. """
        config = '''[known]
unknown : baz'''
        # there is no exception here since empty config is acceptable
        KnownRule(CreatingConfigParser())
        # there is no exception here since the known rule simply does
        # not look at the configuration at all - maybe we should have a
        # 'unknown section' error here
        KnownRule(CreatingConfigParser(config))

    def test_config_file_larger_than(self):
        """ Test the file larger than rule configuration. """
        config = '''[file_larger_than]
bytes : 10
unknown : baz'''
        # there is no exception here since empty config is acceptable
        FileLargerThanRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_larger_than: unknown'):
            FileLargerThanRule(CreatingConfigParser(config))

    def test_rule_file_type_on_whitelist(self):
        """ Test whitelist rule. """
        combinations = [
            [False, ['text/plain']],
            [True, ['application/vnd.ms-excel']],
            [True, ['text/plain', 'application/vnd.ms-excel']],
            [True, ['image/png', 'application/zip', 'application/vnd.ms-excel']],
            [True, ['', 'asdfjkl', '93219843298']],
            [True, []],
        ]
        rule = FileTypeOnWhitelistRule(self.config)
        for expected, types in combinations:
            result = rule.evaluate(MimetypeSample(types))
            self.assertEqual(result.further_analysis, expected)

    def test_rule_office_ole(self):
        """ Test rule office_ole. """
        config = '''[office_macro_with_suspicious_keyword]
            keyword.1 : AutoOpen
            keyword.2 : AutoClose
            keyword.3 : suSPi.ious'''
        rule = OfficeMacroWithSuspiciousKeyword(CreatingConfigParser(config))
        # sample factory to create samples from real files
        factory1 = SampleFactory(
            cuckoo=None, base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)
        # sampe factory to create samples with defined content
        factory2 = CreatingSampleFactory(
            cuckoo=None, base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)
        tests_data_dir = os.path.dirname(os.path.abspath(__file__))+"/test-data"

        combinations = [
            # no office document file extension
            [Result.unknown, factory2.make_sample('test.nodoc', 'test')],
            # test with empty file
            [Result.unknown, factory1.make_sample(tests_data_dir+'/office/empty.doc')],
            # office document with 'suspicious' in macro code
            [Result.bad, factory1.make_sample(tests_data_dir+'/office/suspiciousMacro.doc')],
            # test with blank word doc
            [Result.unknown, factory1.make_sample(tests_data_dir+'/office/blank.doc')],
            # test with legitimate macro
            [Result.unknown, factory1.make_sample(tests_data_dir+'/office/legitmacro.xls')]
        ]
        for expected, sample in combinations:
            result = rule.evaluate(sample)
            self.assertEqual(result.result, expected)

        # test if macro present
        rule = OfficeMacroRule(CreatingConfigParser(config))
        combinations = [
            # no office document file extension
            [Result.unknown, factory2.make_sample('test.nodoc', 'test')],
            # test with empty file
            [Result.unknown, factory1.make_sample(tests_data_dir+'/office/empty.doc')],
            # office document with 'suspicious' in macro code
            [Result.bad, factory1.make_sample(tests_data_dir+'/office/suspiciousMacro.doc')],
            # test with blank word doc
            [Result.unknown, factory1.make_sample(tests_data_dir+'/office/blank.doc')],
            # test with legitimate macro
            [Result.bad, factory1.make_sample(tests_data_dir+'/office/legitmacro.xls')]
        ]
        for expected, sample in combinations:
            result = rule.evaluate(sample)
            self.assertEqual(result.result, expected)

    def test_rule_ignore_generic_whitelist(self):
        """ Test rule to ignore file types on whitelist. """
        config = '''[expressions]
            expression.4  : sample.mimetypes <= {'text/plain', 'inode/x-empty', 'image/jpeg'} -> ignore
        '''
        factory = CreatingSampleFactory(
            cuckoo=None, base_dir="",
            job_hash_regex="", keep_mail_data=False,
            processing_info_dir=None)

        sample = factory.create_sample('file.txt', 'abc')
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample = factory.create_sample('file.html', '<html')
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # bzip2 compressed data
        sample = factory.create_sample('file.txt', 'BZh91AY=')
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

    def test_rule_ignore_mail_signatures(self):
        """ Test rule to ignore cryptographic mail signatures. """
        config = '''[expressions]
            expression.4  : sample.meta_info_name_declared == 'smime.p7s'
                and sample.meta_info_type_declared in {
                    'application/pkcs7-signature',
                    'application/x-pkcs7-signature',
                    'application/pkcs7-mime',
                    'application/x-pkcs7-mime'
                } -> ignore
            expression.3  : sample.meta_info_name_declared == 'signature.asc'
                and sample.meta_info_type_declared in {
                    'application/pgp-signature'
                } -> ignore'''

        part = { "full_name": "p001",
                 "name_declared": "smime.p7s",
                 "type_declared": "application/pkcs7-signature"
               }

        factory = SampleFactory(
            cuckoo=None, base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        # test smime signatures
        sample = factory.make_sample('', metainfo=part)
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.ignored)

        sample.meta_info_name_declared = "file"
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        # test gpg signatures
        sample.meta_info_name_declared = "signature.asc"
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.unknown)

        sample.meta_info_type_declared = "application/pgp-signature"
        rule = ExpressionRule(CreatingConfigParser(config))
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
            cuckoo=None, base_dir=None, job_hash_regex=None,
            keep_mail_data=False, processing_info_dir=None)

        sample = factory.make_sample('')
        sample.register_cuckoo_report(cuckooreport)
        rule = ExpressionRule(CreatingConfigParser(config))
        result = rule.evaluate(sample)
        self.assertEqual(result.result, Result.bad)

    def test_config_file_type_on_whitelist(self):
        """ Test whitelist rule configuration. """
        config = '''[file_type_on_whitelist]
whitelist.1 : foo/bar
unknown : baz'''
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'Empty whitelist, check file_type_on_whitelist rule config.'):
            FileTypeOnWhitelistRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_type_on_whitelist: unknown'):
            FileTypeOnWhitelistRule(CreatingConfigParser(config))

    def test_rule_file_type_on_greylist(self):
        """ Test greylist rule. """
        combinations = [
            [False, ['text/plain']],
            [True, ['application/msword']],
            [True, ['text/plain', 'application/x-dosexec']],
            [True, ['image/png', 'application/zip', 'application/vnd.ms-excel',
                    'application/vnd.ms-powerpoint']],
            [False, ['', 'asdfjkl', '93219843298']],
            [True, []],
        ]
        rule = FileTypeOnGreylistRule(self.config)
        for expected, types in combinations:
            result = rule.evaluate(MimetypeSample(types))
            self.assertEqual(result.further_analysis, expected)

    def test_config_file_type_on_greylist(self):
        """ Test greylist rule configuration. """
        config = '''[file_type_on_greylist]
greylist.1 : foo/bar
unknown : baz'''
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'Empty greylist, check file_type_on_greylist rule config.'):
            FileTypeOnGreylistRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'file_type_on_greylist: unknown'):
            FileTypeOnGreylistRule(CreatingConfigParser(config))

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
        rule = CuckooAnalysisFailedRule(CreatingConfigParser(''))
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
        rule = CuckooAnalysisFailedRule(self.config)
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
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'Empty bad signature list, check cuckoo_evil_sig rule '
                r'config.'):
            CuckooEvilSigRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_evil_sig: unknown'):
            CuckooEvilSigRule(CreatingConfigParser(config))

    def test_config_score(self):
        """ Test the Cuckoo score rule configuration. """
        config = '''[cuckoo_score]
higher_than : 10
unknown : baz'''
        CuckooScoreRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_score: unknown'):
            CuckooScoreRule(CreatingConfigParser(config))

    def test_config_evil_domain(self):
        """ Test the Cuckoo requests evil domain rule configuration. """
        config = '''[requests_evil_domain]
domain.1 : foo
unknown : baz'''
        with self.assertRaisesRegexp(
                PeekabooRulesetConfigError,
                r'Empty evil domain list, check requests_evil_domain rule '
                r'config.'):
            RequestsEvilDomainRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'requests_evil_domain: unknown'):
            RequestsEvilDomainRule(CreatingConfigParser(config))

    def test_config_analysis_failed(self):
        """ Test the Cuckoo analysis failed rule configuration. """
        config = '''[cuckoo_analysis_failed]
failure.1: end of analysis reached!
success.1: analysis completed successfully
unknown : baz'''
        # there should be no exception here since empty config is acceptable
        CuckooAnalysisFailedRule(CreatingConfigParser())

        with self.assertRaisesRegexp(
                PeekabooConfigException,
                r'Unknown config option\(s\) found in section '
                r'cuckoo_analysis_failed: unknown'):
            CuckooAnalysisFailedRule(CreatingConfigParser(config))

    def test_config_final(self):  # pylint: disable=no-self-use
        """ Test the final rule configuration. """
        config = '''[final]
unknown : baz'''
        # there is no exception here since empty config is acceptable
        FinalRule(CreatingConfigParser())
        # there is no exception here since the final rule simply does
        # not look at the configuration at all - maybe we should have a
        # 'unknown section' error here
        FinalRule(CreatingConfigParser(config))


class PeekabooTestResult(unittest.TextTestResult):
    """ Subclassed test result for custom formatting. """
    def getDescription(self, test):
        """ Print only the first docstring line and not the test name as well
        as the parent class does. """
        doc_first_line = test.shortDescription()
        if self.descriptions and doc_first_line:
            return doc_first_line

        return str(test)

def main():
    """ Run the testsuite. """
    gettext.NullTranslations().install()

    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestConfigParser))
    suite.addTest(unittest.makeSuite(TestDefaultConfig))
    suite.addTest(unittest.makeSuite(TestValidConfig))
    suite.addTest(unittest.makeSuite(TestInvalidConfig))
    suite.addTest(unittest.makeSuite(TestSample))
    suite.addTest(unittest.makeSuite(TestDatabase))
    suite.addTest(unittest.makeSuite(TestRulesetEngine))
    suite.addTest(unittest.makeSuite(TestRules))
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
