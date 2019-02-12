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

import sys
import os
import tempfile
import logging
import hashlib
import unittest
from datetime import datetime, timedelta


# Add Peekaboo to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peekaboo.exceptions import PeekabooConfigException
from peekaboo.config import PeekabooConfig, PeekabooRulesetConfig
from peekaboo.sample import SampleFactory
from peekaboo.ruleset import RuleResult, Result
from peekaboo.ruleset.rules import FileTypeOnWhitelistRule, FileTypeOnGreylistRule
from peekaboo.db import PeekabooDatabase, PeekabooDatabaseError


class TestConfig(unittest.TestCase):
    """ Base class for various tests of the configuration module. """
    config_class = PeekabooConfig
    testconfig = None

    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config_file = tempfile.mktemp()
        with open(cls.config_file, 'w') as file_desc:
            file_desc.write(cls.testconfig)

        cls.config = cls.config_class(config_file=cls.config_file)

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        os.unlink(cls.config_file)


class TestDefaultConfig(TestConfig):
    """ Test a configuration of all defaults. """
    testconfig = ''

    def test_1_default_settings(self):
        """ Test a configuration with just defaults """
        self.assertEqual(self.config.config_file, self.config_file)
        self.assertEqual(self.config.user, 'peekaboo')
        self.assertEqual(self.config.group, 'peekaboo')
        self.assertEqual(
            self.config.sock_file, '/var/run/peekaboo/peekaboo.sock')
        self.assertEqual(
            self.config.pid_file, '/var/run/peekaboo/peekaboo.pid')
        self.assertEqual(self.config.interpreter, '/usr/bin/python -u')
        self.assertEqual(self.config.worker_count, 3)
        self.assertEqual(self.config.sample_base_dir, '/tmp')
        self.assertEqual(
            self.config.job_hash_regex, '/var/lib/amavis/tmp/([^/]+)/parts.*')
        self.assertEqual(self.config.use_debug_module, False)
        self.assertEqual(self.config.keep_mail_data, False)
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
        self.assertEqual(self.config.cluster_stale_in_flight_threshold, 3600)
        self.assertEqual(self.config.cluster_duplicate_check_interval, 60)


class TestValidConfig(TestConfig):
    """ Test a configuration with all values different from the defaults. """
    testconfig = '''[global]
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
'''

    def test_1_read_settings(self):
        """ Test reading of configuration settings from file """
        self.assertEqual(self.config.config_file, self.config_file)
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


class TestInvalidConfigBase(unittest.TestCase):
    """ Various tests of invalid config files. """
    config_class = None

    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.config_file = tempfile.mktemp()

    def write_config(self, testconfig):
        """ Helper method for writing out a test config file. """
        with open(self.config_file, 'w') as file_desc:
            file_desc.write(testconfig)

    def test_1_section_header(self):
        """ Test correct error is thrown if section header syntax is wrong """
        self.write_config('''[global[
user: peekaboo''')
        with self.assertRaisesRegexp(
            PeekabooConfigException,
            'Configuration file "%s" can not be parsed: File contains no '
            'section headers' % self.config_file):
            self.config_class(config_file=self.config_file)

    def test_2_value_separator(self):
        """ Test correct error is thrown if the value separator is wrong """
        self.write_config('''[global]
user; peekaboo''')
        with self.assertRaisesRegexp(
            PeekabooConfigException,
            'Configuration file "%s" can not be parsed: (File|Source) '
            'contains parsing errors:' % self.config_file):
            self.config_class(config_file=self.config_file)

    def test_3_section_header(self):
        """ Test correct error is thrown if the config file is missing """
        try:
            os.unlink(self.config_file)
        except OSError:
            pass

        with self.assertRaisesRegexp(
            PeekabooConfigException,
            'Configuration file "%s" can not be opened for reading: '
            r'\[Errno 2\] No such file or directory' % self.config_file):
            self.config_class(config_file=self.config_file)

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        try:
            os.unlink(cls.config_file)
        except OSError:
            pass


class TestInvalidConfig(TestInvalidConfigBase):
    """ Various tests of invalid config files. """
    config_class = PeekabooConfig

    def test_50_unknown_loglevel(self):
        """ Test with an unknown log level """
        self.write_config('''[logging]
log_level: FOO''')
        with self.assertRaisesRegexp(
            PeekabooConfigException,
            'Unknown log level FOO'):
            self.config_class(config_file=self.config_file)


class TestValidRulesetConfig(TestConfig):
    """ Test a configuration with all values different from the defaults. """
    config_class = PeekabooRulesetConfig
    testconfig = '''#[rule0]

[rule1]
option1: foo
option2.1: bar
option2.2: baz

[rule2]
enabled = false

[rule3]
enabled: true

[rule4]
enabled = on

[rule5]
enabled: off
'''

    def test_1_enabled(self):
        """ Test disabling of rules  """
        self.assertEqual(self.config.rule_enabled('rule0'), True)
        self.assertEqual(self.config.rule_enabled('rule1'), True)
        self.assertEqual(self.config.rule_enabled('rule2'), False)
        self.assertEqual(self.config.rule_enabled('rule3'), True)
        self.assertEqual(self.config.rule_enabled('rule4'), True)
        self.assertEqual(self.config.rule_enabled('rule5'), False)

    def test_2_values(self):
        """ Test rule configuration values """
        self.assertEqual(self.config.rule_config('rule0'), None)
        self.assertEqual(self.config.rule_config('rule1')['option1'], 'foo')
        self.assertEqual(
            self.config.rule_config('rule1')['option2'], ['bar', 'baz'])


class TestInvalidRulesetConfig(TestInvalidConfigBase):
    """ Various tests of invalid ruleset config files. """
    config_class = PeekabooRulesetConfig

    def test_50_type_mismatch(self):
        """ Test correct error is thrown if the option type is mismatched """
        self.write_config('''[rule1]
option1: foo
option1.1: bar''')
        with self.assertRaisesRegexp(
            PeekabooConfigException,
            'Setting option1.1 in section rule1 specified as list as well '
            'as individual setting'):
            self.config_class(config_file=self.config_file)

class PeekabooDummyConfig(object):
    """ A dummy configuration for the test cases. """
    def __init__(self):
        """ Initialize dummy configuration """
        self.job_hash_regex = r'/var/lib/amavis/tmp/([^/]+)/parts.*'
        self.sample_base_dir = '/tmp'

    def get(self, option, default):
        """ Return specific dummy settings. """
        config = {
            'whitelist':['text/plain', 'inode/x-empty'],
            'greylist' :['application/x-dosexec', 'application/msword',
                         'application/vnd.ms-powerpoint'],
        }
        return config[option]


class TestDatabase(unittest.TestCase):
    """
    Unittests for Peekaboo's database module.

    @author: Sebastian Deiss
    """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = PeekabooDummyConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db,
                                      instance_id=1,
                                      stale_in_flight_threshold=10)
        cls.no_cluster_db = PeekabooDatabase('sqlite:///' + cls.test_db,
                                             instance_id=0)
        cls.factory = SampleFactory(
            cuckoo=None, base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))
        result = RuleResult('Unittest',
                            Result.failed,
                            'This is just a test case.',
                            further_analysis=False)
        cls.sample.add_rule_result(result)
        cls.sample.determine_result()

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
        sample2 = self.factory.make_sample('foo.pyc')
        sample2.set_attr('sha256sum', hashlib.sha256('foo').hexdigest())
        sample3 = self.factory.make_sample('bar.pyc')
        sample3.set_attr('sha256sum', hashlib.sha256('bar').hexdigest())

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
        sample2 = self.factory.make_sample('foo.pyc')
        sample2.set_attr('sha256sum', hashlib.sha256('foo').hexdigest())
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
    """
    Unittests for Samples.

    @author: Sebastian Deiss
    """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = PeekabooDummyConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.factory = SampleFactory(
            cuckoo=None, base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))

    def test_attribute_dict(self):
        """ Test the attribute functions. """
        self.sample.set_attr('Unittest', 'Hello World!')
        self.assertTrue(self.sample.has_attr('Unittest'))
        self.assertEqual(self.sample.get_attr('Unittest'), 'Hello World!')
        self.sample.set_attr('Unittest', 'Test', override=True)
        self.assertEqual(self.sample.get_attr('Unittest'), 'Test')

    def test_job_hash_regex(self):
        """ Test extraction of the job hash from the working directory path.
        """
        path_with_job_hash = '/var/lib/amavis/tmp/amavis-20170831T132736-07759-iSI0rJ4b/parts'
        sample = self.factory.make_sample(path_with_job_hash)
        job_hash = sample.get_job_hash()
        self.assertEqual(job_hash, 'amavis-20170831T132736-07759-iSI0rJ4b',
                         'Job hash regex is not working')
        job_hash = self.sample.get_job_hash()
        self.assertIn('peekaboo-run_analysis', job_hash)

    def test_sample_attributes(self):
        """ Test the various sample attribute getters. """
        self.assertEqual(self.sample.get_filename(), 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertTrue(set(['text/x-python']).issubset(set(self.sample.mimetypes)))
        self.assertIsNotNone(self.sample.sha256sum)
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.get_result(), Result.unchecked)
        self.assertEqual(self.sample.get_reason(), None)
        self.assertFalse(self.sample.office_macros)

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


class TestRules(unittest.TestCase):
    """
    Unittests for Rules.

    @author: Felix Bauer
    """
    @classmethod
    def setUpClass(cls):
        """ Set up common test case resources. """
        cls.conf = PeekabooDummyConfig()
        cls.factory = SampleFactory(
            cuckoo=None, base_dir=cls.conf.sample_base_dir,
            job_hash_regex=cls.conf.job_hash_regex, keep_mail_data=False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))

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
        rule = FileTypeOnWhitelistRule(self.conf)
        for expected, types in combinations:
            self.sample.set_attr('mimetypes', set(types))
            result = rule.evaluate(self.sample)
            self.assertEqual(result.further_analysis, expected)

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
        rule = FileTypeOnGreylistRule(self.conf)
        for expected, types in combinations:
            self.sample.set_attr('mimetypes', set(types))
            result = rule.evaluate(self.sample)
            self.assertEqual(result.further_analysis, expected)

    @classmethod
    def tearDownClass(cls):
        """ Clean up after the tests. """
        pass

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
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestDefaultConfig))
    suite.addTest(unittest.makeSuite(TestValidConfig))
    suite.addTest(unittest.makeSuite(TestInvalidConfig))
    suite.addTest(unittest.makeSuite(TestValidRulesetConfig))
    suite.addTest(unittest.makeSuite(TestInvalidRulesetConfig))
    suite.addTest(unittest.makeSuite(TestSample))
    suite.addTest(unittest.makeSuite(TestDatabase))
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
