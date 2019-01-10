#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# test.py                                                                     #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2018  science + computing ag                             #
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


import sys
import os
import hashlib
import unittest
from datetime import datetime, timedelta


# Add Peekaboo to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peekaboo.sample import SampleFactory
from peekaboo.ruleset import RuleResult, Result
from peekaboo.ruleset.rules import FileTypeOnWhitelistRule, FileTypeOnGreylistRule
from peekaboo.db import PeekabooDatabase, PeekabooDatabaseError

class PeekabooDummyConfig(object):
    def __init__(self):
        self.job_hash_regex = r'/var/lib/amavis/tmp/([^/]+)/parts.*'
        self.sample_base_dir = '/tmp'

    def get(self, option, default):
        config = {
            'whitelist':['text/plain', 'inode/x-empty'],
            'greylist' :['application/x-dosexec', 'application/msword', 'application/vnd.ms-powerpoint'],
        }
        return config[option]


class TestDatabase(unittest.TestCase):
    """
    Unittests for Peekaboo's database module.

    @author: Sebastian Deiss
    """
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = PeekabooDummyConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db,
                instance_id=0, stale_in_flight_threshold=10)
        cls.factory = SampleFactory(cuckoo = None,
                db_con = cls.db_con,
                connection_map = None,
                base_dir = cls.conf.sample_base_dir,
                job_hash_regex = cls.conf.job_hash_regex,
                keep_mail_data = False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))
        result = RuleResult('Unittest',
                            Result.checked,
                            'This is just a test case.',
                            further_analysis=False)
        cls.sample.add_rule_result(result)
        cls.sample.determine_result()

    def test_1_analysis_save(self):
        self.db_con.analysis_save(self.sample)

    def test_2_sample_info_fetch(self):
        sample_info = self.db_con.sample_info_fetch(self.sample)
        self.assertEqual(self.sample.sha256sum, sample_info.sha256sum)

    def test_3_fetch_result(self):
        sample_info = self.db_con.sample_info_fetch(self.sample)
        self.assertEqual(sample_info.result, Result.checked)
        self.assertEqual(sample_info.reason, 'This is just a test case.')

    def test_5_in_flight_no_cluster(self):
        # should all behave as no-ops
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 0))
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 0))
        self.assertIsNone(self.db_con.clear_sample_in_flight(self.sample, 0))
        self.assertIsNone(self.db_con.clear_sample_in_flight(self.sample, 0))

    def test_6_in_flight_cluster(self):
        self.assertTrue(self.db_con.mark_sample_in_flight(self.sample, 1))
        # re-locking the same sample should fail
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertIsNone(self.db_con.clear_sample_in_flight(self.sample, 1))
        # unlocking twice should fail
        self.assertRaisesRegexp(PeekabooDatabaseError, "Unexpected "
            "inconsistency: Sample .* not recoreded as in-flight upon "
            "clearing flag",
            self.db_con.clear_sample_in_flight, self.sample, 1)

    def test_7_in_flight_clear(self):
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

        # should be a no-op
        self.assertIsNone(self.db_con.clear_in_flight_samples(0))
        self.assertFalse(self.db_con.mark_sample_in_flight(self.sample, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample2, 1))
        self.assertFalse(self.db_con.mark_sample_in_flight(sample3, 2))

        # leave as found
        self.assertIsNone(self.db_con.clear_in_flight_samples(-1))

    def test_8_stale_in_flight(self):
        stale = datetime.utcnow() - timedelta(seconds=20)
        self.assertTrue(self.db_con.mark_sample_in_flight(
            self.sample, 1, stale))
        sample2 = self.factory.make_sample('foo.pyc')
        sample2.set_attr('sha256sum', hashlib.sha256('foo').hexdigest())
        self.assertTrue(self.db_con.mark_sample_in_flight(sample2, 1))

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
        os.unlink(cls.test_db)


class TestSample(unittest.TestCase):
    """
    Unittests for Samples.

    @author: Sebastian Deiss
    """
    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.abspath('./test.db')
        cls.conf = PeekabooDummyConfig()
        cls.db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.factory = SampleFactory(cuckoo = None,
                db_con = cls.db_con,
                connection_map = None,
                base_dir = cls.conf.sample_base_dir,
                job_hash_regex = cls.conf.job_hash_regex,
                keep_mail_data = False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))

    def test_attribute_dict(self):
        self.sample.set_attr('Unittest', 'Hello World!')
        self.assertTrue(self.sample.has_attr('Unittest'))
        self.assertEqual(self.sample.get_attr('Unittest'), 'Hello World!')
        self.sample.set_attr('Unittest', 'Test', override=True)
        self.assertEqual(self.sample.get_attr('Unittest'), 'Test')

    def test_job_hash_regex(self):
        path_with_job_hash = '/var/lib/amavis/tmp/amavis-20170831T132736-07759-iSI0rJ4b/parts'
        sample = self.factory.make_sample(path_with_job_hash)
        job_hash = sample.get_job_hash()
        self.assertEqual(job_hash, 'amavis-20170831T132736-07759-iSI0rJ4b',
                         'Job hash regex is not working')
        job_hash = self.sample.get_job_hash()
        self.assertIn('peekaboo-run_analysis', job_hash)

    def test_sample_attributes(self):
        self.assertEqual(self.sample.get_filename(), 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertTrue(set(['text/x-python']).issubset(set(self.sample.mimetypes)))
        self.assertIsNotNone(self.sample.sha256sum)
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.get_result(), Result.unchecked)
        self.assertEqual(self.sample.get_reason(), None)
        self.assertFalse(self.sample.office_macros)

    def test_sample_attributes_with_meta_info(self):
        sample = self.factory.make_sample('test.pyc', {
            'full_name': '/tmp/test.pyc',
            'name_declared': 'test.pyc',
            'type_declared': 'application/x-bytecode.python',
            'type_long': 'application/x-python-bytecode',
            'type_short': 'pyc',
            'size': '200' })
        self.assertEqual(sample.file_extension, 'pyc')

    def test_sample_without_suffix(self):
        sample = self.factory.make_sample('junk', {
            'full_name': '/tmp/junk',
            'name_declared': 'Report.docx',
            'type_declared': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'type_long': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'type_short': 'docx',
            'size': '212' })
        self.assertEqual(sample.file_extension, 'docx')

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.test_db)


class TestRules(unittest.TestCase):
    """
    Unittests for Rules.

    @author: Felix Bauer
    """
    @classmethod
    def setUpClass(cls):
        cls.conf = PeekabooDummyConfig()
        cls.factory = SampleFactory(cuckoo = None,
                db_con = None,
                connection_map = None,
                base_dir = cls.conf.sample_base_dir,
                job_hash_regex = cls.conf.job_hash_regex,
                keep_mail_data = False)
        cls.sample = cls.factory.make_sample(os.path.realpath(__file__))

    def test_rule_file_type_on_whitelist(self):
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
            r = rule.evaluate(self.sample)
            self.assertEqual(r.further_analysis, expected)

    def test_rule_file_type_on_greylist(self):
        combinations = [
            [False, ['text/plain']],
            [True, ['application/msword']],
            [True, ['text/plain', 'application/x-dosexec']],
            [True, ['image/png', 'application/zip', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint']],
            [False, ['', 'asdfjkl', '93219843298']],
            [True, []],
        ]
        rule = FileTypeOnGreylistRule(self.conf)
        for expected, types in combinations:
            self.sample.set_attr('mimetypes', set(types))
            r = rule.evaluate(self.sample)
            self.assertEqual(r.further_analysis, expected)

    @classmethod
    def tearDownClass(cls):
        pass

def main():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSample))
    suite.addTest(unittest.makeSuite(TestDatabase))
    suite.addTest(unittest.makeSuite(TestRules))
    # TODO: We need more tests!!!

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
