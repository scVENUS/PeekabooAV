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
import unittest


# Add Peekaboo to PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from peekaboo.sample import SampleFactory
from peekaboo.ruleset import RuleResult, Result
from peekaboo.ruleset.rules import file_type_on_whitelist, file_type_on_greylist
from peekaboo.db import PeekabooDatabase

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


class PeekabooDummyDB(object):
    def sample_info2db(self, sample):
        pass

    def sample_info_fetch(self, sha256):
        pass

    def fetch_rule_result(self, sha256):
        return RuleResult('fake_db',
                          result=Result.checked,
                          reason='Test Case',
                          further_analysis=True)

    def sample_info_update(self, sample):
        pass

    def known(self, sha256):
        return False

    def in_progress(self, sha256):
        return True

    def _clear_in_progress(self):
        pass


class TestDatabase(unittest.TestCase):
    """
    Unittests for Peekaboo's database module.

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
        result = RuleResult('Unittest',
                            Result.unknown,
                            'This is just a test case.',
                            further_analysis=True)
        cls.sample.add_rule_result(result)
        cls.sample.determine_result()

    def test_1_analysis2db(self):
        self.db_con.analysis2db(self.sample)

    def test_2_sample_info_fetch(self):
        sample_info = self.db_con.sample_info_fetch(self.sample)
        self.assertEqual(self.sample.sha256sum, sample_info.sha256sum)

    def test_3_sample_info_update(self):
        result = RuleResult('Unittest',
                            Result.checked,
                            'This is another test case.',
                            further_analysis=False)
        self.sample.add_rule_result(result)
        self.sample.determine_result()
        self.db_con.sample_info_update(self.sample)
        rule_result = self.db_con.fetch_rule_result(self.sample)
        self.assertEqual(rule_result.result, Result.checked)
        self.assertEqual(rule_result.reason, 'This is another test case.')

    def test_4_fetch_rule_result(self):
        rule_result = self.db_con.fetch_rule_result(self.sample)
        # RuleResults from the DB have 'db' as rule name
        self.assertEqual(rule_result.rule, 'db')
        self.assertEqual(rule_result.result, Result.checked)
        self.assertEqual(rule_result.reason, 'This is another test case.')
        # We assert True since the DB rule result always sets further_analysis to True
        self.assertTrue(rule_result.further_analysis)

    def test_5_known(self):
        self.assertTrue(self.db_con.known(self.sample))
        self.assertFalse(self.db_con.in_progress(self.sample))

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
        self.assertEqual(self.sample.reason,
                         'Ausschlaggebendes Ergebnis laut Datenbank: Datei ist dem System noch nicht bekannt')
        self.assertFalse(self.sample.office_macros)
        self.assertFalse(self.sample.known)

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
            [False, []], # should this really result in no further_analysis?
        ]
        for expected, types in combinations:
            self.sample.set_attr('mimetypes', set(types))
            r = file_type_on_whitelist(self.conf, self.sample)
            self.assertEqual(r.further_analysis, expected)

    def test_rule_file_type_on_greylist(self):
        combinations = [
            [False, ['text/plain']],
            [True, ['application/msword']],
            [True, ['text/plain', 'application/x-dosexec']],
            [True, ['image/png', 'application/zip', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint']],
            [False, ['', 'asdfjkl', '93219843298']],
            [False, []],
        ]
        for expected, types in combinations:
            self.sample.set_attr('mimetypes', set(types))
            r = file_type_on_greylist(self.conf, self.sample)
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
