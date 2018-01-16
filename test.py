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

from peekaboo.sample import Sample
from peekaboo.ruleset import RuleResult, Result
from peekaboo.db import PeekabooDatabase
from peekaboo.config import _set_config


class PeekabooDummyConfig(object):
    def __init__(self):
        self.db_con = None
        self.job_hash_regex = r'/var/lib/amavis/tmp/([^/]+)/parts.*'
        self.sample_base_dir = '/tmp'
        self.chown2me_exec = 'bin/chown2me'

    def set_db_con(self, db_con):
        self.db_con = db_con

    def get_db_con(self):
        return self.db_con


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

    def close(self):
        pass

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
        db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.conf.set_db_con(db_con)
        _set_config(cls.conf)
        cls.sample = Sample(os.path.realpath(__file__))
        result = RuleResult('Unittest',
                            Result.unknown,
                            'This is just a test case.',
                            further_analysis=True)
        cls.sample.add_rule_result(result)
        cls.sample.determine_result()

    def test_1_analysis2db(self):
        self.conf.db_con.analysis2db(self.sample)

    def test_2_sample_info_fetch(self):
        sample_info = self.conf.db_con.sample_info_fetch(self.sample)
        self.assertEqual(self.sample.sha256sum, sample_info.sha256sum)

    def test_3_sample_info_update(self):
        result = RuleResult('Unittest',
                            Result.checked,
                            'This is another test case.',
                            further_analysis=False)
        self.sample.add_rule_result(result)
        self.sample.determine_result()
        self.conf.db_con.sample_info_update(self.sample)
        rule_result = self.conf.db_con.fetch_rule_result(self.sample)
        self.assertEqual(rule_result.result, Result.checked)
        self.assertEqual(rule_result.reason, 'This is another test case.')

    def test_4_fetch_rule_result(self):
        rule_result = self.conf.db_con.fetch_rule_result(self.sample)
        # RuleResults from the DB have 'db' as rule name
        self.assertEqual(rule_result.rule, 'db')
        self.assertEqual(rule_result.result, Result.checked)
        self.assertEqual(rule_result.reason, 'This is another test case.')
        # We assert True since the DB rule result always sets further_analysis to True
        self.assertTrue(rule_result.further_analysis)

    def test_5_known(self):
        self.assertTrue(self.conf.db_con.known(self.sample))
        self.assertFalse(self.conf.db_con.in_progress(self.sample))

    @classmethod
    def tearDownClass(cls):
        cls.conf.db_con.close()
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
        db_con = PeekabooDatabase('sqlite:///' + cls.test_db)
        cls.conf.set_db_con(db_con)
        _set_config(cls.conf)
        cls.sample = Sample(os.path.realpath(__file__))

    def test_attribute_dict(self):
        self.sample.set_attr('Unittest', 'Hello World!')
        self.assertTrue(self.sample.has_attr('Unittest'))
        self.assertEqual(self.sample.get_attr('Unittest'), 'Hello World!')
        self.sample.set_attr('Unittest', 'Test', override=True)
        self.assertEqual(self.sample.get_attr('Unittest'), 'Test')

    def test_job_hash_regex(self):
        path_with_job_hash = '/var/lib/amavis/tmp/amavis-20170831T132736-07759-iSI0rJ4b/parts'
        sample = Sample(path_with_job_hash)
        job_hash = sample.get_job_hash()
        self.assertEqual(job_hash, 'amavis-20170831T132736-07759-iSI0rJ4b',
                         'Job hash regex is not working')
        job_hash = self.sample.get_job_hash()
        self.assertIn('peekaboo-run_analysis', job_hash)

    def test_sample_attributes(self):
        self.assertEqual(self.sample.get_filename(), 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertTrue(self.__contains_mime(self.sample.mimetypes, 'text/x-python'))
        self.assertIsNotNone(self.sample.sha256sum)
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.get_result(), Result.unchecked)
        self.assertEqual(self.sample.reason,
                         'Ausschlaggebendes Ergebnis laut Datenbank: Datei ist dem System noch nicht bekannt')
        self.assertFalse(self.sample.office_macros)
        self.assertFalse(self.sample.known)

    def test_sample_attributes_with_meta_info(self):
        test_meta_info = '[attachment]\n'
        test_meta_info += 'full_name     : /tmp/test.pyc\n'
        test_meta_info += 'name_declared : test.pyc\n'
        test_meta_info += 'type_declared : application/x-bytecode.python\n'
        test_meta_info += 'type_long     : application/x-python-bytecode\n'
        test_meta_info += 'type_short    : pyc\n'
        test_meta_info += 'size          : 200\n'
        test_meta_info += 'digest        :\n'
        test_meta_info += 'attributes    :\n'
        test_meta_info += 'queue_id      :\n'
        with open('./test_meta_info.info', 'w+') as f:
            f.write(test_meta_info)
        self.sample.load_meta_info('./test_meta_info.info')
        self.assertEqual(self.sample.file_extension, 'pyc')

    def test_sample_without_suffix(self):
        test_meta_info = '[attachment]\n'
        test_meta_info += 'full_name     : /tmp/junk\n'
        test_meta_info += 'name_declared : Report.docx\n'
        test_meta_info += 'type_declared : application/vnd.openxmlformats-officedocument.wordprocessingml.document\n'
        test_meta_info += 'type_long     : application/vnd.openxmlformats-officedocument.wordprocessingml.document\n'
        test_meta_info += 'type_short    : docx\n'
        test_meta_info += 'size          : 212\n'
        test_meta_info += 'digest        :\n'
        test_meta_info += 'attributes    :\n'
        test_meta_info += 'queue_id      :\n'
        with open('./junk.info', 'w+') as f:
            f.write(test_meta_info)
        sample = Sample('junk')
        self.assertEqual(sample.file_extension, '')
        sample.load_meta_info('./junk.info')
        self.assertEqual(sample.file_extension, 'docx')

    @classmethod
    def tearDownClass(cls):
        cls.conf.db_con.close()
        os.unlink(cls.test_db)
        os.unlink('./test_meta_info.info')
        os.unlink('./junk.info')

    def __contains_mime(self, mimetypes, mime):
        if mime in mimetypes:
            return True
        return False


def main():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSample))
    suite.addTest(unittest.makeSuite(TestDatabase))
    # TODO: We need more tests!!!

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
