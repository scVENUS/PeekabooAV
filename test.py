#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# test.py                                                                     #
###############################################################################
#                                                                             #
# Copyright (C) 2016-2017  science + computing ag                             #
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


class PeekabooDummyConfig(object):
    def __init__(self):
        self.db_con = None
        self.job_hash_regex = r"^.*\['(.*)'\].*$"
        self.sample_base_dir = '/tmp'
        self.chown2me_exec = 'bin/chown2me'

    def add_db_con(self, db_con):
        self.db_con = db_con

    def get_db_con(self):
        return self.db_con


class PeekabooDummyDB(object):
    def sample_info2db(self, sample):
        pass

    def get_rule_result(self, sha256):
        return  RuleResult('fake_db',
                            result=Result.checked,
                            reason='Test Case',
                            further_analysis=True)

    def update_sample_info(self, sample):
        pass

    def known(self, sha256):
        return  False

    def in_progress(self, sha256):
        return True

    def close(self):
        pass

    def _clear_in_progress(self):
        pass

    def _dump_samples(self):
        pass

    def _clear_sample_info_table(self):
        pass

    def _drop_sample_info_table(self):
        pass


class TestSample(unittest.TestCase):
    def setUp(self):
        self.conf = PeekabooDummyConfig()
        db_con = PeekabooDummyDB()
        self.conf.add_db_con(db_con)
        self.sample = Sample(self.conf, None, os.path.realpath(__file__))

    def test_sample_attributes(self):
        self.assertEqual(self.sample.get_filename(), 'test.py')
        self.assertEqual(self.sample.file_extension, 'py')
        self.assertTrue(self.__contains_mime(self.sample.mimetypes, 'text/x-python'))
        self.assertIsNotNone(self.sample.sha256sum)
        self.assertEqual(self.sample.job_id, -1)
        self.assertEqual(self.sample.get_result(), Result.unchecked)
        self.assertEqual(self.sample.reason,
                         'Ausschlaggebendes Ergebnis laut Datenbank: Test Case')
        self.assertFalse(self.sample.office_macros)
        self.assertFalse(self.sample.known)

    def tearDown(self):
        self.conf.db_con.close()

    def __contains_mime(self, mimetypes, mime):
        if mime in mimetypes:
            return True
        return False


def main():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestSample))
    # TODO: We need more tests!!!

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    if not result.wasSuccessful():
        sys.exit(1)


if __name__ == '__main__':
    main()
