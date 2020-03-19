###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# sample.py                                                                   #
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


import os
import hashlib
import json
import random
import re
import shutil
import string
import logging
import tempfile
# python 3's open with encoding parameter and implicit usage of the system
# locale-specified encoding
from builtins import open
from datetime import datetime
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)

class SampleFactory(object):
    """ A class for churning out loads of mostly identical sample objects.
    Contains all the global configuration data and object references each
    sample needs and thus serves as a registry of potential API breakage
    perhaps deserving looking into. """
    def __init__(self, cuckoo, base_dir, job_hash_regex,
                 keep_mail_data, processing_info_dir):
        # object references for interaction
        self.cuckoo = cuckoo

        # configuration
        self.base_dir = base_dir
        self.job_hash_regex = job_hash_regex
        self.keep_mail_data = keep_mail_data
        self.processing_info_dir = processing_info_dir

    def make_sample(self, file_path, status_change=None, metainfo=None):
        """ Create a new Sample object based on the factory's configured
        defaults and variable parameters. """
        return Sample(file_path, self.cuckoo, status_change, metainfo,
                      self.base_dir, self.job_hash_regex, self.keep_mail_data,
                      self.processing_info_dir)


class Sample(object):
    """
    This class handles and describes samples to be analysed by Peekaboo.

    A sample has properties like filename, MIME type, checksum or file size.
    These are accessible as properties. Most properties determine their value
    on first access, especially if that determination is somewhat expensive
    such as the file checksum.

    The data structure works together with Cuckoo to run behavioral analysis.
    """
    def __init__(self, file_path, cuckoo=None, status_change=None,
                 metainfo=None, base_dir=None, job_hash_regex=None,
                 keep_mail_data=False, processing_info_dir=None):
        self.__path = file_path
        self.__cuckoo = cuckoo
        self.__wd = None
        self.__filename = os.path.basename(self.__path)
        # A symlink that points to the actual file named
        # sha256sum.suffix
        self.__submit_path = None
        self.__cuckoo_job_id = -1
        self.__cuckoo_failed = False
        self.__cuckoo_report = None
        self.__oletools_report = None
        self.__filetools_report = None
        self.__done = False
        self.__status_change = status_change
        self.__result = Result.unchecked
        self.__reason = None
        self.__report = []  # Peekaboo's own report
        self.__internal_report = []
        self.__file_stat = None
        self.__sha256sum = None
        self.__file_extension = None
        self.__base_dir = base_dir
        self.__job_hash = None
        self.__job_hash_regex = job_hash_regex
        self.__keep_mail_data = keep_mail_data
        self.__processing_info_dir = processing_info_dir

        # Additional attributes for a sample object (i.e. meta info)
        # We do not make these private for the following reasons:
        # - this way they still somewhat resemble the previous arbitrary
        #   attribute dictionary idea
        # - we'd have to implement the name mangling for setting below
        # Even though, it is not recommended to access them directly they're an
        # implementation detail. We add respective properties for that.
        #
        # Security: Add more below to allow them to be accepted from the
        # client. We don't want anyone to be able to pollute our sample
        # objects from the outside. This also serves as a registry of what we
        # actually use and know how to deal with.
        self.meta_info_name_declared = None
        self.meta_info_type_declared = None
        self.meta_info_content_disposition = None

        self.initialized = False

        if metainfo:
            member_variables = vars(self)
            for field in metainfo:
                logger.debug('meta_info_%s = %s', field, metainfo[field])

                # JSON will transfer null/None values but we don't want them as
                # attributes in that case
                member = 'meta_info_%s' % field
                if member in member_variables and metainfo[field] is not None:
                    member_variables[member] = metainfo[field]

    def init(self):
        """
        Initialize the Sample object.

        The actual initialization is done here, because the main thread should
        not do the heavy lifting of e. g. parsing the meta info file to be able
        to accept new connections as quickly as possible.
        Instead, it only adds the sample objects to the queue and the workers
        to the actual initialization.
        """
        if self.initialized:
            return True

        logger.debug("initializing sample")

        # create a temporary directory where mkdtemp makes sure that
        # creation is atomic, i.e. no other process is using it
        try:
            self.__wd = tempfile.mkdtemp(
                prefix=self.job_hash, dir=self.__base_dir)
        except OSError as oserr:
            logger.error('Error creating working directory: %s', oserr)
            return False

        logger.debug('Working directory %s created', self.__wd)

        # create a symlink to submit the file with the correct file extension
        # to cuckoo via submit.py. This is so we do not leak the original
        # filename by default.
        submit_name = self.sha256sum
        if self.file_extension:
            submit_name = '%s.%s' % (submit_name, self.file_extension)

        self.__submit_path = os.path.join(self.__wd, submit_name)

        try:
            os.symlink(self.__path, self.__submit_path)
        except OSError as oserr:
            logger.error('Error linking sample from %s to working '
                         'directory as %s',
                         self.__path, self.__submit_path)
            self.cleanup()
            return False

        logger.debug('Sample symlinked from %s to %s',
                     self.__path, self.__submit_path)

        self.initialized = True

        self.__report.append(_("File \"%s\" %s is being analyzed")
                             % (self.__filename, self.sha256sum))

        # log some additional info to report to aid debugging
        if self.meta_info_name_declared:
            self.__internal_report.append("meta info: name_declared: %s"
                                          % self.meta_info_name_declared)

        if self.meta_info_type_declared:
            self.__internal_report.append("meta info: type_declared: %s"
                                          % self.meta_info_type_declared)

        return True

    @property
    def file_path(self):
        """ Returns the path to the sample given on creation including
        directories and filename. """
        return self.__path

    @property
    def filename(self):
        """ Returns the name of the sample file, i.e. the basename without path
        but including the file extension. """
        return self.__filename

    @property
    def result(self):
        """ Returns the overall evaluation result for this sample.

        @returns: peekaboo.ruleset.Result """
        return self.__result

    @property
    def reason(self):
        """ Gets the reason given by the rule determining the result which
        ended up as the overall evaluation result of this sample.

        @returns: string """
        return self.__reason

    @property
    def peekaboo_report(self):
        """ Return Peekaboo's report meant for the client, detailing what's
        been found on this sample.

        @returns: List of strings.
        """
        # This message used to be:
        # "Die Datei \"%s\" wurde als \"%s\" eingestuft\n\n"
        # Changed intentionally to not trigger configured god/bad matching
        # patterns in clients (e.g. AMaViS) any more since we switched to
        # reporting an overall analysis batch result.
        return self.__report + [_("File \"%s\" is considered \"%s\"")
                                % (self.__filename, self.__result.name)]

    @property
    def done(self):
        """ Tells whether the analysis of the sample is done, i.e. a final
        verdict has been reached and a result and reason are available. """
        return self.__done

    def mark_done(self):
        """ Mark this sample as done, i.e. fully analysed and verdict reached.
        """
        self.__done = True
        if self.__status_change:
            # notify whoever is interested that our status has changed
            self.__status_change.set()

    def generate_job_hash(self, size=8):
        """
        Generates a job hash (default: 8 characters).

        @param size: The amount of random characters to use for a job hash.
                     Defaults to 8.
        @return: a job hash consisting of a static prefix, a timestamp
                 representing the time when the method was invoked, and random
                 characters.
        """
        job_hash = 'peekaboo-run_analysis-'
        job_hash += '%s-' % datetime.now().strftime('%Y%m%dT%H%M%S')
        job_hash += ''.join(
            random.choice(string.digits + string.ascii_lowercase
                          + string.ascii_uppercase) for _ in range(size))
        return job_hash

    @property
    def job_hash(self):
        """ Returns a job identifier extracted from the file path using a
        configurable regular expression for use in other temporary or permanent
        (dump) path names to keep correlation to the original input job. """
        if self.__job_hash:
            return self.__job_hash

        match = re.search(self.__job_hash_regex, self.__path)
        if match is not None:
            job_hash = match.group(1)
        else:
            # regex did not match.
            # so we generate our own job hash and create the
            # working directory.
            job_hash = self.generate_job_hash()

        logger.debug("Job hash for this sample: %s" % job_hash)
        self.__job_hash = job_hash
        return job_hash

    def add_rule_result(self, res):
        """ Add a rule result to the sample. This also adds a message about
        this to the report and updates the overall analysis result (so far).
        """
        logger.debug('Adding rule result %s', res)
        self.__report.append(_("File \"%s\": %s") % (self.__filename, res))

        logger.debug("Current overall result: %s, new rule result: %s",
                     self.__result, res.result)
        # check if result of this rule is worse than what we know so far
        if res.result >= self.__result:
            self.__result = res.result
            self.__reason = res.reason

    def dump_processing_info(self):
        """
        Saves the Cuckoo report as HTML + JSON
        to a directory named after the job hash.
        """
        if not self.__processing_info_dir:
            logger.debug('Not dumping processing info because no path for the '
                         'data is unconfigured.')
            return

        dump_dir = os.path.join(self.__processing_info_dir, self.job_hash)
        if not os.path.isdir(dump_dir):
            try:
                os.makedirs(dump_dir, 0o770)
            except OSError as oserr:
                logger.error('Failed to create dump directory %s: %s',
                             dump_dir, oserr)
                return

        filename = self.__filename + '-' + self.sha256sum

        logger.debug('Dumping processing info to %s for sample %s',
                     dump_dir, self)

        # Peekaboo's report
        peekaboo_report = os.path.join(dump_dir, filename + '_report.txt')
        try:
            with open(peekaboo_report, 'w+') as pr_file:
                if self.__report:
                    pr_file.write('\n'.join(self.__report + [""]))
                if self.__internal_report:
                    pr_file.write('\n'.join(self.__internal_report + [""]))
        except (OSError, IOError) as error:
            logger.error('Failure to write report file %s: %s',
                         peekaboo_report, error)
            return

        # store malicious sample along with the reports
        if self.__result == Result.bad:
            try:
                shutil.copyfile(
                    self.__path,
                    os.path.join(dump_dir, self.__filename)
                )
            except (shutil.Error, IOError, OSError) as error:
                logger.error('Failure to copy sample file %s to dump '
                             'directory: %s', self.__path, error)
                return

        # Cuckoo report
        if self.__cuckoo_report:
            cuckoo_report = os.path.join(dump_dir,
                                         filename + '_cuckoo_report.json')
            try:
                with open(cuckoo_report, 'wb+') as cr_json_file:
                    cr_json = json.dumps(self.__cuckoo_report.raw,
                                         indent=1, ensure_ascii=True)
                    cr_json_file.write(cr_json.encode('ascii'))
            except (OSError, IOError) as error:
                logger.error('Failure to dump json report to %s: %s',
                             cuckoo_report, error)
                return

    @property
    def sha256sum(self):
        """ Returns the SHA256 checksum/fingerprint of this sample. Determines
        it automatically on first call. """

        if not self.__sha256sum:
            with open(self.__path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
                self.__sha256sum = checksum

        return self.__sha256sum

    @property
    def content_disposition(self):
        """ Returns the content disposition in the original email, e.g. inline
        or attachment, None if not available. """
        return self.meta_info_content_disposition

    @property
    def name_declared(self):
        """ Returns the name declared by the sample as its original filename,
        None if not available. """
        return self.meta_info_name_declared

    @property
    def file_extension(self):
        """ Determines the file extension of this sample. """
        if self.__file_extension:
            return self.__file_extension

        # try to find a file name containing an extension. Using
        # self.__filename will almost never yield anything useful because
        # amavis intentionally hands us files named only p001, p002 and so on.
        # But we still try it in case there's no declared name.
        filename = self.__filename
        if self.name_declared:
            filename = self.name_declared

        # extension or the empty string if none found
        self.__file_extension = os.path.splitext(filename)[1][1:]
        return self.__file_extension

    @property
    def type_declared(self):
        """ Returns the MIME type declared by the original MIME part, None if
        not available. """
        return self.meta_info_type_declared

    @property
    def job_id(self):
        return self.__cuckoo_job_id

    @property
    def file_size(self):
        """ Determine and cache sample file size

        @raises: OSError if e.g. file does not exist or is inaccessible """
        if not self.__file_stat:
            self.__file_stat = os.stat(self.__path)

        return self.__file_stat.st_size

    @property
    def cuckoo_failed(self):
        """ Returns whether the Cuckoo analysis failed. """
        return self.__cuckoo_failed

    @property
    def cuckoo_report(self):
        """ Returns the cuckoo report """
        return self.__cuckoo_report

    @property
    def oletools_report(self):
        """ Returns the oletools report """
        return self.__oletools_report

    @property
    def filetools_report(self):
        """ Returns the filetools report """
        return self.__filetools_report

    @property
    def submit_path(self):
        """ Returns the path to use for submission to Cuckoo """
        return self.__submit_path

    def submit_to_cuckoo(self):
        """ Submit the sample to Cuckoo for analysis and record job id.

        @raises: CuckooAnalsisFailedException if submission failed
        @returns: cuckoo job id
        """
        logger.debug("Submitting %s to Cuckoo", self.__submit_path)
        self.__cuckoo_job_id = self.__cuckoo.submit(self)
        self.__internal_report.append(
            _('Sample %s successfully submitted to Cuckoo as job %d')
            % (self, self.__cuckoo_job_id))
        return self.__cuckoo_job_id

    def mark_cuckoo_failure(self):
        """ Records whether Cuckoo analysis failed. """
        self.__cuckoo_failed = True

    def register_cuckoo_report(self, report):
        """ Records a Cuckoo report for later evaluation. """
        self.__cuckoo_report = report

    def register_oletools_report(self, report):
        """ Records a Oletools report for alter evaluation. """
        self.__oletools_report = report

    def register_filetools_report(self, report):
        """ Records a Filetools report for alter evaluation. """
        self.__filetools_report = report

    def cleanup(self):
        """ Clean up after the sample has been analysed, removing a potentially
        created workdir. """
        # nothing to do if we never created a workdir
        if not self.__wd:
            return

        if self.__keep_mail_data:
            logger.debug('Keeping mail data in %s', self.__wd)
            return

        logger.debug("Deleting working directory %s", self.__wd)
        try:
            shutil.rmtree(self.__wd)
        except OSError as oserr:
            logger.error('Failed to remove working directory %s: %s',
                         self.__wd, oserr)

    def __str__(self):
        return ("<Sample(filename='%s', job_id='%d',"
                " result='%s', sha256sum='%s')>"
                % (self.__filename,
                   self.__cuckoo_job_id,
                   self.__result,
                   self.sha256sum))

    __repr__ = __str__
