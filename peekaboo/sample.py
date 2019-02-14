###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# sample.py                                                                   #
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


import os
import hashlib
import json
import random
import re
import shutil
import string
import logging
import tempfile
from datetime import datetime
from peekaboo.toolbox.files import guess_mime_type_from_file_contents, \
                                   guess_mime_type_from_filename
from peekaboo.toolbox.ms_office import has_office_macros
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

    A sample has attributes like:
    filename, MIME type, sha256, ...
    Those attributes are determined on demand kept in a dictionary, which is
    accessible through the methods has_attr, get_attr, and set_attr.

    The data structure works together with Cuckoo to run behavioral attributes.

    @author: Felix Bauer
    @author: Sebastian Deiss
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
        self.__cuckoo_report = None
        self.__done = False
        self.__status_change = status_change
        self.__rule_results = []
        self.__result = Result.unchecked
        self.__reason = None
        self.__report = []  # Peekaboo's own report
        self.__internal_report = []
        # Additional attributes for a sample object (e. g. meta info)
        self.__attributes = {}
        self.__file_stat = None
        self.__sha256sum = None
        self.__mimetypes = None
        self.__file_extension = None
        self.__office_macros = None
        self.__base_dir = base_dir
        self.__job_hash = None
        self.__job_hash_regex = job_hash_regex
        self.__keep_mail_data = keep_mail_data
        self.__processing_info_dir = processing_info_dir
        self.initialized = False

        if metainfo:
            for field in metainfo:
                logger.debug('meta_info_%s = %s', field, metainfo[field])

                # JSON will transfer null/None values but we don't want them as
                # attributes in that case
                if metainfo[field] is not None:
                    self.set_attr('meta_info_' + field, metainfo[field])

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
            return

        logger.debug("initializing sample")

        # create a symlink to submit the file with the correct file extension
        # to cuckoo via submit.py - but only if we can actually figure out an
        # extension. Otherwise the point is moot.
        self.__submit_path = self.__path
        file_ext = self.file_extension
        if file_ext:
            # create a temporary directory where mkdtemp makes sure that
            # creation is atomic, i.e. no other process is using it
            self.__wd = tempfile.mkdtemp(
                prefix=self.job_hash, dir=self.__base_dir)
            self.__submit_path = os.path.join(
                self.__wd, '%s.%s' % (self.sha256sum, file_ext))

            logger.debug('ln -s %s %s' % (self.__path, self.__submit_path))
            os.symlink(self.__path, self.__submit_path)

        self.initialized = True

        message = "Datei \"%s\" %s wird analysiert" % (self.__filename,
                                                         self.sha256sum)
        self.__report.append(message)

        # log some additional info to report to aid debugging
        if self.has_attr('meta_info_name_declared'):
            self.__internal_report.append(
                "meta info: name_declared: %s" %
                self.get_attr('meta_info_name_declared'))

        if self.has_attr('meta_info_type_declared'):
            self.__internal_report.append(
                "meta info: type_declared: %s" %
                self.get_attr('meta_info_type_declared'))

    def get_attr(self, key):
        """
        Get a sample attribute by a specified key.

        @param key: The identifier of the sample attribute to get.
        """
        if self.has_attr(key):
            return self.__attributes[key]
        raise KeyError("Attribute for key '%s' not found." % key)

    def set_attr(self, key, val, override=True):
        """
        Add an attribute to a sample.

        @param key: The identifier of the attribute.
        @param val: The attribute to add.
        @param override: Whether the existing attribute shall be overwritten or not.
        """
        if self.has_attr(key) and override is False:
            raise KeyError("Key '%s' already exists." % key)
        self.__attributes[key] = val

    def has_attr(self, key):
        """
        Check if an attribute exists for this sample.

        @param key: The identifier of the attribute.
        """
        if key in self.__attributes.keys():
            return True
        return False

    def remove_attr(self, key):
        """
        Delete an attribute for this sample.

        @param key: The identifier of the attribute
        @raises ValueError: if the given key was not found in
                            the attributes dictionary.
        """
        if key in self.__attributes.keys():
            del self.__attributes[key]
        raise ValueError('No attribute named "%s" found.' % key)

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
        # message = "Die Datei \"%s\" wurde als \"%s\" eingestuft\n\n"
        # Changed intentionally to not trigger configured god/bad matching
        # patterns in clients (e.g. AMaViS) any more since we switched to
        # reporting an overall analysis batch result.
        return self.__report + ["Die Datei \"%s\" wird als \"%s\" betrachtet\n"
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

        job_hash = re.sub('.*%s.*' % self.__job_hash_regex, r'\1',
                          self.__path)
        if job_hash == self.__path:
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
        logger.debug('Adding rule result %s' % str(res))
        self.__rule_results.append(res)

        logger.debug("Current overall result: %s, new rule result: %s",
                     self.__result, res.result)
        # check if result of this rule is worse than what we know so far
        if res.result >= self.__result:
            self.__result = res.result
            self.__reason = res.reason

        # also append a report message right away
        self.__report.append("Datei \"%s\": %s" % (self.__filename, str(res)))

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
            os.makedirs(dump_dir, 0o770)
        filename = self.__filename + '-' + self.sha256sum

        logger.debug('Dumping processing info to %s for sample %s',
                     dump_dir, self)

        # Peekaboo's report
        try:
            peekaboo_report = os.path.join(dump_dir, filename + '_report.txt')
            with open(peekaboo_report, 'w+') as f:
                f.write('\n'.join(self.__report))
                f.write('\n'.join(self.__internal_report))
        except IOError as ioerror:
            logger.exception(ioerror)

        # store malicious sample along with the reports
        if self.__result == Result.bad:
            try:
                shutil.copyfile(
                    self.__path,
                    os.path.join(dump_dir, self.__filename)
                )
            except IOError as ioerror:
                logger.exception(ioerror)

        # Cuckoo report
        if self.__cuckoo_report:
            try:
                cuckoo_report = os.path.join(dump_dir,
                                             filename + '_cuckoo_report.json')
                with open(cuckoo_report, 'w+') as f:
                    json.dump(self.__cuckoo_report.raw, f, indent=1)
            except IOError as ioerror:
                logger.exception(ioerror)

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
    def file_extension(self):
        """ Determines the file extension of this sample. """
        if self.__file_extension:
            return self.__file_extension

        # try to find a file name containing an extension. Using
        # self.__filename will almost never yield anything useful because
        # amavis intentionally hands us files named only p001, p002 and so on.
        # But we still try it in case there's no declared name.
        filename = self.__filename
        if self.has_attr('meta_info_name_declared'):
            filename = self.get_attr('meta_info_name_declared')

        # extension or the empty string if none found
        self.__file_extension = os.path.splitext(filename)[1][1:]
        return self.__file_extension

    @property
    def mimetypes(self):
        """ Determines the mimetypes of this sample. """
        if self.__mimetypes:
            return self.__mimetypes

        mime_types = set()

        # get MIME type from meta info
        declared_mt = None
        if self.has_attr('meta_info_type_declared'):
            declared_mt = self.get_attr('meta_info_type_declared')
            if declared_mt is not None:
                logger.debug('Sample declared as "%s"' % declared_mt)
                mime_types.add(declared_mt)

        declared_filename = self.__filename
        if self.has_attr('meta_info_name_declared'):
            declared_filename = self.get_attr('meta_info_name_declared')

        # check if the sample is an S/MIME signature (smime.p7s)
        # If so, don't overwrite the MIME type since we do not want to analyse
        # S/MIME signatures.
        # FIXME: This is oddly specific for this generic routine. Should it be
        # some sort of callback or plugin?
        leave_alone_types = {
            'p7s': [
                'application/pkcs7-signature',
                'application/x-pkcs7-signature',
                'application/pkcs7-mime',
                'application/x-pkcs7-mime',
            ]
        }

        if declared_filename == 'smime.p7s' and declared_mt in leave_alone_types['p7s']:
            logger.info('S/MIME signature detected. Using declared MIME type over detected ones.')
            self.__mimetypes = set([declared_mt])
            return self.__mimetypes

        # determine mime on original p[0-9]* file
        # result of __submit_path would be "inode/symlink"
        content_based_mime_type = guess_mime_type_from_file_contents(self.__path)
        if content_based_mime_type is not None:
            mime_types.add(content_based_mime_type)

        name_based_mime_type = guess_mime_type_from_filename(declared_filename)
        if name_based_mime_type is not None:
            mime_types.add(name_based_mime_type)

        logger.debug('Determined MIME Types: %s' % mime_types)
        self.__mimetypes = mime_types
        return mime_types

    @property
    def job_id(self):
        return self.__cuckoo_job_id

    @property
    def office_macros(self):
        """ Determines if this sample contains any office macros. """
        if not self.__office_macros:
            self.__office_macros = has_office_macros(self.__path)

        return self.__office_macros

    @property
    def file_size(self):
        if not self.__file_stat:
            self.__file_stat = os.stat(self.__path)

        return self.__file_stat.st_size

    @property
    def cuckoo_report(self):
        """ Returns the cuckoo report """
        return self.__cuckoo_report

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
        message = 'Erfolgreich an Cuckoo gegeben %s als Job %d' \
                  % (self, self.__cuckoo_job_id)
        self.__internal_report.append(message)
        return self.__cuckoo_job_id

    def register_cuckoo_report(self, report):
        """ Records a Cuckoo report for later evaluation. """
        self.__cuckoo_report = report

    def cleanup(self):
        """ Clean up after the sample has been analysed, removing a potentially
        created workdir. """
        # nothing to do if we never created a workdir
        if not self.__wd:
            return

        if self.__keep_mail_data:
            logger.debug('Keeping mail data in %s' % self.__wd)
            return

        logger.debug("Deleting tempdir %s" % self.__wd)
        try:
            shutil.rmtree(self.__wd)
        except OSError as e:
            logger.exception(e)

    def __str__(self):
        return ("<Sample(filename='%s', job_id='%d',"
                " result='%s', sha256sum='%s')>"
                % (self.__filename,
                   self.__cuckoo_job_id,
                   self.__result,
                   self.sha256sum))

    __repr__ = __str__
