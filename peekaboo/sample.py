###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# sample.py                                                                   #
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


import datetime
import enum
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
from peekaboo.ruleset import Result


logger = logging.getLogger(__name__)


class SampleFactory:
    """ A class for churning out loads of mostly identical sample objects.
    Contains all the global configuration data and object references each
    sample needs and thus serves as a registry of potential API breakage
    perhaps deserving looking into. """
    def __init__(self, processing_info_dir):
        # configuration
        self.processing_info_dir = processing_info_dir

    def make_sample(self, content, name=None, content_type=None,
                    content_disposition=None):
        """ Create a new Sample object based on the factory's configured
        defaults and variable parameters. """
        return Sample(content, name, content_type, content_disposition,
                      self.processing_info_dir)


@enum.unique
class JobState(enum.Enum):
    """ Enumeration of states a job processing some sample can be in. """
    ACCEPTED = 1
    FINISHED = 2


class Sample:
    """
    This class handles and describes samples to be analysed by Peekaboo.

    A sample has properties like filename, MIME type, checksum or file size.
    These are accessible as properties. Most properties determine their value
    on first access, especially if that determination is somewhat expensive
    such as the file checksum.
    """
    def __init__(self, content, filename=None, content_type=None,
                 content_disposition=None,
                 processing_info_dir=None, job_id=None):
        # we do neither need nor accept for path traversal attack avoidance
        # full paths
        if filename is not None:
            filename = os.path.basename(filename)

        self.__content = content
        self.__filename = filename
        self.__content_type = content_type
        self.__content_disposition = content_disposition
        self.__cuckoo_failed = False
        self.__cuckoo_report = None
        self.__cortex_failed = False
        self.__cortex_report = None
        self.__oletools_report = None
        self.__filetools_report = None
        self.__knowntools_report = None
        self.__id = job_id
        self.__state = JobState.ACCEPTED
        self.__result = Result.unchecked
        self.__reason = None
        self.__report = []
        self.__sha256sum = None
        self.__file_extension = None
        self.__processing_info_dir = processing_info_dir

    @property
    def filename(self):
        """ Returns the name of the sample file, i.e. the basename without path
        but including the file extension. """
        return self.__filename

    @property
    def content(self):
        """ Returns the content of the sample file. """
        return self.__content

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
    def id(self):
        """ Return the (job) ID of this sample. """
        return self.__id

    def update_id(self, job_id):
        """ Update the (job) ID of this sample. """
        self.__id = job_id

    @property
    def state(self):
        """ Tells whether the analysis of the sample is done, i.e. a final
        verdict has been reached and a result and reason are available. """
        return self.__state

    def mark_done(self):
        """ Mark this sample as done, i.e. fully analysed and verdict reached.
        """
        self.__state = JobState.FINISHED

    def add_rule_result(self, res):
        """ Add a rule result to the sample. This also adds a message about
        this to the report and updates the overall analysis result (so far).
        """
        res_str = "%s" % res
        logger.debug("%d: Adding rule result %s", self.__id, res_str)
        self.__report.append(res_str)

        logger.debug("%d: Current overall result: %s, new rule result: %s",
                     self.__id, self.__result, res.result)
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

        now = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        dump_dir = os.path.join(
            self.__processing_info_dir, "%s-%s" % (now, self.sha256sum))
        if not os.path.isdir(dump_dir):
            try:
                os.makedirs(dump_dir, 0o770)
            except OSError as oserr:
                logger.error('Failed to create dump directory %s: %s',
                             dump_dir, oserr)
                return

        logger.debug('%d: Dumping processing info to %s',
                     self.__id, dump_dir)

        # Peekaboo's report
        peekaboo_report = os.path.join(dump_dir, 'report.txt')
        try:
            with open(peekaboo_report, 'w+') as pr_file:
                pr_file.write('Declared file name: %s\n' % self.__filename)
                pr_file.write(
                    'Declared content type: %s\n' % self.__content_type)
                pr_file.write(
                    'Declared content disposition: %s\n' %
                    self.__content_disposition)
                if self.__report:
                    pr_file.write('\n'.join(self.__report + [""]))
        except (OSError, IOError) as error:
            logger.error('Failure to write report file %s: %s',
                         peekaboo_report, error)
            return

        # store malicious sample along with the reports
        if self.__result == Result.bad:
            sample_dump = os.path.join(dump_dir, 'sample.bin')
            try:
                with open(sample_dump, 'wb') as dump_file:
                    dump_file.write(self.__content)
            except (shutil.Error, IOError, OSError) as error:
                logger.error('Failure to dump sample file to dump '
                             'directory: %s', error)
                return

        # Cuckoo report
        if self.__cuckoo_report:
            cuckoo_report = os.path.join(dump_dir, 'cuckoo_report.json')
            try:
                with open(cuckoo_report, 'wb+') as cr_json_file:
                    cr_json = json.dumps(self.__cuckoo_report.dump,
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
            self.__sha256sum = hashlib.sha256(self.__content).hexdigest()

        return self.__sha256sum

    @property
    def content_disposition(self):
        """ Returns the content disposition in the original email, e.g. inline
        or attachment, None if not available. """
        return self.__content_disposition

    # for compat with ruleset
    @property
    def name_declared(self):
        """ Returns the name declared by the sample as its original filename,
        None if not available. """
        return self.__filename

    @property
    def file_extension(self):
        """ Determines the file extension of this sample. """
        if self.__file_extension:
            return self.__file_extension

        # no extension if we have not filename to extract it from
        if self.__filename is None:
            return None

        ext = os.path.splitext(self.__filename)[1][1:]

        # sanity checks, where splitext already promises:
        # - ext is empty or
        # - begins with a period and contains at most one period.
        #   [and we already strippped that period]
        # - Leading periods on the basename are ignored;
        # We extend that to:
        # - allow only ascii (no Unicode)
        # - allow only printable characters (no control codes)
        # - allow only alphanumeric characters and some symbols (arbitrarily
        #   chosen based on file extension list in Wikipedia and personal
        #   experience)
        allowed_characters = string.ascii_letters + string.digits

        # we're seeing attachments whose declared filenames include what seems
        # to be meant as query strings (e.g. foo.jpg?resize=600,510). Since
        # there are no file extensions we know of containing those characters,
        # we do not allow them. Since we cannot find any document stating that
        # the name parameter of header Content-Type can contain URLs/URIs,
        # we're not even attempting to go down the rabbit hole of parsing it as
        # such to avoid the inevitable fallout from it. Instead we rather not
        # extract any extension at all.
        allowed_characters += string.punctuation.translate(
                str.maketrans('', '', '?;&'))

        # test works indirectly by stripping what is allowed from beginning and
        # end of the extension and checking that nothing remains.
        if ext.strip(allowed_characters):
            return None

        self.__file_extension = ext
        return self.__file_extension

    @property
    def type_declared(self):
        """ Returns the MIME type declared by the original MIME part, None if
        not available. """
        return self.__content_type

    @property
    def file_size(self):
        """ Return sample file size based on content length. """
        return len(self.__content)

    @property
    def cuckoo_failed(self):
        """ Returns whether the Cuckoo analysis failed. """
        return self.__cuckoo_failed

    @property
    def cuckoo_report(self):
        """ Returns the cuckoo report """
        return self.__cuckoo_report

    @property
    def cortex_failed(self):
        """ Returns whether a Cortex analysis failed. """
        return self.__cortex_failed

    @property
    def cortex_report(self):
        """ Returns the Cortex report. """
        return self.__cortex_report

    @property
    def oletools_report(self):
        """ Returns the oletools report """
        return self.__oletools_report

    @property
    def filetools_report(self):
        """ Returns the filetools report """
        return self.__filetools_report

    @property
    def knowntools_report(self):
        """ Returns the knowntools report """
        return self.__knowntools_report

    def mark_cuckoo_failure(self):
        """ Records whether Cuckoo analysis failed. """
        self.__cuckoo_failed = True

    def register_cuckoo_report(self, report):
        """ Records a Cuckoo report for later evaluation. """
        self.__cuckoo_report = report

    def mark_cortex_failure(self):
        """ Records whether Cortex analysis failed. """
        self.__cortex_failed = True

    def register_cortex_report(self, report):
        """ Records a Cortex report for later evaluation. """
        self.__cortex_report = report

    def register_oletools_report(self, report):
        """ Records a Oletools report for alter evaluation. """
        self.__oletools_report = report

    def register_filetools_report(self, report):
        """ Records a Filetools report for alter evaluation. """
        self.__filetools_report = report

    def register_knowntools_report(self, report):
        """ Records a Knowntools report for alter evaluation. """
        self.__knowntools_report = report

    def __str__(self):
        """ A string representation with selected information for positive
        identification. ID should be enough but may be uninitialised. Should
        not modify object state, i.e. should not use properties. """
        return f"<Sample(id='{self.__id}')>"

    __repr__ = __str__
