###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# sample.py                                                                   #
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


import os
import hashlib
import re
import errno
import shutil
import logging
from datetime import datetime
from peekaboo.config import get_config
from peekaboo.exceptions import CuckooReportPendingException, \
                                CuckooAnalysisFailedException
from peekaboo.toolbox.sampletools import SampleMetaInfo, ConnectionMap, next_job_hash
from peekaboo.toolbox.files import chown2me, guess_mime_type_from_file_contents
from peekaboo.toolbox.ms_office import has_office_macros
from peekaboo.toolbox.cuckoo import submit_to_cuckoo
import peekaboo.ruleset as ruleset


logger = logging.getLogger(__name__)


def make_sample(file, socket):
    """
    Create a Sample object from a given file.

    :param file: Path to the file to create a Sample object from.
    :param socket: An optional socket to write the report to.
    :return: A sample object representing the given file or None if the file does not exist.
    """
    logger.debug("Looking at file %s" % file)
    if not os.path.isfile(file):
        logger.debug('%s is not a file' % file)
        return None
    s = Sample(file, socket)
    logger.debug('Created sample %s' % s)
    return s


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
    def __init__(self, file_path, sock=None):
        self.__path = file_path
        self.__config = get_config()
        self.__db_con = self.__config.get_db_con()
        self.__meta_info = None
        self.__wd = None
        self.__filename = os.path.basename(self.__path)
        # A symlink that points to the actual file named
        # sha256sum.suffix
        self.__symlink = None
        self.__result = ruleset.Result.unchecked
        self.__report = []  # Peekaboo's own report
        self.__socket = sock
        # Additional attributes for a sample object (e. g. meta info)
        self.__attributes = {}
        self.initialized = False
        self.meta_info_loaded = False

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

        job_hash = self.get_job_hash()
        self.__wd = os.path.join(self.__config.sample_base_dir, job_hash)

        chown2me()

        meta_info_file = os.path.join(self.__wd, self.__filename + '.info')
        self.set_attr('meta_info_file', meta_info_file)
        self.load_meta_info(meta_info_file)

        try:
            self.__create_symlink()
        except OSError:
            pass
        self.initialized = True

        # Add sample to database with state 'inProgress' if the sample is unknown
        # to avoid multiple concurrent analysis.
        self.__result = ruleset.Result.inProgress
        self.__db_con.analysis2db(self)

        message = "Datei \"%s\" %s wird analysiert\n" % (self.__filename,
                                                         self.sha256sum)
        self.__report.append(message)
        self.__send_message(message)

    def get_attr(self, key):
        """
        Get a sample attribute by a specified key.

        :param key: The identifier of the sample attribute to get.
        """
        if self.has_attr(key):
            return self.__attributes[key]
        raise KeyError("Attribute for key '%s' not found." % key)

    def set_attr(self, key, val, override=True):
        """
        Add an attribute to a sample.

        :param key: The identifier of the attribute.
        :param val: The attribute to add.
        :param override: Whether the existing attribute shall be overwritten or not.
        """
        if self.has_attr(key) and override is False:
            raise KeyError("Key '%s' already exists." % key)
        self.__attributes[key] = val

    def has_attr(self, key):
        """
        Check if an attribute exists for this sample.

        :param key: The identifier of the attribute.
        """
        if key in self.__attributes.keys():
            return True
        return False

    def remove_attr(self, key):
        """
        Delete an attribute for this sample.

        :param key: The identifier of the attribute
        :raises ValueError if the given key was not found in
                the attributes dictionary.
        """
        if key in self.__attributes.keys():
            del self.__attributes[key]
        raise ValueError('No attribute named "%s" found.' % key)

    def get_file_path(self):
        return self.__path

    def get_filename(self):
        return self.__filename

    def get_result(self):
        return self.__result

    def get_peekaboo_report(self):
        return ''.join(self.__report)

    def get_job_hash(self):
        job_hash = re.sub(self.__config.job_hash_regex, r'\1',
                          self.__path)
        if job_hash == self.__path:
            # regex did not match.
            # so we generate our own job hash and create the
            # working directory.
            job_hash = next_job_hash()
            os.mkdir(os.path.join(self.__config.sample_base_dir,
                                  job_hash))

        logger.debug("Job hash for this sample: %s" % job_hash)
        return job_hash

    def load_meta_info(self, meta_info_file):
        try:
            self.__meta_info = SampleMetaInfo(meta_info_file)
            logger.debug('Parsing meta info file %s for file %s' % (meta_info_file, self.__path))
            # Add the information from the dump info file as attributes to the sample object.
            for info in self.__meta_info.get_all().items('attachment'):
                logger.debug('meta_info_%s = %s' % (info[0], info[1]))
                self.set_attr('meta_info_' + info[0], info[1])
            self.meta_info_loaded = True
        except Exception:
            logger.info('No metadata available for file %s' % self.__path)

    def save_result(self):
        if self.__db_con.known(self):
            logger.debug('Known sample info not logged to database')
        else:
            logger.debug('Saving results to database')
            self.__db_con.sample_info_update(self)
        if self.__socket is not None:
            ConnectionMap.remove(self.__socket, self)
        if not ConnectionMap.has_connection(self.__socket):
            self.__cleanup_temp_files()
            self.__close_socket()

    def add_rule_result(self, res):
        logger.debug('Adding rule result %s' % str(res))
        rule_results = []
        if self.has_attr('rule_results'):
            rule_results = self.get_attr('rule_results')
        rule_results.append(res)
        self.set_attr('rule_results', rule_results)

    def determine_result(self):
        for rule_result in self.get_attr('rule_results'):
            logger.debug("Current result: %s, Rule result: %s"
                         % (self.__result, rule_result.result))
            # check if result of this rule is worse than what we know so far
            if rule_result.result > self.__result:
                self.__result = rule_result.result
                self.set_attr('reason', rule_result.reason)

    def report(self):
        """
        Create the report for this sample. The report is saved as a list of
        strings and is available via get_peekaboo_report(). Also, if a socket connection was
        supplied to the sample the report messages are also written to the socket.
        """
        # TODO: move to rule processing engine.
        self.determine_result()

        for rule_result in self.get_attr('rule_results'):
            message = "Datei \"%s\": %s\n" % (self.__filename, str(rule_result))
            self.__report.append(message)
            self.__send_message(message)

        if self.__result == ruleset.Result.inProgress:
            logger.warning('Ruleset result forces to unchecked.')
            self.__result = ruleset.Result.unchecked

        message = "Die Datei \"%s\" wurde als \"%s\" eingestuft\n\n" \
                  % (self.__filename, self.__result.name)
        self.__report.append(message)
        self.__send_message(message)

    @property
    def sha256sum(self):
        if not self.has_attr('sha256sum'):
            with open(self.__path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
                self.set_attr('sha256sum', checksum)
                return checksum
        return self.get_attr('sha256sum')

    @property
    def known(self):
        _known = self.__db_con.known(self)
        if _known:
            self.set_attr('known', True)
            return True
        return False

    @property
    def file_extension(self):
        if self.has_attr('meta_info_name_declared'):
            file_ext = self.get_attr('meta_info_name_declared').split('.')[-1]
            if self.has_attr('file_extension'):
                if self.get_attr('file_extension') != file_ext:
                    self.set_attr('file_extension', file_ext, override=True)
            else:
                self.set_attr('file_extension', file_ext)
        elif not self.has_attr('file_extension'):
            file_ext = os.path.splitext(self.__filename)[1][1:]
            self.set_attr('file_extension', file_ext)
        return self.get_attr('file_extension')

    @property
    def mimetype(self):
        """
        Can not be cached (hard to determine if known/complete).

        determine mime on original p[0-9]* file
        later result will be "inode/symlink"
        """
        mime_type = None

        smime = {
            'p7s': [
                'application/pkcs7-signature',
                'application/x-pkcs7-signature',
                'application/pkcs7-mime',
                'application/x-pkcs7-mime',
            ]
        }

        # get MIME type from meta info
        try:
            declared_mt = self.__meta_info.get_mime_type()
            if declared_mt is not None:
                logger.debug('Sample declared as "%s"' % declared_mt)
                mime_type = declared_mt
        except Exception as e:
            logger.exception(e)
            if self.meta_info_loaded:
                logger.error('Cannot get mime type from meta info although meta info is loaded.')

        detected_mime_type = guess_mime_type_from_file_contents(self.__path)
        if detected_mime_type != mime_type:
            logger.debug(
                'Detected MIME type does not match declared MIME Type: declared: %s, detected: %s.'
                % (mime_type, detected_mime_type)
            )
            # check if the sample is an smime signature (smime.p7s)
            # If so, don't overwrite the MIME type since we do not want to analyse S/MIME signatures.
            try:
                declared_filename = self.get_attr('meta_info_name_declared')
            except KeyError:
                declared_filename = self.__filename
            if declared_filename == 'smime.p7s' and mime_type in smime['p7s']:
                logger.info('Using declared MIME type over detected one for S/MIME signatures.')
            else:
                logger.debug('Overwriting declared MIME Type with "%s"' % detected_mime_type)
                mime_type = detected_mime_type

        if not self.has_attr('mimetypes'):
            self.set_attr('mimetypes', mime_type)

        return self.get_attr('mimetypes')

    @property
    def job_id(self):
        if self.has_attr('job_id'):
            return self.get_attr('job_id')
        return -1

    @property
    def reason(self):
        # TODO: Cover all possible cases.
        # if reason exists and sample is not known?
        if not self.has_attr('reason'):
            if not self.has_attr('known'):
                rr = self.__db_con.fetch_rule_result(self)
                self.__result = rr.result
                self.set_attr('known', True)
                self.set_attr('reason',
                              'Ausschlaggebendes Ergebnis laut Datenbank: %s'
                              % rr.reason)
        return self.get_attr('reason')

    @property
    def office_macros(self):
        if not self.has_attr('office_macros'):
            self.set_attr('office_macros', has_office_macros(self.__path))
        return self.get_attr('office_macros')

    @property
    def file_size(self):
        if not self.has_attr('file_stat'):
            self.set_attr('file_stat', os.stat(self.__path))
        return self.get_attr('file_stat').st_size

    @property
    def analyses_time(self):
        if not self.has_attr('analyses_time'):
            timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
            self.set_attr('analyses_time', timestamp)
            return timestamp
        return self.get_attr('analyses_time')

    @property
    def requested_domains(self):
        if not self.has_attr('requested_domains'):
            try:
                self.set_attr(
                    'requested_domains',
                    self.get_attr('cuckoo_report').requested_domains
                )
            except KeyError:
                self.set_attr('requested_domains', [])
        return self.get_attr('requested_domains')

    @property
    def cuckoo_report(self):
        if not self.has_attr('cuckoo_report'):
            try:
                file_for_analysis = os.path.join(self.__wd, self.__symlink)
                logger.debug("Submitting %s to Cuckoo" % file_for_analysis)
                job_id = submit_to_cuckoo(file_for_analysis)
                self.set_attr('job_id', job_id)
                message = 'Erfolgreich an Cuckoo gegeben %s als Job %d\n' \
                          % (self, job_id)
                self.__report.append(message)
                logger.info('Sample submitted to Cuckoo. Job ID: %s. Sample: %s' % (job_id, self))
                self.__db_con.analysis_update(self)
                raise CuckooReportPendingException()
            except CuckooAnalysisFailedException as e:
                logger.exception(e)
        return self.get_attr('cuckoo_report')

    @property
    def cuckoo_analysis_failed(self):
        if not self.has_attr('cuckoo_failed'):
            if self.has_attr('cuckoo_report'):
                report = self.get_attr('cuckoo_report')
                if report.analysis_failed:
                    self.set_attr('cuckoo_failed', True)
                else:
                    self.set_attr('cuckoo_failed', False)
        return self.get_attr('cuckoo_failed')

    def __create_symlink(self):
        """
        creates a symlink to submit the file with the correct
        file extension to cuckoo via submit.py.
        """
        orig = os.path.join(self.__wd, self.__filename)
        self.__symlink = '%s/%s.%s' % (self.__wd,
                                       self.sha256sum,
                                       self.file_extension)
        logger.debug('ln -s %s %s' % (orig, self.__symlink))

        os.symlink(orig, self.__symlink)

    def __close_socket(self):
        logger.debug('Closing socket connection.')
        try:
            if self.__socket is not None:
                self.__socket.close()
        except EnvironmentError as e:
            # base class for exceptions that can occur outside the Python system.
            # e. g. IOError, OSError
            if e.errno == errno.EPIPE:
                logger.warning('Unable to close the socket. Broken pipe.')
            else:
                logger.exception(e)

    def __cleanup_temp_files(self):
        try:
            if self.__config.keep_mail_data:
                logger.debug('Keeping mail data in %s' % self.__wd)
            else:
                logger.debug("Deleting tempdir %s" % self.__wd)
                shutil.rmtree(self.__wd)
        except OSError as e:
            logger.exception(e)

    def __send_message(self, msg):
        """
        Write a message to the socket.

        :param msg: The message to send (max. 1024 bytes).
        """
        if self.__socket is None:
            return
        try:
            self.__socket.send(msg)
            logger.debug('Message send: %s ' % msg)
        except IOError as e:
            if e.errno == errno.EPIPE:
                logger.warning('Unable send message "%s". Broken pipe.' % msg)
            else:
                logger.exception(e)

    def __str__(self):
        meta_info_loaded = 'no'
        job_id = -1
        if self.__meta_info:
            meta_info_loaded = 'yes'
        if self.has_attr('job_id'):
            job_id = self.get_attr('job_id')

        return ("<Sample(filename='%s', known='%s', meta_info_loaded='%s', job_id='%d',"
                " result='%s', sha256sum='%s')>"
                % (self.__filename,
                   'yes' if self.known else 'no',
                   meta_info_loaded,
                   job_id,
                   self.__result,
                   self.sha256sum))

    __repr__ = __str__
