###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# sample.py                                                                   #
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


import os
import sys
import hashlib
import magic
import mimetypes
import re
import subprocess
import json
import errno
import string
import shutil
import logging
from ConfigParser import SafeConfigParser
from random import choice
from datetime import datetime
from oletools.olevba import VBA_Parser
from peekaboo import MultiRegexMatcher
from peekaboo.config import get_config
from peekaboo.exceptions import CuckooReportPendingException
import peekaboo.pjobs as pjobs
import peekaboo.ruleset as ruleset


logger = logging.getLogger(__name__)


class SampleMetaInfo(object):
    """
    DumpInfo data structure that contains additional metadata about
    a Sample to analyse.

    @author: Felix Bauer
    @author: Sebastian Deiss
    @see: Sample
    """
    def __init__(self, meta_info_path):
        self.__meta_info_path = meta_info_path
        self.__meta_info = None
        ##############################################
        self._read()

    def _read(self):
        """
        Utilizes SafeConfigParser to parse the .info file (ini format).

        @see: SafeConfigParser
        """
        logger.debug('Reading metadata for %s' % self.__meta_info_path)
        meta_info = SafeConfigParser()
        meta_info.read(self.__meta_info_path)
        self.__meta_info = meta_info

    def get(self):
        """
        Gets the additional meta information as ConfigParser object.
        """
        return self.__meta_info

    def __str__(self):
        return '<SampleMetaInfo(%s)>' % str(self.__meta_info)


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
    def __init__(self, sock, file_path):
        self.__socket = sock
        self.__file_path = file_path
        self.__config = get_config()
        self.__db_con = self.__config.get_db_con()
        self.__meta_info = None
        self.__wd = None
        self.__filename = os.path.basename(self.__file_path)
        # A symlink that points to the actual file named
        # <sha256sum>.suffix
        self.__symlink = None
        self.__result = ruleset.Result.unchecked
        self.__report = []  # Peekaboo's own report
        # Additional attributes for a sample object (e. g. dump info)
        self.__attributes = {}
        self.initalized = False
        self.meta_info_loaded = False

    def init(self):
        """
        Initialize the Sample object.

        The actual initialization is done here, because the main thread should
        not do the heavy lifting of e. g. parsing the dump_info file to be able
        to accept new connections as quickly as possible.
        Instead, it only adds the sample objects to the queue and the workers
        to the actual initialization.
        """
        if self.initalized:
            return

        logger.debug("initializing sample")

        job_hash = self.get_job_hash()
        self.__wd = os.path.join(self.__config.sample_base_dir, job_hash)

        self.chown2me()

        meta_info_file = os.path.join(self.__wd, self.__filename + '.info')
        self.set_attr('meta_info_file', meta_info_file)
        self.load_meta_info(meta_info_file)

        try:
            self.create_symlink()
        except OSError:
            pass
        self.initalized = True

        # add sample to database with state inProgress if sample unknown
        # to avoid multiple concurrent analysis
        self.__result = ruleset.Result.inProgress
        self.__db_con.analysis2db(self)

        message = "Datei \"%s\" %s wird analysiert\n" % (self.__filename,
                                                         self.sha256sum)
        self.__report.append(message)
        try:
            self.__socket.send(message)
        except Exception as e:
            if e.errno == errno.EPIPE:
                logger.warning('Unable send message "%s". Broken pipe.' % message)
            else:
                logger.exception(e)

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

    def get_job_hash(self):
        job_hash = re.sub(self.__config.job_hash_regex, r'\1',
                          self.__file_path)
        if job_hash == self.__file_path:
            # regex did not match.
            # so we generate our own job hash and create the
            # working directory.
            job_hash = self.__gen_job_hash()
            os.mkdir(os.path.join(self.__config.sample_base_dir,
                                  job_hash))

        logger.debug("job_hash: %s" % job_hash)
        return job_hash

    def chown2me(self):
        """kinda dirty hack to acquire ownership of that directory. """
        logger.debug('Invoking chown2me...')
        proc = subprocess.Popen(self.__config.chown2me_exec,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        proc.wait()
        if proc.returncode != 0:
            logger.error('chown2me exited with code %d' % proc.returncode)

    def load_meta_info(self, meta_info_file):
        try:
            meta_info = SampleMetaInfo(meta_info_file)
            self.__meta_info = meta_info.get()
            logger.debug('Parsing meta info file %s for file %s' % (meta_info_file, self.__file_path))
            # Add the information from the dump info file as attributes to the sample object.
            for info in self.__meta_info.items('attachment'):
                logger.debug('meta_info_%s = %s' % (info[0], info[1]))
                self.set_attr('meta_info_' + info[0], info[1])
            self.meta_info_loaded = True
        except Exception as e:
            logger.info('No metadata available for file %s' % self.__file_path)

    def create_symlink(self):
        """ 
        creates a symlink to submit the file with correct
        file extension to cuckoo via submit.py.
        """
        orig = os.path.join(self.__wd, self.__filename)
        self.__symlink = '%s/%s.%s' % (self.__wd,
                                       self.sha256sum,
                                       self.file_extension)
        logger.debug('ln -s %s %s' % (orig, self.__symlink))

        os.symlink(orig, self.__symlink)

    def get_file_path(self):
        return self.__file_path

    def get_filename(self):
        return self.__filename

    def get_result(self):
        return self.__result

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

    def __ask_db(self):
        if not self.has_attr('known'):
            rr = self.__db_con.fetch_rule_result(self)
            self.__result = rr.result
            self.set_attr('known', True)
            self.set_attr('reason',
                          'Ausschlaggebendes Ergebnis laut Datenbank: %s'
                          % rr.reason)

    #
    # Methods handling sample attributes.
    #

    @property
    def sha256sum(self):
        if not self.has_attr('sha256sum'):
            with open(self.__file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
                self.set_attr('sha256sum', checksum)
                return checksum
        return self.get_attr('sha256sum')

    @property
    def known(self):
        return self.__db_con.known(self)

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
    def mimetypes(self):
        """
        Can not be cached (hard to determine if known/complete)

        determine mime on original p[0-9]* file
        later result will be "inode/symlink"
        maybe even get this information from dump_info
        (compare in rule only)
        """
        mtypes = []

        # get types from dump_info
        try:
            declared_mt = self.get_mime_type_from_meta_info()
            mtypes.append(declared_mt)
        except Exception:
            if self.meta_info_loaded:
                logger.warning('Cannot get mime types from meta info although meta info is loaded.')

        if self.__symlink:
            symlink_mt = self.guess_mime_type_from_filename(self.__symlink)
            mtypes.append(symlink_mt)

        file_mt = self.guess_mime_type_from_file_contents(self.__file_path)
        mtypes.append(file_mt)

        if not self.has_attr('mimetypes'):
            self.set_attr('mimetypes', mtypes)
        else:
            # merge lists
            current_mt = self.get_attr('mimetypes')
            new_mt = list(set(mtypes + current_mt))
            self.set_attr('mimetypes', new_mt)

        logger.debug('Mime type returned as %s'
                     % self.get_attr('mimetypes'))

        return self.get_attr('mimetypes')

    def get_mime_type_from_meta_info(self):
        declared_mt = self.__meta_info.get('attachment', 'type_declared')
        return declared_mt

    def guess_mime_type_from_filename(self, file_path):
        """ Guess the type of a file based on its filename or URL. """
        if not mimetypes.inited:
            mimetypes.init()
            mimetypes.add_type('application/javascript', '.jse')

        mt = mimetypes.guess_type(file_path)[0]
        if mt:
            return mt

    def guess_mime_type_from_file_contents(self, file_path):
        """  Get type from file magic bytes. """
        mt = magic.from_file(file_path, mime=True)
        if mt:
            return mt

    @property
    def job_id(self):
        if self.has_attr('job_id'):
            return self.get_attr('job_id')
        return -1

    @property
    def reason(self):
        if not self.has_attr('reason'):
            self.__ask_db()
        return self.get_attr('reason')

    @property
    def office_macros(self):
        if not self.has_attr('office_macros'):
            office_ext = [
                ".doc", ".docm", ".dotm", ".docx", ".ppt", ".pptm",
                ".pptx", ".potm", ".ppam", ".ppsm", ".xls", ".xlsm", ".xlsx",
            ]

            # vbaparser crashes if file is not an office document, power
            #   point, spreadsheet, odt, ....
            # at least three bytes are required to determine mime-type
            if self.file_size < 3:
                self.set_attr('office_macros', [])
            elif self.file_extension not in office_ext:
                self.set_attr('office_macros', [])
            else:
                try:
                    # vbaparser reports macros for text documents
                    vbaparser = VBA_Parser(self.__file_path)
                    self.set_attr('office_macros',
                                  vbaparser.detect_vba_macros())
                except Exception as e:
                    logger.critical("vbatools crashed", type(e), e)
                    self.set_attr('office_macros', [])
        return self.get_attr('office_macros')

    @property
    def file_size(self):
        if not self.has_attr('file_stat'):
            self.set_attr('file_stat', os.stat(self.__file_path))
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
            cr = self.cuckoo_report
            try:
                self.set_attr('requested_domains',
                              [d['request'] for d in cr['network']['dns']])
            except KeyError:
                # TODO: Handle KeyError
                pass
        return self.get_attr('requested_domains')

    @property
    def cuckoo_report(self):
        if not self.has_attr('cuckoo_report'):
            try:
                file_for_analysis = os.path.join(self.__wd, self.__symlink)
                logger.debug("Submitting %s to cuckoo" % file_for_analysis)
                proc = self.__config.cuckoo_submit
                proc.append(file_for_analysis)
                p = subprocess.Popen(proc,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE)
                p.wait()
            except Exception as e:
                logger.error("Popen: %s" % str(e))
                raise e

            if not p.returncode == 0:
                # TODO: tell opponent on socket that file has not been checked
                logger.error('submit didn\'t work')
            else:
                out, err = p.communicate()
                logger.debug("Popen out: %s" % out)
                logger.debug("Popen err: %s" % err)
                # process output to get jobID
                patterns = []
                # Example: Success: File "/var/lib/peekaboo/.bashrc" added as task with ID #4
                patterns.append(".*Success.*: File .* added as task with ID #([0-9]*).*")
                patterns.append(".*added as task with ID ([0-9]*).*")
                matcher = MultiRegexMatcher(patterns)
                m = matcher.match(out.replace("\n", ""))
                logger.debug('Pattern %d matched.' % matcher.matched_pattern)

                if m:
                    self.set_attr('job_id', int(m.group(1)))
                    message = 'Erfolgreich an Cuckoo gegeben %s als Job %d\n' \
                              % (self.__filename, self.get_attr('job_id'))
                    self.__report.append(message)
                    logger.debug('Connection send: %s ' % message)
                    if self.__socket:
                        try:
                            self.__socket.send(message)
                        except Exception as e:
                            logger.exception(e)

            # stop worker
            sys.stdout.flush()
            raise CuckooReportPendingException()
        return self.get_attr('cuckoo_report')

    @property
    def cuckoo_analysis_failed(self):
        if not self.has_attr('cuckoo_failed'):
            if self.has_attr('cuckoo_report'):
                cr = self.get_attr('cuckoo_report')
                # todo log reason to socket connection
                if cr['debug']['errors']:
                    # does only contain internal information
                    # important for debugging
                    logger.error("Cuckoo Analysis Failed: %s"
                                 % str(cr['debug']['errors']))
                    self.set_attr('cuckoo_failed', True)
                else:
                    self.set_attr('cuckoo_failed', False)
        return self.get_attr('cuckoo_failed')

    def parse_cuckoo_report(self):
        """
        Reads the JSON report from Cuckoo and loads it into the Sample object.
        """
        task_id = self.get_attr('job_id')
        cuckoo_report = os.path.join(self.__config.cuckoo_storage,
                                       'analyses/%d/reports/report.json'
                                       % task_id)
        self.set_attr('cuckoo_json_report_file', cuckoo_report)
        logger.debug('Accessing Cuckoo report at %s for task %d' % (cuckoo_report,
                                                                    task_id))

        if not os.path.isfile(cuckoo_report):
            raise OSError('Cuckoo report not found.')
        else:
            with open(cuckoo_report) as data:
                report = json.load(data)
                self.set_attr('cuckoo_report', report)

    def add_rule_result(self, res):
        logger.debug('Adding rule result %s' % str(res))
        rule_results = []
        if self.has_attr('rule_results'):
            rule_results = self.get_attr('rule_results')
        rule_results.append(res)
        self.set_attr('rule_results', rule_results)

    def save_result(self):
        if self.__db_con.known(self):
            logger.debug('Known sample info not logged to database')
        else:
            logger.debug('Saving results to database')
            self.__db_con.sample_info_update(self)
        self._cleanup()

    def set_job_id(self, job_id):
        if not self.has_attr('job_id'):
            self.set_attr('job_id', job_id)

    def set_cuckoo_report(self, data):
        if not self.has_attr('cuckoo_report'):
            self.set_attr('cuckoo_report', data)

#############################################
    def report(self):
        """ report result to socket connection """
        self.determine_result()

        for rule_result in self.get_attr('rule_results'):
            message = "Datei \"%s\": %s\n" % (self.__filename, str(rule_result))
            self.__report.append(message)
            logger.info('Connection send: %s ' % message)
            try:
                self.__socket.send(message)
            except Exception as e:
                if e.errno == errno.EPIPE:
                    logger.warning('Unable send message "%s". Broken pipe.' % message)
                else:
                    logger.exception(e)

        # check if result still init value inProgress
        if self.__result == ruleset.Result.inProgress:
            logger.warning('Ruleset result forces to unchecked.')
            self.__result = ruleset.Result.unchecked

        message = "Die Datei \"%s\" wurde als \"%s\" eingestuft\n\n" \
                  % (self.__filename, self.__result.name)
        self.__report.append(message)
        logger.debug('Connection send: %s ' % message)
        if self.__socket:
            try:
                self.__socket.send(message)
            except Exception as e:
                if e.errno == errno.EPIPE:
                    logger.warning('Unable send message "%s". Broken pipe.' % message)
                else:
                    logger.exception(e)

    def get_peekaboo_report(self):
        return ''.join(self.__report)

    def _cleanup(self):
        if pjobs.Jobs.remove_job(self.__socket, self) <= 0:
            # returns count of remaining samples for this connection
            logger.debug('Closing connection.')
            # delete all files created by dump_info
            try:
                logger.debug("Deleting tempdir %s" % self.__wd)
                shutil.rmtree(self.__wd)
            except OSError as e:
                logger.error("OSError while clean up %s: %s"
                             % (self.__wd, str(e)))
            if not os.path.isdir(self.__wd):
                logger.debug('Clean up of %s complete' % self.__wd)
            else:
                logger.info('Clean up of %s failed' % self.__wd)

            try:
                self.__socket.close()
            except Exception as e:
                if e.errno == errno.EPIPE:
                    logger.warning('Unable to close the socket. Broken pipe.')
                else:
                    logger.exception(e)

    def determine_result(self):
        for rule_result in self.get_attr('rule_results'):
            logger.debug("Current result: %s, Rule result: %s"
                         % (self.__result, rule_result.result))
            # check if result of this rule is worse than what we know so far
            if rule_result.result > self.__result:
                self.__result = rule_result.result
                self.set_attr('reason', rule_result.reason)

    def __gen_job_hash(self, size=8):
        """
        Generates a job hash (default: 8 characters).
        """
        job_hash = 'peekaboo-analyses-'
        job_hash += '%s-' % self.analyses_time
        job_hash += ''.join(choice(string.digits +
                                   string.ascii_lowercase +
                                   string.ascii_uppercase)
                            for _ in range(size))
        return job_hash
