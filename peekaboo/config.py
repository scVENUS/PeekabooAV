###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# config.py                                                                   #
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

""" The configuration for the main program as well as the ruleset. Handles
defaults as well as reading a configuration file. """


import re
import sys
import logging
import configparser
from peekaboo.exceptions import PeekabooConfigException
from peekaboo.toolbox.cortex import tlp


logger = logging.getLogger(__name__)

class PeekabooConfigParser( # pylint: disable=too-many-ancestors
        configparser.ConfigParser):
    """ A config parser that gives error feedback if a required file does not
    exist or cannot be opened. """
    LOG_LEVEL = object()
    OCTAL = object()
    RELIST = object()
    IRELIST = object()

    def __init__(self, config_file):
        super().__init__()

        try:
            self.read_file(open(config_file))
        except IOError as ioerror:
            raise PeekabooConfigException(
                'Configuration file "%s" can not be opened for reading: %s' %
                (config_file, ioerror))
        except configparser.Error as cperror:
            raise PeekabooConfigException(
                'Configuration file "%s" can not be parsed: %s' %
                (config_file, cperror))

        self.lists = {}
        self.relists = {}

    def getlist(self, section, option, raw=False, vars=None, fallback=None):
        """ Special getter where multiple options in the config file
        distinguished by a .<no> suffix form a list. Matches the signature for
        configparser getters. """
        # cache results because the following is somewhat inefficient
        if section not in self.lists:
            self.lists[section] = {}

        if option in self.lists[section]:
            return self.lists[section][option]

        if section not in self:
            self.lists[section][option] = fallback
            return fallback

        # Go over all options in this section we want to allow "holes" in
        # the lists, i.e setting.1, setting.2 but no setting.3 followed by
        # setting.4. We use here that ConfigParser retains option order from
        # the file.
        value = []
        for setting in self[section]:
            if not setting.startswith(option):
                continue

            # Parse 'setting' into (key) and 'setting.subscript' into
            # (key, subscript) and use it to determine if this setting is a
            # list. Note how we do not use the subscript at all here.
            name_parts = setting.split('.')
            key = name_parts[0]
            is_list = len(name_parts) > 1

            if key != option:
                continue

            if not is_list:
                raise PeekabooConfigException(
                    'Option %s in section %s is supposed to be a list '
                    'but given as individual setting' % (setting, section))

            # Potential further checks:
            # - There are no duplicate settings with ConfigParser. The last
            #   one always wins.

            value.append(self[section].get(setting, raw=raw, vars=vars))

        # it's not gonna get any better on the next call, so cache even the
        # default
        if not value:
            value = fallback

        self.lists[section][option] = value
        return value

    def getirelist(self, section, option, raw=False, vars=None, fallback=None, flags=None):
        """ Special getter for lists of regular expressions that are compiled to match
        case insesitive (IGNORECASE). Returns the compiled expression objects in a
        list ready for matching and searching.
        """
        return self.getrelist(section, option, raw=raw, vars=vars, fallback=fallback, flags=re.IGNORECASE)

    def getrelist(self, section, option, raw=False, vars=None, fallback=None, flags=0):
        """ Special getter for lists of regular expressions. Returns the
        compiled expression objects in a list ready for matching and searching.
        """
        if section not in self.relists:
            self.relists[section] = {}

        if option in self.relists[section]:
            return self.relists[section][option]

        if section not in self:
            self.relists[section][option] = fallback
            return fallback

        strlist = self[section].getlist(option, raw=raw, vars=vars,
                                        fallback=fallback)
        if strlist is None:
            self.relists[section][option] = None
            return None

        compiled_res = []
        for regex in strlist:
            try:
                compiled_res.append(re.compile(regex, flags))
            except (ValueError, TypeError) as error:
                raise PeekabooConfigException(
                    'Failed to compile regular expression "%s" (section %s, '
                    'option %s): %s' % (re, section, option, error))

        # it's not gonna get any better on the next call, so cache even the
        # default
        if not compiled_res:
            compiled_res = fallback

        self.relists[section][option] = compiled_res
        return compiled_res

    def get_log_level(self, section, option, raw=False, vars=None,
                      fallback=None):
        """ Get the log level from the configuration file and parse the string
        into a logging loglevel such as logging.CRITICAL. Raises config
        exception if the log level is unknown. Options identical to get(). """
        levels = {
            'CRITICAL': logging.CRITICAL,
            'ERROR': logging.ERROR,
            'WARNING': logging.WARNING,
            'INFO': logging.INFO,
            'DEBUG': logging.DEBUG
        }

        level = self.get(section, option, raw=raw, vars=vars, fallback=None)
        if level is None:
            return fallback

        if level not in levels:
            raise PeekabooConfigException('Unknown log level %s' % level)

        return levels[level]

    def gettlp(self, section, option, raw=False, vars=None, fallback=None):
        levels = {
            'red': tlp.RED,
            '3': tlp.RED,
            'amber': tlp.AMBER,
            '2': tlp.AMBER,
            'green': tlp.GREEN,
            '1': tlp.GREEN,
            'white': tlp.WHITE,
            '0': tlp.WHITE,
        }

        level = self.get(section, option, raw=raw, vars=vars, fallback=None)
        if level is None:
            return fallback
        level = level.lower()

        if level not in levels:
            raise PeekabooConfigException('Unknown tlp level %s' % level)

        return levels[level]

    def getoctal(self, section, option, raw=False, vars=None, fallback=None):
        """ Get an integer in octal notation. Raises config
        exception if the format is wrong. Options identical to get(). """
        value = self.get(section, option, raw=raw, vars=vars, fallback=None)
        if value is None:
            return fallback

        try:
            octal = int(value, 8)
        except ValueError:
            raise PeekabooConfigException(
                'Invalid value for octal option %s in section %s: %s'
                % (option, section, value))

        return octal

    def get_by_type(self, section, option, fallback=None, option_type=None):
        """ Get an option from the configuration file parser. Automatically
        detects the type from the type of the default if given and calls the
        right getter method to coerce the value to the correct type.

        @param section: Which section to look for option in.
        @type section: string
        @param option: The option to read.
        @type option: string
        @param fallback: (optional) Default value to return if option is not
                         found. Defaults itself to None so that the method will
                         return None if the option is not found.
        @type fallback: int, bool, str or None.
        @param option_type: Override the option type.
        @type option_type: int, bool, str or None. """
        if option_type is None and fallback is not None:
            option_type = type(fallback)

        getter = {
            int: self.getint,
            float: self.getfloat,
            bool: self.getboolean,
            list: self.getlist,
            tuple: self.getlist,
            str: self.get,
            None: self.get,

            # these only work when given explicitly as option_type
            self.LOG_LEVEL: self.get_log_level,
            self.OCTAL: self.getoctal,
            self.RELIST: self.getrelist,
            self.IRELIST: self.getirelist,
            tlp: self.gettlp,
        }

        return getter[option_type](section, option, fallback=fallback)

    def set_known_options(self, config_options):
        """ Set a number of known config options as member variables. Also
        checks for unknown options being present.

        @param config_options: the mapping of config option to section and
                               option name
        @type config_options: Dict of two-item-tuples
                              (config_option: [section, option])
        @raises PeekabooConfigException: if any unknown sections or options are
                                         found. """
        settings = vars(self)
        check_options = {}
        for (setting, config_names) in config_options.items():
            section = config_names[0]
            option = config_names[1]

            # remember for later checking for unknown options
            if section not in check_options:
                check_options[section] = []
            check_options[section].append(option)

            # maybe force the option's value type
            option_type = None
            if len(config_names) == 3:
                option_type = config_names[2]

            # e.g.:
            # self.log_format = self.get('logging', 'log_format',
            #                            self.log_format)
            settings[setting] = self.get_by_type(
                section, option, fallback=settings[setting],
                option_type=option_type)

        # now check for unknown options
        self.check_config(check_options)

    def check_config(self, known_options):
        """ Check this configuration against a list of known options. Raise an
        exception if any unknown options are found.

        @param known_options: A dict of sections and options, the key being the
                              section name and the value a list of option names.
        @type known_options: dict

        @returns: None
        @raises PeekabooConfigException: if any unknown sections or options are
                                         found.
        """
        known_sections = known_options.keys()
        self.check_sections(known_sections)

        # go over sections both allowed and in the config
        for section in known_sections:
            self.check_section_options(section, known_options[section])

    def check_sections(self, known_sections):
        """ Check a list of known section names against this configuration

        @param known_sections: names of known sections
        @type known_sections: list(string)

        @returns: None
        @raises PeekabooConfigException: if any unknown sections are found in
                                         the configuration.
        """
        section_diff = set(self.sections()) - set(known_sections)
        if section_diff:
            raise PeekabooConfigException(
                'Unknown section(s) found in config: %s'
                % ', '.join(section_diff))

    def check_section_options(self, section, known_options):
        """ Check a config section for unknown options.

        @param section: name of section to check
        @type section: string
        @param known_options: list of names of known options to check against
        @type known_options: list(string)

        @returns: None
        @raises PeekabooConfigException: if any unknown options are found. """
        try:
            section_options = map(
                # account for option.1 list syntax
                lambda x: x.split('.')[0],
                self.options(section))
        except configparser.NoSectionError:
            # a non-existant section can have no non-allowed options :)
            return

        option_diff = set(section_options) - set(known_options)
        if option_diff:
            raise PeekabooConfigException(
                'Unknown config option(s) found in section %s: %s'
                % (section, ', '.join(option_diff)))


class PeekabooConfig(PeekabooConfigParser):
    """ This class represents the Peekaboo configuration. """
    def __init__(self, config_file=None, log_level=None):
        """ Initialise the configuration with defaults, overwrite with command
        line options and finally read the configuration file. """
        # hard defaults: The idea here is that every config option has a
        # default that would in principle enable Peekaboo to run. Code using
        # the option should still cope with no or an empty value being handed
        # to it.
        self.user = 'peekaboo'
        self.group = None
        self.host = '127.0.0.1'
        self.port = 8100
        self.pid_file = None
        self.log_level = logging.INFO
        self.log_format = '%(asctime)s - %(name)s - (%(threadName)s) - ' \
                          '%(levelname)s - %(message)s'
        self.worker_count = 3
        self.processing_info_dir = '/var/lib/peekaboo/malware_reports'
        self.report_locale = None
        self.db_url = 'sqlite:////var/lib/peekaboo/peekaboo.db'
        self.db_async_driver = None
        self.db_log_level = logging.WARNING
        self.config_file = '/opt/peekaboo/etc/peekaboo.conf'
        self.ruleset_config = '/opt/peekaboo/etc/ruleset.conf'
        self.analyzer_config = '/opt/peekaboo/etc/analyzers.conf'
        self.cluster_instance_id = 0
        self.cluster_stale_in_flight_threshold = 15*60
        self.cluster_duplicate_check_interval = 60

        # section and option names for the configuration file. key is the above
        # variable name whose value will be overwritten by the configuration
        # file value. Third item can be getter function if special parsing is
        # required.
        config_options = {
            'log_level': ['logging', 'log_level', self.LOG_LEVEL],
            'log_format': ['logging', 'log_format'],
            'user': ['global', 'user'],
            'group': ['global', 'group'],
            'pid_file': ['global', 'pid_file'],
            'host': ['global', 'host'],
            'port': ['global', 'port'],
            'worker_count': ['global', 'worker_count'],
            'processing_info_dir': ['global', 'processing_info_dir'],
            'report_locale': ['global', 'report_locale'],
            'db_url': ['db', 'url'],
            'db_async_driver': ['db', 'async_driver'],
            'db_log_level': ['db', 'log_level', self.LOG_LEVEL],
            'ruleset_config': ['ruleset', 'config'],
            'analyzer_config': ['analyzers', 'config'],
            'cluster_instance_id': ['cluster', 'instance_id'],
            'cluster_stale_in_flight_threshold': ['cluster', 'stale_in_flight_threshold'],
            'cluster_duplicate_check_interval': ['cluster', 'duplicate_check_interval'],
        }

        # overrides from outside, e.g. by command line arguments whose values
        # are needed while reading the configuration file already (most notably
        # log level and path to the config file).
        if log_level:
            self.log_level = log_level
        if config_file:
            self.config_file = config_file

        # setup default logging to log any errors during the
        # parsing of the config file.
        self.setup_logging()

        # read configuration file. Note that we require a configuration file
        # here. We may change that if we decide that we want to allow the user
        # to run us with the above defaults only.
        super().__init__(self.config_file)

        # overwrite above defaults in our member variables via indirect access
        self.set_known_options(config_options)

        # Update logging with what we just parsed from the config
        self.setup_logging()

        # here we could overwrite defaults and config file with additional
        # command line arguments if required

    def setup_logging(self):
        """ Setup logging to console by reconfiguring the root logger so that
        it affects all loggers everywhere.  """
        _logger = logging.getLogger()

        # Check if we already have a log handler
        if _logger.handlers:
            # Remove all handlers
            for handler in _logger.handlers:
                _logger.removeHandler(handler)
        # log format
        log_formatter = logging.Formatter(self.log_format)
        # create console handler and set level to debug
        to_console_log_handler = logging.StreamHandler(sys.stdout)
        to_console_log_handler.setFormatter(log_formatter)
        _logger.addHandler(to_console_log_handler)
        _logger.setLevel(self.log_level)

    def __str__(self):
        settings = {}
        for (option, value) in vars(self).items():
            if not option.startswith('_'):
                settings[option] = value

        return '<PeekabooConfig(%s)>' % settings

    __repr__ = __str__


class PeekabooAnalyzerConfig(PeekabooConfigParser):
    """ This class represents the analyzer configuration. """
    def __init__(self, config_file=None):
        """ Initialise the configuration with defaults, overwrite with command
        line options and finally read the configuration file. """
        self.cuckoo_url = 'http://127.0.0.1:8090'
        self.cuckoo_api_token = ''
        self.cuckoo_poll_interval = 5
        self.cuckoo_submit_original_filename = True
        self.cuckoo_maximum_job_age = 15*60

        self.cortex_url = 'http://127.0.0.1:9001'
        self.cortex_tlp = tlp.AMBER
        self.cortex_api_token = ''
        self.cortex_poll_interval = 5
        self.cortex_submit_original_filename = True
        self.cortex_maximum_job_age = 15*60

        config_options = {
            'cuckoo_url': ['cuckoo', 'url'],
            'cuckoo_api_token': ['cuckoo', 'api_token'],
            'cuckoo_poll_interval': ['cuckoo', 'poll_interval'],
            'cuckoo_submit_original_filename': [
                'cuckoo', 'submit_original_filename'],
            'cuckoo_maximum_job_age': ['cuckoo', 'maximum_job_age'],

            'cortex_url': ['cortex', 'url'],
            'cortex_tlp': ['cortex', 'tlp'],
            'cortex_api_token': ['cortex', 'api_token'],
            'cortex_poll_interval': ['cortex', 'poll_interval'],
            'cortex_submit_original_filename': [
                'cortex', 'submit_original_filename'],
            'cortex_maximum_job_age': ['cortex', 'maximum_job_age'],
        }

        # read configuration file. Note that we require a configuration file
        # here. We may change that if we decide that we want to allow the user
        # to run us with the above defaults only.
        super().__init__(config_file)

        # overwrite above defaults in our member variables via indirect access
        self.set_known_options(config_options)

    def __str__(self):
        settings = {}
        for (option, value) in vars(self).items():
            if not option.startswith('_'):
                settings[option] = value

        return '<PeekabooConfig(%s)>' % settings

    __repr__ = __str__
