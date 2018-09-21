###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# config.py                                                                   #
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
import logging
from ConfigParser import SafeConfigParser, NoSectionError, NoOptionError


logger = logging.getLogger(__name__)


class PeekabooConfig(object):
    """
    This class represents the Peekaboo configuration file.

    :author: Sebastian Deiss
    """
    def __init__(self, config_file='./peekaboo.conf'):
        self.__config = None
        self.user = None
        self.group = None
        self.pid_file = None
        self.sock_file = None
        self.log_level = logging.INFO
        self.log_format = '%(asctime)s - %(name)s - (%(threadName)s) - ' \
                          '%(levelname)s - %(message)s'
        self.interpreter = None
        self.worker_count = 3
        self.sample_base_dir = None
        self.job_hash_regex = None
        self.use_debug_module = None
        self.keep_mail_data = None
        self.db_url = None
        self.ruleset_config = None
        self.cuckoo_mode = "api"
        self.cuckoo_url = ""
        self.cuckoo_poll_interval = 5
        self.cuckoo_storage = None
        self.cuckoo_exec = None
        self.cuckoo_submit = None
        ##############################################
        # setup default logging to log any errors during the
        # parsing of the config file.
        self.__setup_logging()
        self.__parse(config_file)

    def __parse(self, config_file):
        config = SafeConfigParser()
        config.read(config_file)
        self.__config = config
        try:
            log_level = config.get('logging', 'log_level')
            self.log_level = self.__parse_log_level(log_level)
            self.log_format = config.get('logging', 'log_format')
            self.user = config.get('global', 'user')
            self.group = config.get('global', 'group')
            self.pid_file = config.get('global', 'pid_file')
            self.sock_file = config.get('global', 'socket_file')
            self.interpreter = config.get('global', 'interpreter')
            self.worker_count = int(config.get('global', 'worker_count'))
            self.sample_base_dir = config.get('global', 'sample_base_dir')
            self.job_hash_regex = config.get('global', 'job_hash_regex')
            self.use_debug_module = True if config.get(
                'global', 'use_debug_module'
            ) == 'yes' else False
            self.keep_mail_data = True if config.get(
                'global', 'keep_mail_data'
            ) == 'yes' else False
            self.db_url = config.get('db', 'url')
            self.ruleset_config = config.get('ruleset', 'config')
            self.cuckoo_mode = config.get('cuckoo', 'mode')
            self.cuckoo_url = config.get('cuckoo', 'url')
            self.cuckoo_poll_interval = config.get('cuckoo', 'poll_interval')
            self.cuckoo_storage = config.get('cuckoo', 'storage_path')
            self.cuckoo_exec = config.get('cuckoo', 'exec')
            self.cuckoo_submit = config.get('cuckoo', 'submit').split(' ')
            # Update logging with what we just parsed from the config
            self.__setup_logging()
        except NoSectionError as e:
            logger.critical('configuration section not found')
            logger.exception(e)
            sys.exit(1)
        except NoOptionError as e:
            logger.critical('configuration option not found')
            logger.exception(e)
            sys.exit(1)

    def change_log_level(self, log_level):
        """
        Overwrite the log level from the configuration file.

        :param log_level: The new log level.
        """
        ll = self.__parse_log_level(log_level)
        self.log_level = ll
        logger.setLevel(ll)

    def __parse_log_level(self, log_level):
        if log_level == 'CRITICAL':
            return logging.CRITICAL
        elif log_level == 'ERROR':
            return logging.ERROR
        elif log_level == 'WARNING':
            return logging.WARNING
        elif log_level == 'INFO':
            return logging.INFO
        elif log_level == 'DEBUG':
            return logging.DEBUG

    def __setup_logging(self):
        """
        Setup logging to console.
        """
        _logger = logging.getLogger()

        # Check if we already have a log handler
        if len(_logger.handlers) > 0:
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
        sections = {}
        for section in self.__config.sections():
            sections[section] = {}
            for key, value in self.__config.items(section):
                sections[section][key] = value
        return '<PeekabooConfig(%s)>' % str(sections)

    __repr__ = __str__


class PeekabooRulesetConfiguration(object):
    """
    This class represents the ruleset configuration file "ruleset.conf".

    The ruleset configuration is stored as a dictionary in the form of
    ruleset_config[rule_name][config_option] = value | [value1, value2, ...]

    @author: Sebastian Deiss
    @since: 1.6
    """
    def __init__(self, config_file):
        self.config_file = config_file
        self.ruleset_config = {}
        config = SafeConfigParser()
        try:
            config.read(self.config_file)
            for section in config.sections():
                if section not in self.ruleset_config.keys():
                    self.ruleset_config[section] = {}
                for setting, value in config.items(section):
                    if '.' in setting:
                        key = setting.split('.')[0]
                        if key not in self.ruleset_config[section]:
                            self.ruleset_config[section][key] = []
                        self.ruleset_config[section][key].append(value)
                    else:
                        self.ruleset_config[section][setting] = value
        except NoSectionError as e:
            logger.exception(e)
        except NoOptionError as e:
            logger.exception(e)

    def rule_config(self, rule):
        # potentially do some validity checks here

        # arbitrary interface definition: return an empty hash if no rule
        # config exists as empty rule config so the rule func can rely on it
        # and does not need to do any type checking
        return self.ruleset_config.get(rule, {})

    # rule is enabled as long as:
    # - no config section for that rule is present
    # - enabled keyword is not present in that section or
    # - enabled is not equal to 'no'
    def rule_enabled(self, rule):
        return (self.rule_config(rule).get('enabled', 'yes') != 'no')

    def __str__(self):
        return '<PeekabooRulesetConfiguration(filepath="%s")>' % self.config_file

    __repr__ = __str__
