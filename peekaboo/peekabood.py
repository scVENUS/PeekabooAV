###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# peekabood.py                                                                #
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


from __future__ import print_function
from __future__ import absolute_import
import os
import sys
import threading
import socket
import errno
import stat
import pwd
import grp
import logging
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from twisted.internet import reactor
from . import _owl, __version__, logger
from .pjobs import Jobs, Workers
from .sample import Sample
from .config import PeekabooConfig
from .db import PeekabooDBHandler
from .cuckoo_wrapper import CuckooManager


# marker to stop other threads on exit
global done


class PeekabooDaemonListener(object):
    """
    runs in separate thread (the second next to main
    (cuckooWrapper))the main thread runs cuckoo while this one handles
    socket connection and job submission

    @author: Felix Bauer
    @author: Sebastian Deiss
    """
    def __init__(self, config):
        self.config = config
        self.workers = Workers(config.worker_count)
        if os.path.exists(config.sock_file):
            os.remove(config.sock_file)

    def run(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        server.bind(self.config.sock_file)

        # The backlog argument specifies the maximum number of queued
        # connections and should be at least 0.
        # The maximum value is system-dependent (usually 5).
        server.listen(5)

        # allow writes to socket by others
        os.chmod(self.config.sock_file, stat.S_IWOTH)

        os.chmod(self.config.sock_file, stat.S_IREAD | stat.S_IWRITE |
                 stat.S_IRGRP | stat.S_IWGRP | stat.S_IWOTH)

        if oct(os.stat(self.config.sock_file).st_mode & 0777) == '0662' or \
           grp.getgrgid(int(os.stat(self.config.sock_file).st_gid)).gr_name == 'amavis':
            pass
        else:
            logger.error('Check permissions on filesocket %s (user amavis has '
                         'to be able to write to it' % self.config.sock_file)

        logger.info("Listening...")
        done = False
        while done is False:
            try:
                # check if Workers are alive
                # for worker in Workers.w:
                #    if not worker.isAlive():
                #        # TODO clean up and restart worker
                #        done = True
                #        raise Exception('Worker thread died', self.workers)

                # block wait for incoming connection
                conn, __ = server.accept()

                conn.send("Hallo das ist Peekaboo\n\n")

                # check if there are more than twice as many samples in
                # queue waiting to be processed as there are worker
                # threads:
                if Workers.q.qsize() > self.config.worker_count * 2:
                    conn.send("WARNING: queue size > %d, rejected connection from amavis\n"
                              % (self.config.worker_count * 2))
                    conn.close()
                    logger.warning('Queue size > %d, rejected connection from amavis'
                                   % (self.config.worker_count * 2))
                    continue

                logger.info('Accepted connection')

                # receive directory path from amavis socket
                path = str(conn.recv(1024)).replace('\n', '')

                logger.info("Received %s" % path)

                if not os.path.exists(path):
                    conn.send("ERROR: path from amavis doesn't exist or no "
                              "permission to access it")
                    logger.error('Path from amavis doesn\'t exist or no '
                                 'permission to access it')
                    conn.close()
                    continue
                else:   # path does exist
                    # close connection if there is nothing to analyze
                    for_analysis = []
                    if os.path.isfile(path):
                        sample = self._make_sample(path, conn)
                        if sample:
                            for_analysis.append(sample)
                    else:
                        # walk recursively through entries in directory
                        for dirname, __, filenames in os.walk(path):
                            for filename in filenames:
                                logger.debug("Found file %s" % filename)
                                p = os.path.join(dirname, filename)
                                sample = self._make_sample(p, conn)
                                if sample:
                                    for_analysis.append(sample)

                    # introduced after issue where results were reported
                    # before all file could be added
                    for s in for_analysis:
                        Jobs.add_job(conn, s)
                        self.workers.submit_job(s, self.__class__)

                    if len(for_analysis) == 0:
                        conn.close()
            except socket.error as e:
                # A socket error
                logger.error('Socket error exception %s %s' % (type(e),
                                                               str(e)))
            except IOError as e:
                logger.debug('ERROR, IO error exception %s %s' % (type(e),
                                                                  str(e)))
                if e.errno == errno.EPIPE:
                    logger.error('ERROR, something went wrong with PIPE')
            except Exception:
                logger.error('Unexpected exception in PeekabooDaemonListener')
                raise

        logger.debug("Shutting down...")

        server.close()
        os.remove(self.config.sock_file)

        logger.debug('Socket closed')

    def _make_sample(self, p, conn):
        logger.debug("Looking at file %s" % p)
        if not os.path.isfile(p):
            logger.debug('%s is not a file' % p)
            return None
        s = Sample(self.config, conn, p)
        logger.debug('Created sample %s' % s)

        # check if sample is already in progress
        existing = Jobs.get_sample_by_sha256(s.sha256sum)
        if existing is not None:
            logger.info("Same sample detected %s and %s"
                        % (s, existing))
            return None

        # TODO:
        # handle this (problem sample.__socketConnection not [])
        # multiple analysis of same file (wait for inProgress finish)
        #    Jobs.addJob(conn, same)
        # 2017-03-01: sdeiss: forAnalysis.append(s) is now in the else path.
        return s


def __get_dev_status(config):
    """
    State, code, and changes from git

    TODO: Remove for production.
    """
    logger.debug("State, Code and Changes from git")
    # user and groups
    uid = pwd.getpwuid(os.getuid())[0]
    groups = ', '.join([grp.getgrgid(g).gr_name for g in os.getgroups()])
    logger.debug('User: %s, groups: %s' % (uid, groups))

    logger.debug("permissions on %s" % config.sock_file)
    os.system("ls -la %s" % config.sock_file)

    # put most resent git commit id and comment into log
    os.system("git status")     # info about modified files
    os.system("git log -1")     # full info of last commit
    os.system("git log --oneline --decorate | head -5")   # last 5 commits

    # put local changes into log
    os.system("git diff | cat")

    # put installed pip packages into log
    logger.debug("pip check for installed requirements and versions")
    os.system("bash -c \"comm --nocheck-order -23 requirements.txt"
              "<(pip freeze)\"")

    # put database state into log
    logger.debug("database schema and count of records")
    os.system("sqlite3 analysis.db \".schema\"")
    os.system("sqlite3 analysis.db \"SELECT COUNT(*) FROM sample\"")


def main():
    arg_parser = ArgumentParser()
    arg_parser.add_argument('-c', '--config', action='store', required=False,
                            default=os.path.join('./peekaboo.conf'),
                            help='The configuration file for Peekaboo.')
    arg_parser.add_argument('-d', '--debug', action='store_true', required=False,
                            help="Run Peekaboo in debug mode regardless of what's "
                                 "specified in the configuration.",
                            default=False)
    arg_parser.add_argument('-D', '--daemon', action='store_true', required=False,
                            help='Run Peekaboo in daemon mode (suppresses the logo to be written to STDOUT.',
                            default=False)
    args = arg_parser.parse_args()

    if not args.daemon:
        print(_owl)
    else:
        print('Starting Peekaboo %s.' % __version__)

    # read configuration
    config = PeekabooConfig(args.config)
    # Check if CLI arguments override the configuration
    if args.debug:
        config.log_level = logging.DEBUG
    config.setup_logging()

    # Log the configuration options if we are in debug mode
    if config.log_level == logging.DEBUG:
        logger.debug(config.__str__())

    # establish a connection to the database
    try:
        db_con = PeekabooDBHandler(config.db_url)
        config.add_db_con(db_con)
    except Exception as e:
        logger.critical(str(e))
        sys.exit(1)

    # Import debug module if we are in debug mode
    if config.log_level == logging.DEBUG:
        from peekaboo.debug import peekaboo_debugger
        peekaboo_debugger()

    if os.getuid() == 0:
        logger.warning('Peekaboo should not run as root')
        # drop privileges to user
        os.setgid(grp.getgrnam(config.group)[2])
        os.setuid(pwd.getpwnam(config.user)[2])
        # set $HOME to the users home directory
        # (VirtualBox must access the configs)
        os.environ['HOME'] = pwd.getpwnam(config.user)[5]
        logger.info("Dropped privileges to user %s and group %s"
                    % (config.user, config.group))
        logger.debug('$HOME is ' + os.environ['HOME'])

    # write PID file
    pid = str(os.getpid())
    file(config.pid_file, "w").write("%s\n" % pid)

    # show development status (latest git changes etc.) in debug mode
    if config.log_level == 'DEBUG':
        __get_dev_status(config)

    # start thread to handle socket connections from amavis
    listener = PeekabooDaemonListener(config)
    daemon = threading.Thread(target=listener.run)
    daemon.daemon = True
    daemon.start()

    # tell systemd startup finished
    #  there is more
    #  https://www.freedesktop.org/software/systemd/man/sd_notify.html#
    n = SystemdNotifier()
    n.notify("READY=1")

    # Run Cuckoo sandbox, parse log output, and report back of Peekaboo.
    # If this dies Peekaboo dies, since this is the main thread.
    mgr = CuckooManager()
    reactor.spawnProcess(mgr, config.interpreter, [config.interpreter, '-u',
                                                   config.cuckoo_exec])
    reactor.run()

    # just so other threads also terminate
    done = True
    logger.info("Terminating.")


if __name__ == '__main__':
    main()
