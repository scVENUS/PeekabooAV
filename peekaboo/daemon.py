###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# daemon.py                                                                   #
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
import sys
import errno
import grp
import pwd
import stat
import logging
import socketserver
import socket
import signal
from time import sleep
import json
from threading import Thread, Event
from argparse import ArgumentParser
from sdnotify import SystemdNotifier
from peekaboo import PEEKABOO_OWL, __version__
from peekaboo.config import PeekabooConfig, PeekabooRulesetConfig
from peekaboo.db import PeekabooDatabase
from peekaboo.queuing import JobQueue
from peekaboo.ruleset import Result
from peekaboo.sample import SampleFactory
from peekaboo.exceptions import PeekabooDatabaseError, PeekabooConfigException
from peekaboo.toolbox.cuckoo import Cuckoo, CuckooEmbed, CuckooApi


logger = logging.getLogger(__name__)


class SignalHandler():
    """
    Signal handler.
    
    @author: Felix Bauer
    """
    def __init__(self):
        """ register custom signal handler """
        self.listeners = []

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGCHLD, self.signal_handler)

    def register_listener(self, listener):
        """ Register a listener object which is expected to implement a very
        simple interface: Method shut_down() is called if SIGINT or SIGTERM
        arrive, reap_children() is called if SIGCHLD arrives. Both are expected
        to defer actual handling of the condition. """
        self.listeners.append(listener)

    def signal_handler(self, sig, frame):
        """ catch signal and call appropriate methods in registered listener
        classes """
        if sig == signal.SIGINT or sig == signal.SIGTERM:
            logger.debug("SIGINT/TERM")

            # these should take serious care about being called across threads
            for listener in self.listeners:
                listener.shut_down()

        if sig == signal.SIGCHLD:
            logger.debug("SIGCHLD")
            for listener in self.listeners:
                listener.reap_children()


class PeekabooStreamServer(socketserver.ThreadingUnixStreamServer):
    """
    Asynchronous server.

    @author: Sebastian Deiss
    """
    def __init__(self, server_address, request_handler_cls, job_queue,
                 sample_factory, bind_and_activate=True,
                 request_queue_size=10, status_change_timeout=60):
        self.server_address = server_address
        self.__job_queue = job_queue
        self.__sample_factory = sample_factory
        self.request_queue_size = request_queue_size
        self.allow_reuse_address = True
        self.status_change_timeout = status_change_timeout
        self.__shutdown_requested = False
        self.__request_triggers = {}
        
        # no super() since old-style classes
        logger.debug('Starting up server.')
        socketserver.ThreadingUnixStreamServer.__init__(self, server_address,
                                                        request_handler_cls,
                                                        bind_and_activate=bind_and_activate)

    @property
    def job_queue(self):
        return self.__job_queue

    @property
    def sample_factory(self):
        return self.__sample_factory

    @property
    def shutting_down(self):
        """ Return True if we've received a shutdown request. """
        return self.__shutdown_requested

    def register_request(self, thread, event):
        """ Register an event for a request being handled to trigger if we want
        it to shut down. """
        self.__request_triggers[thread] = event
        logger.debug('Request registered with server.')

    def deregister_request(self, thread):
        """ Deregister a request which has finished handling and does no logner
        need to be made aware that we want it to shut down. """
        logger.debug('Request deregistered from server.')
        del self.__request_triggers[thread]

    def shutdown(self):
        """ Shut down the server. In our case, notify requests which are
        currently being handled to shut down as well. """
        logger.debug('Server shutting down.')
        self.__shutdown_requested = True
        for thread in self.__request_triggers:
            # wake up the thread so it can see that we're shutting down
            self.__request_triggers[thread].set()

        socketserver.ThreadingUnixStreamServer.shutdown(self)

    def server_close(self):
        """ Finally completely close down the server. """
        logger.debug('Closing down server.')
        # no new connections from this point on
        os.remove(self.server_address)
        return socketserver.ThreadingUnixStreamServer.server_close(self)


class PeekabooStreamRequestHandler(socketserver.StreamRequestHandler):
    """
    Request handler used by PeekabooStreamServer to handle analysis requests.

    @author: Sebastian Deiss
    """
    def setup(self):
        socketserver.StreamRequestHandler.setup(self)
        self.job_queue = self.server.job_queue
        self.sample_factory = self.server.sample_factory
        self.status_change_timeout = self.server.status_change_timeout

    def handle(self):
        """
        Handles an analysis request. This is expected to be a JSON structure
        containing the path of the directory / file to analyse. Structure::

            [ { "full_name": "<path>",
                "name_declared": ...,
                ... },
              { ... },
              ... ]

        The maximum buffer size is 16 KiB, because JSON incurs some bloat.
        """
        self.request.sendall('Hallo das ist Peekaboo\n\n')
        request = self.request.recv(1024 * 16).rstrip()

        try:
            parts = json.loads(request)
        except:
            self.request.sendall('FEHLER: Ungueltiges JSON.')
            logger.error('Invalid JSON in request.')
            return

        if type(parts) not in (list, tuple):
            self.request.sendall('FEHLER: Ungueltiges Datenformat.')
            logger.error('Invalid data structure.')
            return

        # create an event we will give to all the samples to wake us if their
        # status changes
        status_change = Event()
        status_change.clear()

        to_be_analysed = []
        for part in parts:
            if not part.has_key('full_name'):
                self.request.sendall('FEHLER: Unvollstaendige Datenstruktur.')
                logger.error('Incomplete data structure.')
                return

            path = part['full_name']
            logger.info("Got run_analysis request for %s" % path)
            if not os.path.exists(path):
                self.request.sendall('FEHLER: Pfad existiert nicht oder '
                        'Zugriff verweigert.')
                logger.error('Path does not exist or no permission '
                        'to access it.')
                return

            if not os.path.isfile(path):
                self.request.sendall('FEHLER: Eingabe ist keine Datei.')
                logger.error('Input is not a file')
                return

            sample = self.sample_factory.make_sample(
                path, status_change=status_change, metainfo=part)
            to_be_analysed.append(sample)
            logger.debug('Created sample %s' % sample)

        # introduced after an issue where results were reported
        # before all files could be added.
        for sample in to_be_analysed:
            self.job_queue.submit(sample, self.__class__)

        # register with our server so it can notify us if it wants us to shut
        # down
        # NOTE: Every exit point from this routine needs to deregister this
        # request from the server to avoid memory leaks. Unfortunately, the
        # server cannot do this iteself on shutdown_request() because it does
        # not have any thread ID available there.
        self.server.register_request(self, status_change)

        # wait for results to come in
        done = []
        while to_be_analysed:
            # wait for an event to signal that its status has changed or
            # timeout expires
            if not status_change.wait(self.status_change_timeout):
                # keep our client engaged
                # TODO: Impose maximum processing time of our own?
                try:
                    self.request.send('Dateien werden analysiert...\n')
                    logger.debug('Client updated that samples are still '
                                 'processing.')
                except IOError as ioerror:
                    if ioerror.errno == errno.EPIPE:
                        # client got fed up with waiting, we're done here
                        logger.warning(
                            'Client closed connection on us: %s', ioerror)

                        # Abort handling this request since no-one's interested
                        # any more. We could dequeue the samples here to avoid
                        # unnecessary work. Instead we'll have them run their
                        # course, assuming that we'll be much quicker
                        # responding if the client decides to resubmit them.
                        self.server.deregister_request(self)
                        return

                    logger.warning('Error updating client on processing '
                                   'status: %s', ioerror)

                # Fall through here and evaluate all samples for paranoia's
                # sake in case our status change event has a race condition.
                # It shouldn't though, because we wait for it, then first clear
                # it and then look at all samples that might have set it. If
                # while doing that another sample sets it and we don't catch it
                # because we've already looked at it, the next wait will
                # immediately return and send us back into checking all samples
                # for status change.

            # see if our server is shutting down and follow it if so
            if self.server.shutting_down:
                try:
                    self.request.send('Peekaboo wird beendet.\n')
                    logger.debug('Request shutting down with server.')
                except IOError as ioerror:
                    pass

                self.server.deregister_request(self)
                return

            status_change.clear()

            # see which samples are done and which are still processing
            still_analysing = []
            for sample in to_be_analysed:
                if sample.done:
                    done.append(sample)
                    continue

                still_analysing.append(sample)

            to_be_analysed = still_analysing

        # deregister notification from server since we've exited our wait loop
        self.server.deregister_request(self)

        # evaluate results into an overall result: We want to present the
        # client with an overall result instead of confusing them with
        # assertions about individual files. Particularly in the case of
        # AMaViS, this would otherwise lead to messages being passed on as
        # clean where a single attachment evaluated to "good" but analysis of
        # all the others failed.
        result = Result.unchecked
        reports = []
        logger.debug('Determining final verdict to report to client.')
        for sample in done:
            # check if result of this rule is worse than what we know so far
            sample_result = sample.get_result()
            logger.debug('Current overall result: %s, Sample result: %s',
                         result.name, sample_result.name)
            if sample_result >= result:
                result = sample_result

            # and unconditionally append its report to our list of things to
            # report to the client
            reports.append(sample.get_peekaboo_report())

        # report back
        logger.debug('Reporting batch as "%s" to client', result.name)
        reports.append('Die Datensammlung wurde als "%s" eingestuft\n\n'
                       % result.name)
        for report in reports:
            try:
                self.request.send(report)
            except IOError as ioerror:
                if ioerror.errno == errno.EPIPE:
                    # client got fed up with waiting, we're done here
                    logger.warning('Client closed connection on us: %s',
                                   ioerror)
                else:
                    logger.warning('Error sending report to client: %s',
                                   ioerror)

                return

        # shut down connection
        logger.debug('Results reported back to client - closing connection.')


def run():
    """ Runs the Peekaboo daemon. """
    arg_parser = ArgumentParser(
        description='Peekaboo Extended Email Attachment Behavior Observation Owl'
    )
    arg_parser.add_argument(
        '-c', '--config',
        action='store',
        help='The configuration file for Peekaboo.'
    )
    arg_parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help="Run Peekaboo in debug mode regardless of what's specified in the configuration."
    )
    arg_parser.add_argument(
        '-D', '--daemon',
        action='store_true',
        help='Run Peekaboo in daemon mode (suppresses the logo to be written to STDOUT).'
    )
    args = arg_parser.parse_args()

    print('Starting Peekaboo %s.' % __version__)
    if not args.daemon:
        print(PEEKABOO_OWL)

    # Check if CLI arguments override the configuration
    log_level = None
    if args.debug:
        log_level = logging.DEBUG

    try:
        config = PeekabooConfig(config_file=args.config, log_level=log_level)
        logger.debug(config)
    except PeekabooConfigException as error:
        logging.critical(error)
        sys.exit(1)

    # establish a connection to the database
    try:
        db_con = PeekabooDatabase(
            db_url=config.db_url, instance_id=config.cluster_instance_id,
            stale_in_flight_threshold=config.cluster_stale_in_flight_threshold)
    except PeekabooDatabaseError as error:
        logging.critical(error)
        sys.exit(1)
    except Exception as error:
        logger.critical('Failed to establish a connection to the database '
                        'at %s: %s', config.db_url, error)
        sys.exit(1)

    # Import debug module if we are in debug mode
    debugger = None
    if config.use_debug_module:
        from peekaboo.debug import PeekabooDebugger
        debugger = PeekabooDebugger()
        debugger.start()

    if os.getuid() == 0:
        if config.user and config.group:
            # drop privileges to user
            os.setgid(grp.getgrnam(config.group)[2])
            os.setuid(pwd.getpwnam(config.user)[2])
            logger.info("Dropped privileges to user %s and group %s"
                        % (config.user, config.group))

            # set $HOME to the users home directory
            # (VirtualBox must access the configs)
            os.environ['HOME'] = pwd.getpwnam(config.user)[5]
            logger.debug('$HOME is ' + os.environ['HOME'])
        else:
            logger.warning('Peekaboo should not run as root. Please '
                           'configure a user and group to run as.')
            sys.exit(0)

    # write PID file
    pid = str(os.getpid())
    with open(config.pid_file, "w") as pidfile:
        pidfile.write("%s\n" % pid)

    systemd = SystemdNotifier()

    # clear all our in flight samples and all instances' stale in flight
    # samples
    db_con.clear_in_flight_samples()
    db_con.clear_stale_in_flight_samples()

    # a cluster duplicate interval of 0 disables the handler thread which is
    # what we want if we don't have an instance_id and therefore are alone
    cluster_duplicate_check_interval = 0
    if config.cluster_instance_id > 0:
        cluster_duplicate_check_interval = config.cluster_duplicate_check_interval
        if cluster_duplicate_check_interval < 5:
            cluster_update_check_interval = 5
            log.warning("Raising excessively low cluster duplicate check "
                        "interval to %d seconds.",
                        cluster_duplicate_check_interval)

    # workers of the job queue need the ruleset configuration to create the
    # ruleset engine with it
    try:
        ruleset_config = PeekabooRulesetConfig(config.ruleset_config)
        logger.debug(ruleset_config)
    except PeekabooConfigException as error:
        logging.critical(error)
        sys.exit(1)

    job_queue = JobQueue(
        worker_count=config.worker_count, ruleset_config=ruleset_config,
        db_con=db_con,
        cluster_duplicate_check_interval=cluster_duplicate_check_interval)

    if config.cuckoo_mode == "embed":
        cuckoo = CuckooEmbed(job_queue, config.cuckoo_exec,
                             config.cuckoo_submit, config.cuckoo_storage,
                             config.interpreter)
    # otherwise it's the new API method and default
    else:
        cuckoo = CuckooApi(job_queue, config.cuckoo_url,
                config.cuckoo_poll_interval)

    sig_handler = SignalHandler()
    sig_handler.register_listener(cuckoo)

    # Factory producing almost identical samples providing them with global
    # config values and references to other objects they need, such as cuckoo,
    # database connection and connection map.
    sample_factory = SampleFactory(cuckoo,
                config.sample_base_dir, config.job_hash_regex,
                config.keep_mail_data)

    # Try three times to start SocketServer
    for i in range(0, 3):
        try:
            # We only want to accept 2 * worker_count connections.
            server = PeekabooStreamServer(config.sock_file,
                    PeekabooStreamRequestHandler,
                    job_queue = job_queue,
                    sample_factory = sample_factory,
                    request_queue_size = config.worker_count * 2)
            break
        except socket.error as msg:
            logger.warning("SocketServer couldn't start (%i): %s" % (i, msg))
    if not server:
        logger.error('Fatal: Couldn\'t initialise Peekaboo Server')
        sys.exit(1)

    runner = Thread(target=server.serve_forever)
    runner.daemon = True

    rc = 1
    try:
        runner.start()
        logger.info('Peekaboo server is listening on %s' % server.server_address)

        os.chmod(config.sock_file, stat.S_IWOTH | stat.S_IREAD |
                                   stat.S_IWRITE | stat.S_IRGRP |
                                   stat.S_IWGRP | stat.S_IWOTH)

        systemd.notify("READY=1")
        # If this dies Peekaboo dies, since this is the main thread. (legacy)
        rc = cuckoo.do()
    except Exception as error:
        logger.critical('Main thread aborted: %s' % error)
    finally:
        server.shutdown()
        server.server_close()
        job_queue.shut_down()
        db_con.clear_in_flight_samples()
        db_con.clear_stale_in_flight_samples()
        if debugger is not None:
            debugger.shut_down()

    sys.exit(rc)

if __name__ == '__main__':
    run()
