###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# db.py                                                                       #
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

""" A class wrapping database operations needed by Peekaboo based on
SQLAlchemy. """

import asyncio
import random
import re
import time
import threading
import logging
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Text, DateTime, \
        Enum, Index
import sqlalchemy.sql.expression
import sqlalchemy.ext.asyncio
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import SQLAlchemyError, IntegrityError, OperationalError, \
        DBAPIError
from peekaboo import __version__
from peekaboo.ruleset import Result
from peekaboo.sample import JobState
from peekaboo.exceptions import PeekabooDatabaseError

DB_SCHEMA_VERSION = 9

logger = logging.getLogger(__name__)
Base = declarative_base()


#
# Database schema definition.
##############################################################################


class InFlightSample(Base):
    """
    Table tracking whether a specific sample is currently being analysed and by
    which Peekaboo instance.
    """
    __tablename__ = 'in_flight_samples_v%d' % DB_SCHEMA_VERSION

    # Indices:
    # - general considerations: The table will likely never have more than a
    #   couple of hundret entries. But we add and delete quite frequently.
    # - uniqueness of the primary key ensures atomic insertion when adding a
    #   lock
    # - column: we delete our own stale locks by instance_id.
    # - column: we delete other's stale locks by start_time.
    # - compound: we delete our own locks by sha256sum and instance_id.
    #   (admittedly a bit of overkill since the individual columns are already
    #   indexed.)

    sha256sum = Column(String(64), primary_key=True)
    instance_id = Column(Integer, nullable=False, index=True)
    start_time = Column(DateTime, nullable=False, index=True)

    __table_args__ = (
        # Index names need to be unique per schema in postgresql.
        Index('ix_%s_sha_iid' % __tablename__, sha256sum, instance_id),
        )

    def __str__(self):
        return (
            '<InFlightSample(sha256sum="%s", instance_id="%s", '
            'start_time="%s")>'
            % (self.sha256sum,
               self.instance_id,
               self.start_time.strftime("%Y%m%dT%H%M%S"))
        )

    __repr__ = __str__


class SampleInfo(Base):
    """ Definition of the sample_info table. """
    __tablename__ = 'sample_info_v%d' % DB_SCHEMA_VERSION

    # Indices:
    # - general considerations: The table grows very large over time. Every
    #   sample is checked against it to find a cached analysis result.
    #   Otherwise it's quite unused currently.
    # - compound: we frequently search by sha256sum and file extension

    id = Column(Integer, primary_key=True)
    state = Column(Enum(JobState), nullable=False)
    sha256sum = Column(String(64), nullable=False)
    file_extension = Column(String(16), nullable=True)
    analysis_time = Column(DateTime, nullable=False,
                           index=True)
    result = Column(Enum(Result), nullable=False)
    reason = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_%s_sha_fe' % __tablename__, sha256sum, file_extension),
        )

    def __str__(self):
        return ('<SampleInfo(sample_sha256_hash="%s", file_extension="%s", '
                'reason="%s", analysis_time="%s")>'
                % (self.sha256sum,
                   self.file_extension,
                   self.reason,
                   self.analysis_time.strftime("%Y%m%dT%H%M%S")))

    __repr__ = __str__


#
# End of database schema definition.
##############################################################################


class PeekabooDatabase:
    """ Peekaboo's database. """
    def __init__(self, db_url, instance_id=0,
                 stale_in_flight_threshold=15*60,
                 log_level=logging.WARNING):
        """
        Initialize the Peekaboo database handler.

        @param db_url: An RFC 1738 URL that points to the database.
        @param instance_id: A positive, unique ID differentiating this Peekaboo
                            instance from any other instance using the same
                            database for concurrency coordination. Value of 0
                            means that we're alone and have no other instances
                            to worry about.
        @param stale_in_flight_threshold: Number of seconds after which a in
        flight marker is considered stale and deleted or ignored.
        @param log_level: Overrides the log level of the database modules. The
                          idea is for the database to be silent by default and
                          only emit log messages if switched on explictly and
                          independently of the Peekaboo log level.
        """
        logging.getLogger('sqlalchemy.engine').setLevel(log_level)
        # aiosqlite picks up the global log level unconditionally so we need to
        # override it as well and explicitly
        logging.getLogger('aiosqlite').setLevel(log_level)

        self.__engine = create_engine(db_url, future=True)
        session_factory = sessionmaker(bind=self.__engine)
        self.__session = scoped_session(session_factory)
        self.__lock = threading.RLock()
        self.__async_lock = asyncio.Lock()

        async_db_url = re.sub(
            r'sqlite(\+[a-z]+)?:///', 'sqlite+aiosqlite:///', re.sub(
            r'mysql(\+[a-z]+)?://', 'mysql+asyncmy://', re.sub(
            r'postgresql(\+[a-z]+)?://', 'postgresql+asyncpg://',
            db_url)))
        async_engine = sqlalchemy.ext.asyncio.create_async_engine(async_db_url)
        self.__async_session_factory = sessionmaker(
            bind=async_engine,
            class_=sqlalchemy.ext.asyncio.AsyncSession)
        # no scoping necessary as we're not using asyncio across threads

        self.instance_id = instance_id
        self.stale_in_flight_threshold = stale_in_flight_threshold
        self.retries = 5
        # ultra-simple quadratic backoff:
        # attempt 1: 10 * 2**(1) == 10-20msecs
        # attempt 2: 10 * 2**(2) == 20-40msecs
        # attempt 3: 10 * 2**(3) == 40-80msecs
        # attempt 4: 10 * 2**(4) == 80-160msecs
        self.deadlock_backoff_base = 10
        self.connect_backoff_base = 2000

        attempt = 1
        delay = 0
        while attempt <= self.retries:
            with self.__lock:
                try:
                    Base.metadata.create_all(self.__engine)
                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    attempt, delay = self.was_transient_error(
                        error, attempt, 'create metadata')

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Failed to create schema in database: %s' % error)

            time.sleep(delay)

    def was_transient_error(self, error, attempt, action):
        """ Decide if an exception signals a transient error condition and
        sleep for some milliseconds if so.

        @param error: The exception object to look at.
        @type attempt: The current attempt number.
        @returns: The new attempt number or -1 if no further attempts should be
                  made.
        """
        # will not be retried anyway, so no use checking and sleeping
        if attempt >= self.retries:
            return -1, 0

        # only DBAPIError has connection_invalidated

        if getattr(error, 'connection_invalidated', False):
            logger.debug('Connection invalidated %s. Retrying.', action)
            return attempt + 1, 0

        # Access the original DBAPI exception anonymously.
        # We intentionally do some crude duck-typing here to avoid
        # imports of otherwise optional RDBMS modules. False-positive
        # would cause some useless retries of a different but
        # identically numbered error of another RDBMS.
        if (getattr(error, 'orig', None) is None or
                getattr(error.orig, 'args', None) is None):
            return -1, 0

        args = error.orig.args

        # (MySQLdb._exceptions.OperationalError) (2002, "Can't connect to local
        # MySQL server through socket '/var/run/mysqld/mysqld.sock' (2)")
        if (isinstance(args, tuple) and len(args) > 0 and args[0] in [2002, 2003]):
            # sleep some millisecs
            maxmsecs = self.connect_backoff_base * 2**attempt
            backoff = random.randint(maxmsecs/2, maxmsecs)
            logger.debug('Connection failed %s, backing off for %d '
                         'milliseconds before retrying', action, backoff)
            return attempt + 1, backoff / 1000

        # (MySQLdb._exceptions.OperationalError) (1213, 'Deadlock
        # found when trying to get lock; try restarting transaction')
        if (isinstance(args, tuple) and len(args) > 0 and args[0] in [1213]):
            # sleep some millisecs
            maxmsecs = self.deadlock_backoff_base * 2**attempt
            backoff = random.randint(maxmsecs/2, maxmsecs)
            logger.debug('Database deadlock detected %s, backing off for %d '
                         'milliseconds before retrying.', action, backoff)
            return attempt + 1, backoff / 1000

        return -1, 0

    async def analysis_add(self, sample):
        """
        Add an analysis task to the analysis journal in the database.

        @param sample: The sample object for this analysis task.
        @returns: ID of the newly created analysis task (also updated
                  in the sample)
        """
        sample_info = SampleInfo(
            state=sample.state,
            sha256sum=sample.sha256sum,
            file_extension=sample.file_extension,
            analysis_time=datetime.now(),
            result=sample.result,
            reason=sample.reason)

        job_id = None
        attempt = 1
        delay = 0
        while attempt <= self.retries:
            async with self.__async_lock:
                async with self.__async_session_factory() as session:
                    session.add(sample_info)
                    try:
                        # flush to retrieve the automatically assigned primary
                        # key value
                        await session.flush()
                        job_id = sample_info.id
                        await session.commit()
                        break
                    except (OperationalError, DBAPIError,
                            SQLAlchemyError) as error:
                        await session.rollback()

                        attempt, delay = self.was_transient_error(
                            error, attempt, 'adding analysis')

                        if attempt < 0:
                            raise PeekabooDatabaseError(
                                'Failed to add analysis task to the database: %s' % error)

            await asyncio.sleep(delay)

        sample.update_id(job_id)
        return job_id

    def analysis_update(self, sample):
        """
        Update an analysis task in the analysis journal in the database.

        @param sample: The sample object for this analysis task.
        """
        statement = sqlalchemy.sql.expression.update(SampleInfo).where(
            SampleInfo.id == sample.id).values(
                state=sample.state,
                result=sample.result,
                reason=sample.reason)

        attempt = 1
        delay = 0
        while attempt <= self.retries:
            with self.__lock:
                with self.__session() as session:
                    try:
                        session.execute(statement)
                        session.commit()
                        break
                    except (OperationalError, DBAPIError,
                            SQLAlchemyError) as error:
                        session.rollback()

                        attempt, delay = self.was_transient_error(
                            error, attempt, 'updating analysis')

                        if attempt < 0:
                            raise PeekabooDatabaseError(
                                'Failed to update analysis task in the database: %s' %
                                error)

            time.sleep(delay)

    def analysis_journal_fetch_journal(self, sample):
        """
        Fetch information stored in the database about a given sample object.

        @param sample: The sample object of which the information shall be
                       fetched from the database.
        @return: A sorted list of (analysis_time, result, reason) of the
                 requested sample.
        """
        statement = sqlalchemy.sql.expression.select(
            SampleInfo.analysis_time, SampleInfo.result,
            SampleInfo.reason).where(
                SampleInfo.id != sample.id).filter_by(
                    state=JobState.FINISHED,
                    sha256sum=sample.sha256sum,
                    file_extension=sample.file_extension).order_by(
                        SampleInfo.analysis_time)

        sample_journal = None
        attempt = 1
        delay = 0
        while attempt <= self.retries:
            with self.__session() as session:
                try:
                    sample_journal = session.execute(statement).all()
                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt, 'fetching analysis journal')

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Failed to fetch analysis journal from the database: %s' %
                            error)

            time.sleep(delay)

        return sample_journal

    async def analysis_retrieve(self, job_id):
        """
        Fetch information stored in the database about a given sample object.

        @param job_id: ID of the analysis to retrieve
        @type job_id: int
        @return: reason and result for the given analysis task
        """
        statement = sqlalchemy.sql.expression.select(
            SampleInfo.reason, SampleInfo.result).filter_by(
                id=job_id, state=JobState.FINISHED)

        result = None
        attempt = 1
        delay = 0
        while attempt <= self.retries:
            async with self.__async_session_factory() as session:
                try:
                    proxy = await session.execute(statement)
                    result = proxy.first()
                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    await session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt, 'retrieving analysis result')

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Failed to retrieve analysis from the database: %s' %
                            error)

            await asyncio.sleep(delay)

        return result

    def mark_sample_in_flight(self, sample, instance_id=None, start_time=None):
        """
        Mark a sample as in flight, i.e. being worked on by an instance.

        @param sample: The sample to mark as in flight.
        @param instance_id: (optionally) The ID of the instance that is
                            handling this sample. Default: Us.
        @param start_time: Override the time the marker was placed for
                           debugging purposes.
        """
        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if self.instance_id == 0:
            return True

        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        if start_time is None:
            start_time = datetime.utcnow()

        sha256sum = sample.sha256sum
        in_flight_marker = InFlightSample(sha256sum=sha256sum,
                                          instance_id=instance_id,
                                          start_time=start_time)
        attempt = 1
        delay = 0
        while attempt <= self.retries:
            # a new session needs to be constructed on each attempt
            with self.__session() as session:
                # try to mark this sample as in flight in an atomic insert
                # operation (modulo possible deadlocks with various RDBMS)
                session.add(in_flight_marker)

                try:
                    session.commit()
                    logger.debug('Marked sample %s as in flight', sha256sum)
                    return True
                # duplicate primary key == entry already exists
                except IntegrityError:
                    session.rollback()
                    logger.debug('Sample %s is already in flight on another '
                                'instance', sha256sum)
                    return False
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt, 'marking sample %s as in flight' %
                        sha256sum)

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Unable to mark sample as in flight: %s' % error)

            time.sleep(delay)

        return False

    def clear_sample_in_flight(self, sample, instance_id=None):
        """
        Clear the mark that a sample is being processed by an instance.

        @param sample: The sample to clear from in-flight list.
        @param instance_id: (optionally) The ID of the instance that is
                            handling this sample. Default: Us.
        """
        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if self.instance_id == 0:
            return

        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        sha256sum = sample.sha256sum
        statement = sqlalchemy.sql.expression.delete(
            InFlightSample).where(
                InFlightSample.sha256sum == sha256sum).where(
                    InFlightSample.instance_id == instance_id)

        attempt = 1
        cleared = 0
        while attempt <= self.retries:
            with self.__session() as session:
                try:
                    # clear in-flight marker from database
                    marker = session.execute(statement)
                    session.commit()
                    cleared = marker.rowcount
                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt, 'clearing in-flight status of '
                        'sample %s' % sha256sum)

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Unable to clear in-flight status of sample: %s' %
                            error)

            time.sleep(delay)

        if cleared == 0:
            raise PeekabooDatabaseError('Unexpected inconsistency: Sample %s '
                                        'not recoreded as in-flight upon '
                                        'clearing flag.' % sha256sum)
        elif cleared > 1:
            raise PeekabooDatabaseError('Unexpected inconsistency: Multiple '
                                        'instances of sample %s in-flight '
                                        'status cleared against database '
                                        'constraints!?' % sha256sum)

        logger.debug('Cleared sample %s from in-flight list', sha256sum)

    def clear_in_flight_samples(self, instance_id=None):
        """
        Clear all in-flight markers left over by previous runs or other
        instances by removing them from the lock table.

        @param instance_id: Clear our own (None), another instance's (positive
                            integer) or all instances' (negative integer) locks.
                            Since an instance_id of 0 disables in-flight sample
                            tracking, no instance will ever set a marker with
                            that ID so that specifying 0 here will amount to a
                            no-op or rather clean-up of invalid entries.
        """
        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples
        if self.instance_id == 0:
            return

        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        if instance_id < 0:
            # delete all locks
            statement = sqlalchemy.sql.expression.delete(InFlightSample)
            logger.debug('Clearing database of all in-flight samples.')
        else:
            # delete only the locks of a specific instance
            statement = sqlalchemy.sql.expression.delete(
                InFlightSample).where(
                    InFlightSample.instance_id == instance_id)
            logger.debug('Clearing database of all in-flight samples of '
                         'instance %d.', instance_id)

        attempt = 1
        while attempt <= self.retries:
            with self.__session() as session:
                try:
                    session.execute(statement)
                    session.commit()
                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt,
                        'clearing database of in-flight samples')

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Unable to clear the database of in-flight '
                            'samples: %s' % error)

            time.sleep(delay)

    def clear_stale_in_flight_samples(self):
        """
        Clear all in-flight markers that are too old and therefore stale. This
        detects instances which are locked up, crashed or shut down.
        """
        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if self.instance_id == 0:
            return True

        logger.debug(
            'Clearing database of all stale in-flight samples '
            '(%d seconds)', self.stale_in_flight_threshold)

        def clear_statement(statement_class):
            # delete only the locks of a specific instance
            return statement_class(InFlightSample).where(
                InFlightSample.start_time <= datetime.utcnow() - timedelta(
                    seconds=self.stale_in_flight_threshold))

        delete_statement = clear_statement(sqlalchemy.sql.expression.delete)
        select_statement = clear_statement(sqlalchemy.sql.expression.select)

        attempt = 1
        cleared = 0
        while attempt <= self.retries:
            with self.__session() as session:
                try:
                    # only do the query if debugging is enabled
                    if logger.isEnabledFor(logging.DEBUG):
                        # obviously there's a race between logging and actual
                        # delete here, use with caution, compare with actual
                        # number of markers cleared below before relying on it
                        # for debugging
                        markers = session.execute(select_statement)
                        for stale in markers:
                            logger.debug(
                                'Stale in-flight marker to clear: %s', stale)

                    markers = session.execute(delete_statement)
                    session.commit()

                    cleared = markers.rowcount
                    if cleared > 0:
                        logger.warning(
                            '%d stale in-flight samples cleared.', cleared)

                    break
                except (OperationalError, DBAPIError,
                        SQLAlchemyError) as error:
                    session.rollback()

                    attempt, delay = self.was_transient_error(
                        error, attempt,
                        'clearing the database of stale in-flight samples')

                    if attempt < 0:
                        raise PeekabooDatabaseError(
                            'Unable to clear the database of stale in-flight '
                            'samples: %s' % error)

            time.sleep(delay)

        return cleared > 0

    def drop(self):
        """ Drop all tables of the database. """
        try:
            Base.metadata.drop_all(self.__engine)
        except SQLAlchemyError as error:
            raise PeekabooDatabaseError(
                'Unable to drop all tables of the database: %s' % error)
