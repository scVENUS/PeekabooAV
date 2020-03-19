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

import threading
import logging
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, \
        Enum, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from peekaboo import __version__
from peekaboo.ruleset import Result
from peekaboo.exceptions import PeekabooDatabaseError

DB_SCHEMA_VERSION = 7

logger = logging.getLogger(__name__)
Base = declarative_base()


#
# Database schema definition.
##############################################################################


class PeekabooMetadata(Base):
    """ Definition of the _meta table for Peekaboo. """
    __tablename__ = '_meta'
    peekaboo_version = Column(String(10), nullable=False,
                              primary_key=True)
    db_schema_version = Column(Integer, nullable=False,
                               primary_key=True,
                               autoincrement=False)
    cuckoo_version = Column(String(10), nullable=False,
                            primary_key=True)

    def __str__(self):
        return (
            '<PeekabooMetadata(peekaboo_version="%s", db_schema_version="%s", '
            'cuckoo_version="%s")>'
            % (self.peekaboo_version,
               self.db_schema_version,
               self.cuckoo_version)
        )

    __repr__ = __str__


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
    sha256sum = Column(String(64), nullable=False)
    file_extension = Column(String(16), nullable=True)
    result = Column(Enum(Result), nullable=False)
    reason = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_%s_sha_fe' % __tablename__, sha256sum, file_extension),
        )

    def __str__(self):
        return ('<SampleInfo(sample_sha256_hash="%s", file_extension="%s", '
                'reason="%s")>'
                % (self.sha256sum,
                   self.file_extension,
                   self.reason))

    __repr__ = __str__


class AnalysisJournal(Base):
    """ Definition of the analysis_jobs table. """
    __tablename__ = 'analysis_jobs_v%d' % DB_SCHEMA_VERSION

    # Indices:
    # - general considerations: We're not using this table at all currently.
    #   All indexes are therefore currenly only futureproofing and admin or
    #   scripting aids.
    # - column: Speed up removal of old entries by analysis_time.
    # - column: Index foreign key to speed up search and removal by sample id.

    id = Column(Integer, primary_key=True)
    job_hash = Column(String(255), nullable=False)
    cuckoo_job_id = Column(Integer, nullable=False)
    filename = Column(String(255), nullable=False)
    analysis_time = Column(DateTime, nullable=False,
                           index=True)
    sample_id = Column(Integer, ForeignKey(SampleInfo.id),
                       nullable=False, index=True)
    sample = relationship('SampleInfo')

    def __str__(self):
        return (
            '<AnalysisJournal(job_hash="%s", cuckoo_job_id="%s", '
            'filename="%s", analysis_time="%s")>'
            % (self.job_hash,
               self.cuckoo_job_id,
               self.filename,
               self.analysis_time.strftime("%Y%m%dT%H%M%S"))
        )

    __repr__ = __str__


#
# End of database schema definition.
##############################################################################


class PeekabooDatabase(object):
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
        """
        logging.getLogger('sqlalchemy.engine').setLevel(log_level)

        self.__engine = create_engine(db_url, pool_recycle=1)
        session_factory = sessionmaker(bind=self.__engine)
        self.__session = scoped_session(session_factory)
        self.__lock = threading.RLock()
        self.instance_id = instance_id
        self.stale_in_flight_threshold = stale_in_flight_threshold
        if not self._db_schema_exists():
            self._init_db()
            logger.debug('Database schema created.')

    def analysis_save(self, sample):
        """
        Save an analysis task to the analysis journal in the database.

        @param sample: The sample object for this analysis task.
        """
        analysis = AnalysisJournal()
        analysis.job_hash = sample.job_hash
        analysis.cuckoo_job_id = sample.job_id
        analysis.filename = sample.filename
        analysis.analysis_time = datetime.now()
        sample_info = self.sample_info_fetch(sample)
        if sample_info is None:
            sample_info = SampleInfo(
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension,
                result=sample.result,
                reason=sample.reason)

        analysis.sample = sample_info

        with self.__lock:
            session = self.__session()
            session.add(analysis)
            try:
                session.commit()
            except SQLAlchemyError as error:
                session.rollback()
                raise PeekabooDatabaseError(
                    'Failed to add analysis task to the database: %s' % error
                )
            finally:
                session.close()

    def sample_info_fetch(self, sample):
        """
        Fetch information stored in the database about a given sample object.

        @param sample: The sample object of which the information shall be
                       fetched from the database.
        @return: A SampleInfo object containing the information stored in teh
                 database about the sample.
        """
        with self.__lock:
            session = self.__session()
            sample_info = session.query(SampleInfo).filter_by(
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension).first()
            session.close()
        return sample_info

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

        session = self.__session()

        # try to mark this sample as in flight in an atomic insert operation
        sha256sum = sample.sha256sum
        session.add(InFlightSample(sha256sum=sha256sum,
                                   instance_id=instance_id,
                                   start_time=start_time))

        locked = False
        try:
            session.commit()
            locked = True
            logger.debug('Marked sample %s as in flight', sha256sum)
        # duplicate primary key == entry already exists
        except IntegrityError:
            session.rollback()
            logger.debug('Sample %s is already in flight on another instance',
                         sha256sum)
        except SQLAlchemyError as error:
            session.rollback()
            raise PeekabooDatabaseError('Unable to mark sample as in flight: '
                                        '%s' % error)
        finally:
            session.close()

        return locked

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

        session = self.__session()

        # clear in-flight marker from database
        sha256sum = sample.sha256sum
        query = session.query(InFlightSample).filter(
            InFlightSample.sha256sum == sha256sum).filter(
                InFlightSample.instance_id == instance_id)

        try:
            # delete() is not queued and goes to the DB before commit()
            cleared = query.delete()
            session.commit()
        except SQLAlchemyError as error:
            session.rollback()
            raise PeekabooDatabaseError('Unable to clear in-flight status of '
                                        'sample: %s' % error)
        finally:
            session.close()

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

        session = self.__session()

        if instance_id < 0:
            # delete all locks
            query = session.query(InFlightSample)
            logger.debug('Clearing database of all in-flight samples.')
        else:
            # delete only the locks of a specific instance
            query = session.query(InFlightSample).filter(
                InFlightSample.instance_id == instance_id)
            logger.debug('Clearing database of all in-flight samples of '
                         'instance %d.', instance_id)
        try:
            # delete() is not queued and goes to the DB before commit()
            query.delete()
            session.commit()
        except SQLAlchemyError as error:
            session.rollback()
            raise PeekabooDatabaseError('Unable to clear the database of '
                                        'in-flight samples: %s' % error)
        finally:
            session.close()

    def clear_stale_in_flight_samples(self):
        """
        Clear all in-flight markers that are too old and therefore stale. This
        detects instances which are locked up, crashed or shut down.
        """
        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if self.instance_id == 0:
            return True

        session = self.__session()

        # delete only the locks of a specific instance
        query = session.query(InFlightSample).filter(
            InFlightSample.start_time <= datetime.utcnow() - timedelta(
                seconds=self.stale_in_flight_threshold))
        logger.debug(
            'Clearing database of all stale in-flight samples '
            '(%d seconds)', self.stale_in_flight_threshold)

        try:
            # the loop triggers the query, so only do it if debugging is
            # enabled
            if logger.isEnabledFor(logging.DEBUG):
                # obviously there's a race between logging and actual delete
                # here, use with caution, compare with actual number of markers
                # cleared below before relying on it for debugging
                for stale in query:
                    logger.debug('Stale in-flight marker to clear: %s', stale)

            # delete() is not queued and goes to the DB before commit()
            cleared = query.delete()
            session.commit()
            if cleared > 0:
                logger.warn('%d stale in-flight samples cleared.', cleared)
        except SQLAlchemyError as error:
            session.rollback()
            raise PeekabooDatabaseError('Unable to clear the database of '
                                        'stale in-flight samples: %s' % error)
        finally:
            session.close()

        return cleared > 0

    def drop(self):
        """ Drop all tables of the database. """
        try:
            Base.metadata.drop_all(self.__engine)
        except SQLAlchemyError as error:
            raise PeekabooDatabaseError(
                'Unable to drop all tables of the database: %s' % error)

    def _db_schema_exists(self):
        if not self.__engine.dialect.has_table(self.__engine, '_meta'):
            return False

        session = self.__session()
        # get the first of potentially multiple metadata entries ordered by
        # descending schema version to get the newest currently configured
        # schema
        meta = session.query(PeekabooMetadata).order_by(
            PeekabooMetadata.db_schema_version.desc()).first()
        if not meta:
            return False

        schema_version = meta.db_schema_version
        session.close()
        if schema_version < DB_SCHEMA_VERSION:
            logger.info('Adding new database schema.')
            return False

        return True

    def _init_db(self):
        """
        Initializes the Peekaboo database by creating tables and
        writing meta information to the '_meta' table.
        """
        Base.metadata.create_all(self.__engine)
        meta = PeekabooMetadata()
        meta.peekaboo_version = __version__
        meta.db_schema_version = DB_SCHEMA_VERSION
        # TODO: Get Cuckoo version.
        meta.cuckoo_version = '2.0'
        session = self.__session()
        session.add(meta)
        try:
            session.commit()
        except SQLAlchemyError as error:
            session.rollback()
            raise PeekabooDatabaseError(
                'Cannot initialize the database: %s' % error)
        finally:
            session.close()
