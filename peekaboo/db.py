###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# db.py                                                                       #
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


from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, relationship
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from peekaboo import __version__
from peekaboo.ruleset import Result, RuleResult
from peekaboo.exceptions import PeekabooDatabaseError
import threading
import logging


logger = logging.getLogger(__name__)
Base = declarative_base()


#
# Database schema definition.
##############################################################################


class PeekabooMetadata(Base):
    """
    Definition of the _meta table for Peekaboo.

    @author: Sebastian Deiss
    """
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


class AnalysisResult(Base):
    """
    Definition of the analysis_result table.

    @author: Sebastian Deiss
    """
    __tablename__ = 'analysis_result_v4'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)

    def __str__(self):
        return '<AnalysisResult(name="%s")>' % self.name

    __repr__ = __str__


class InFlightSample(Base):
    """
    Table tracking whether a specific sample is currently being analysed and by
    which Peekaboo instance.
    """
    __tablename__ = 'in_flight_samples_v4'

    sha256sum = Column(String(64), primary_key=True)
    instance_id = Column(Integer, nullable=False)


class SampleInfo(Base):
    """
    Definition of the sample_info table.

    @author: Sebastian Deiss
    """
    __tablename__ = 'sample_info_v4'

    id = Column(Integer, primary_key=True)
    sha256sum = Column(String(64), nullable=False)
    file_extension = Column(String(16), nullable=True)
    result_id = Column(Integer, ForeignKey('analysis_result_v4.id'),
                       nullable=False)
    result = relationship("AnalysisResult")
    reason = Column(Text, nullable=True)

    def set_result(self, result):
        self.__result = result

    def get_result(self):
        return self.__result

    def __str__(self):
        return ('<SampleInfo(sample_sha256_hash="%s", file_extension="%s", '
                'reason="%s")>'
                % (self.sha256sum,
                   self.file_extension,
                   self.reason))

    __repr__ = __str__


class AnalysisJournal(Base):
    """
    Definition of the analysis_jobs table.

    @author: Sebastian Deiss
    """
    __tablename__ = 'analysis_jobs_v4'

    id = Column(Integer, primary_key=True)
    job_hash = Column(String(255), nullable=False)
    cuckoo_job_id = Column(Integer, nullable=False)
    filename = Column(String(255), nullable=False)
    analyses_time = Column(DateTime, nullable=False)
    sample_id = Column(Integer, ForeignKey('sample_info_v4.id'),
                       nullable=False)
    sample = relationship('SampleInfo')

    def __str__(self):
        return (
            '<AnalysisJournal(job_hash="%s", cuckoo_job_id="%s", filename="%s", analysis_time="%s")>'
            % (self.job_hash,
               self.cuckoo_job_id,
               self.filename,
               self.analyses_time.strftime("%Y%m%dT%H%M%S"))
        )

    __repr__ = __str__


#
# End of database schema definition.
##############################################################################


class PeekabooDatabase(object):
    """
    Peekaboo's database.

    @author: Sebastian Deiss
    """
    def __init__(self, db_url, instance_id=0):
        """
        Initialize the Peekaboo database handler.

        :param db_url: An RFC 1738 URL that points to the database.
        :param instance_id: A positive, unique ID differentiating this Peekaboo
                            instance from any other instance using the same
                            database for concurrency coordination. Value of 0
                            means that we're alone and have no other instances
                            to worry about.
        """
        self.db_schema_version = 4
        self.__engine = create_engine(db_url, pool_recycle=1)
        session_factory = sessionmaker(bind=self.__engine)
        self.__Session = scoped_session(session_factory)
        self.__lock = threading.RLock()
        self.instance_id = instance_id
        if not self._db_schema_exists():
            self._init_db()
            logger.debug('Database schema created.')
        else:
            self.clear_in_flight_samples()

    def analysis_save(self, sample):
        """
        Save an analysis task to the analysis journal in the database.

        :param sample: The sample object for this analysis task.
        """
        with self.__lock:
            session = self.__Session()
            analysis = AnalysisJournal()
            analysis.job_hash = sample.get_job_hash()
            analysis.cuckoo_job_id = sample.job_id
            analysis.filename = sample.get_filename()
            analysis.analyses_time = datetime.strptime(sample.analyses_time,
                                                       "%Y%m%dT%H%M%S")
            analysis_result = PeekabooDatabase.__get_or_create(
                session,
                AnalysisResult,
                name=sample.get_result().name
            )
            s = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension,
            )
            if s is None:
                s = PeekabooDatabase.__create(
                    SampleInfo,
                    sha256sum=sample.sha256sum,
                    file_extension=sample.file_extension,
                    result=analysis_result,
                    reason=sample.reason
                )
            analysis.sample = s
            session.add(analysis)
            try:
                session.commit()
            except SQLAlchemyError as e:
                session.rollback()
                raise PeekabooDatabaseError(
                    'Failed to add analysis task to the database: %s' % e
                )
            finally:
                session.close()

    def sample_info_exists(self, sample):
        """
        Check if a log for a given sample exists.

        :param sample: The Sample object to check.
        """
        with self.__lock:
            return self.__exists(
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )

    def sample_info_fetch(self, sample):
        """
        Fetch information stored in the database about a given sample object.

        :param sample: The sample object of which the information shall be fetched from the database.
        :return: A SampleInfo object containing the information stored in teh database about the sample.
        """
        with self.__lock:
            session = self.__Session()
            sample_info = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )
            if sample_info:
                sample_info.set_result(Result.from_string(sample_info.result.name))
            session.close()
        return sample_info

    def fetch_rule_result(self, sample):
        """
        Gets the sample information from the database as a RuleResult object.

        :param sample: The Sample object to get the rule result from.
        :return: Returns a RuleResult object containing the sample information.
        """
        with self.__lock:
            session = self.__Session()
            sample_info = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )
            if sample_info:
                result = RuleResult(
                    'db',
                    result=Result.from_string(sample_info.result.name),
                    reason=sample_info.reason,
                    further_analysis=True
                )
            else:
                result = RuleResult(
                    'db',
                    result=Result.unknown,
                    reason="Datei ist dem System noch nicht bekannt",
                    further_analysis=True
                )
            session.close()
        return result

    def known(self, sample):
        """
        Check if we already have a sample in the database by its SHA-256 hash.

        :param sample: The Sample object to check.
        """
        with self.__lock:
            is_known = False
            session = self.__Session()
            sample_info = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )
            if sample_info is not None:
                is_known = True
            session.close()
            return is_known

    def mark_sample_in_flight(self, sample, instance_id=None):
        """
        Mark a sample as in flight, i.e. being worked on by an instance.

        :param sample: The sample to mark as in flight.
        :param instance_id: (optionally) The ID of the instance that is
                            handling this sample. Default: Us.
        """
        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if instance_id == 0:
            return True

        session = self.__Session()

        # try to mark this sample as in flight in an atomic insert operation
        sha256sum = sample.sha256sum
        session.add(InFlightSample(sha256sum=sha256sum,
                                   instance_id=instance_id))

        locked = False
        try:
            session.commit()
            locked = True
            logger.debug('Marked sample %s as in flight' % sha256sum)
        # duplicate primary key == entry already exists
        except IntegrityError as e:
            session.rollback()
            logger.debug('Sample %s is already in flight on another instance' %
                         sha256sum)
        except SQLAlchemyError as e:
            session.rollback()
            raise PeekabooDatabaseError('Unable to mark sample as in flight' %
                                        e)
        finally:
            session.close()

        return locked

    def clear_sample_in_flight(self, sample, instance_id=None):
        """
        Clear the mark that a sample is being processed by an instance.

        :param sample: The sample to clear from in-flight list.
        :param instance_id: (optionally) The ID of the instance that is
                            handling this sample. Default: Us.
        """
        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples in the database
        if instance_id == 0:
            return

        session = self.__Session()

        # clear in-flight marker from database
        sha256sum = sample.sha256sum
        cleared = session.query(InFlightSample).filter(
            InFlightSample.sha256sum == sha256sum).filter(
                InFlightSample.instance_id == instance_id).delete()

        try:
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            raise PeekabooDatabaseError('Unable to clear in-flight status of '
                                        'sample: %s' % e)
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

        logger.debug('Cleared sample %s from in-flight list' % sha256sum)

    def clear_in_flight_samples(self, instance_id=None):
        """
        Clear all in-flight markers left over by previous runs or other
        instances by removing them from the lock table.

        @instance_id: Clear our own (None), another instance's (positive
                      integer), all instances' (negative integer) locks or do
                      nothing (0).
        """
        # use our own instance id if none is given
        if instance_id is None:
            instance_id = self.instance_id

        # an instance id of 0 denotes that we're alone and don't need to track
        # in-flight samples
        if instance_id == 0:
            return

        session = self.__Session()

        if instance_id < 0:
            # delete all locks
            session.query(InFlightSample).delete()
            logger.debug('Clearing database of all in-flight samples.')
        else:
            # delete only the locks of a specific instance
            session.query(InFlightSample).filter(
                InFlightSample.instance_id == instance_id).delete()
            logger.debug('Clearing database of all in-flight samples of '
                         'instance %d.' % instance_id)

        try:
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            raise PeekabooDatabaseError('Unable to clear the database of '
                                        'in-flight samples: %s' % e)
        finally:
            session.close()

    def drop(self):
        """ Drop all tables of the database. """
        try:
            Base.metadata.drop_all(self.__engine)
        except SQLAlchemyError as e:
            raise PeekabooDatabaseError(
                'Unable to drop all tables of the database: %s' % e
            )

    def _db_schema_exists(self):
        if not self.__engine.dialect.has_table(self.__engine, '_meta'):
            return False
        else:
            session = self.__Session()
            meta = session.query(PeekabooMetadata)[-1]
            schema_version = meta.db_schema_version
            session.close()
            if schema_version < self.db_schema_version:
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
        meta.db_schema_version = self.db_schema_version
        # TODO: Get Cuckoo version.
        meta.cuckoo_version = '2.0'
        session = self.__Session()
        session.add(meta)
        '''
        session.add_all([
            AnalysisResult(name='unchecked'),
            AnalysisResult(name='unknown'),
            AnalysisResult(name='ignored'),
            AnalysisResult(name='checked'),
            AnalysisResult(name='good'),
            AnalysisResult(name='bad'),
        ])
        '''
        try:
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            raise PeekabooDatabaseError(
                'Cannot initialize the database: %s' % e
            )
        finally:
            session.close()

    def __exists(self, model, **kwargs):
        """
        Check whether an ORM instance exists.

        :param session: An SQLAlchemy session object.
        :param model: The model to query.
        :return: True if the ORM instance exists otherwise False.
        """
        session = self.__Session()
        instance = PeekabooDatabase.__get(session, model, **kwargs)
        session.close()
        if instance is not None:
            return True
        return False

    @staticmethod
    def __get_or_create(session, model, **kwargs):
        """
        Get an ORM instance or create it if does not exist.

        :param session: An SQLAlchemy session object.
        :param model: The model to query.
        :return: A row instance.
        """
        instance = PeekabooDatabase.__get(session, model, **kwargs)
        return instance or model(**kwargs)

    @staticmethod
    def __get(session, model, **kwargs):
        """
        Get an ORM instance.

        :param session: An SQLAlchemy session object.
        :param model: The model to query.
        :return: An ORM instance or None.
        """
        return session.query(model).filter_by(**kwargs).first()

    @staticmethod
    def __create(model, **kwargs):
        """
        Create an ORM instance.

        :param model: The model to create.
        :return: An ORM instance of the given model.
        """
        return model(**kwargs)

    def __del__(self):
        self.__engine.dispose()
