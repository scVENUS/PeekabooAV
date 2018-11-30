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
from sqlalchemy.exc import SQLAlchemyError
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
    __tablename__ = 'analysis_result_v3'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)

    def __str__(self):
        return '<AnalysisResult(name="%s")>' % self.name

    __repr__ = __str__


class SampleInfo(Base):
    """
    Definition of the sample_info table.

    @author: Sebastian Deiss
    """
    __tablename__ = 'sample_info_v3'

    id = Column(Integer, primary_key=True)
    sha256sum = Column(String(64), nullable=False)
    file_extension = Column(String(16), nullable=True)
    result_id = Column(Integer, ForeignKey('analysis_result_v3.id'),
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
    __tablename__ = 'analysis_jobs_v3'

    id = Column(Integer, primary_key=True)
    job_hash = Column(String(255), nullable=False)
    cuckoo_job_id = Column(Integer, nullable=False)
    filename = Column(String(255), nullable=False)
    analyses_time = Column(DateTime, nullable=False)
    sample_id = Column(Integer, ForeignKey('sample_info_v3.id'),
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
    def __init__(self, db_url):
        """
        Initialize the Peekaboo database handler.

        :param db_url: An RFC 1738 URL that points to the database.
        """
        self.db_schema_version = 3
        self.__engine = create_engine(db_url, pool_recycle=1)
        session_factory = sessionmaker(bind=self.__engine)
        self.__Session = scoped_session(session_factory)
        self.__lock = threading.RLock()
        if not self._db_schema_exists():
            self._init_db()
            logger.debug('Database schema created.')
        else:
            self.clear_in_progress()

    def analysis2db(self, sample):
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
            # NOTE: We cannot determine if a known sample is inProgress again.
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
                    result=analysis_result
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

    def analysis_update(self, sample):
        """
        Update an analysis task in the database.
        This method is called if a sample object was processed by Cuckoo and therefore
        has a Cuckoo job ID, which we want to store in the database.

        :param sample: The sample object containing the info to update.
        """
        with self.__lock:
            session = self.__Session()
            analysis = self.__get(
                session,
                AnalysisJournal,
                job_hash=sample.get_job_hash(),
                filename=sample.get_filename()
            )
            if analysis:
                analysis.cuckoo_job_id = sample.job_id
                session.add(analysis)
                try:
                    session.commit()
                except SQLAlchemyError as e:
                    session.rollback()
                    raise PeekabooDatabaseError(
                        'Failed to update analysis task in the database: %s' % e
                    )
                finally:
                    session.close()

    def sample_info_update(self, sample):
        """
        Update sample information.

        :param sample: The sample object containing the info to update.
        """
        with self.__lock:
            session = self.__Session()
            sample_info = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )
            if sample_info is not None:
                sample_info.result = PeekabooDatabase.__get_or_create(
                    session,
                    AnalysisResult,
                    name=sample.get_result().name
                )
                sample_info.reason = sample.reason
                try:
                    session.commit()
                    logger.debug(
                        'Updated sample info in the database for sample %s.' % sample
                    )
                except SQLAlchemyError as e:
                    session.rollback()
                    raise PeekabooDatabaseError(
                        'Failed to update info for sample %s in the database: %s'
                        % (sample, e)
                    )
                finally:
                    session.close()
            else:
                raise PeekabooDatabaseError(
                    'No info found in the database for sample %s' % sample
                )

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
                if sample_info.result.name != 'inProgress':
                    is_known = True
            session.close()
            return is_known

    def in_progress(self, sample):
        """
        Check if a sample is in progress using its SHA-256 hash.

        :param sample: The Sample object to check.
        """
        with self.__lock:
            is_in_progress = False
            session = self.__Session()
            sample_info = PeekabooDatabase.__get(
                session,
                SampleInfo,
                sha256sum=sample.sha256sum,
                file_extension=sample.file_extension
            )
            if sample_info is not None:
                if sample_info.result.name == 'inProgress':
                    is_in_progress = True
            session.close()
            return is_in_progress

    def clear_in_progress(self):
        """ Remove all samples with the result 'inProgress'. """
        session = self.__Session()
        in_progress = PeekabooDatabase.__get(
            session,
            AnalysisResult,
            name='inProgress'
        )
        in_progress_samples = session.query(SampleInfo).filter_by(
            result=in_progress
        ).all()
        for in_progress_sample in in_progress_samples:
            session.query(AnalysisJournal).filter_by(
                sample=in_progress_sample
            ).delete()
        try:
            session.commit()
            logger.debug('Cleared the database from "inProgress" entries.')
        except SQLAlchemyError as e:
            session.rollback()
            raise PeekabooDatabaseError(
                'Unable to clear the database from "inProgress" entries: %s' % e
            )
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
            if meta.db_schema_version < self.db_schema_version:
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
            AnalysisResult(name='inProgress'),
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
