###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# db.py                                                                       #
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
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.engine import create_engine
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.orm.util import has_identity
from . import logger
from .ruleset import RuleResult, Result
from .util import log_exception
import threading


Base = declarative_base()


class SampleInfo(Base):
    """
    Definition of the sample_info table.

    @author: Sebastian Deiss
    """
    __tablename__ = 'sample_info'

    id = Column(Integer, primary_key=True)
    sample_sha256_hash = Column(String(64), nullable=True)
    analyses_time = Column(DateTime, nullable=False)
    result = Column(String(255), nullable=True)
    reason = Column(String(1024), nullable=True)

    def __repr__(self):
        return ("<SampleInfo(sample_sha256_hash='%s', result='%s', reason='%s', "
                "analyses_time='%s')>"
                % (self.sample_sha256_hash, self.result, self.reason,
                   self.analyses_time.strftime("%Y-%m-%d %H:%M")))


class PeekabooDBHandler(object):
    """
    The database handler of Peekaboo.

    @author: Sebastian Deiss
    """
    def __init__(self, db_url):
        """
        Initialize the Peekaboo database handler.

        :param db_url: An RFC 1738 URL that points to the database.
        """
        self.engine = create_engine(db_url)
        self.db_con = None
        self.Session = sessionmaker(bind=self.engine)
        self.lock = threading.Lock()
        try:
            self.db_con = self.engine.connect()
            if not self.db_con.dialect.has_table(self.engine, 'sample_info'):
                Base.metadata.create_all(self.engine)
                logger.debug('Created database schema')
        except Exception as e:
            log_exception(e)
            raise e

    def sample_info2db(self, sample):
        """
        Add sample information to the database.

        :param sample: The sample object to get the info from.
        """
        self.lock.acquire()
        session = self.Session()
        sample_info = SampleInfo(sample_sha256_hash=sample.sha256sum,
                                 analyses_time=datetime.strptime(sample.analyses_time, "%Y-%m-%d %H:%M"),
                                 result=sample.get_result().name,
                                 reason=sample.reason)
        session.add(sample_info)
        session.commit()
        session.close_all()
        self.lock.release()
        logger.debug('Added sample %s to the database.' % sample)

    def get_rule_result(self, sha256):
        """
        Gets the sample information from the database as a RuleResult object.

        :param sha256: The SHA-256 checksum of the sample.
        :return: Returns a RuleResult object containing the sample information.
        """
        session = self.Session()
        sample = session.query(SampleInfo).filter_by(sample_sha256_hash=sha256).first()
        if sample:
            result = RuleResult('db',
                                result=Result.from_string(sample.result),
                                reason=sample.reason,
                                further_analysis=True)
        else:
            result = RuleResult('db',
                                result=Result.unknown,
                                reason="Datei ist dem System noch nicht bekannt",
                                further_analysis=True)
        session.close_all()
        return result

    def update_sample_info(self, sample):
        """
        Update sample information.

        :param sample: The sample object containing the info to update
        """
        session = self.Session()
        query = session.query(SampleInfo).filter(SampleInfo.sample_sha256_hash == sample.sha256sum)
        query.update({'result': sample.get_result().name,
                      'reason': sample.reason})
        session.commit()
        session.close_all()
        logger.debug('Updated sample info in the database for sample %s.'
                     % sample)

    def known(self, sha256):
        """
        Check if we already know a sample with its SHA-256 hash.

        :param sha256: The SHA-256 hash to check for.
        """
        session = self.Session()
        sample = session.query(SampleInfo).filter(SampleInfo.sample_sha256_hash == sha256,
                                                  SampleInfo.result != 'inProgress').scalar()
        if sample is not None:
            return True
        return False

    def in_progress(self, sha256):
        """
        Check if a sample is in progress using it's SHA-256 hash.

        :param sha256: The SHA-256 hash to check for.
        """
        session = self.Session()
        sample = session.query(SampleInfo).filter(SampleInfo.sample_sha256_hash == sha256,
                                                  SampleInfo.result == 'inProgress').scalar()
        if sample is not None:
            return True
        return False

    def close(self):
        """
        Close the database connection.
        """
        self.db_con.close()

    def _clear_in_progress(self):
        """
        Remove all samples with the result 'inProgress'.
        """
        logger.debug("Clearing 'inProgress' samples")
        session = self.Session()
        session.query(SampleInfo).filter_by(result='inProgress').delete()
        session.commit()
        session.close_all()

    def _dump_samples(self):
        """
        Dumps all entries of the sample_info table to the console.

        @note: This method is for debugging purposes only.
        """
        session = self.Session()
        for sample_info in session.query(SampleInfo).order_by(SampleInfo.id):
            print('%s: %s, %s, %s' % (sample_info.sample_sha256_hash,
                                      sample_info.analyses_time.strftime("%Y-%m-%d %H:%M"),
                                      sample_info.result,
                                      sample_info.reason))
        session.close_all()

    def _clear_sample_info_table(self):
        """
        Deletes all entries of the sample_info_table.
        """
        session = self.Session()
        session.query(SampleInfo).delete()
        session.commit()
        session.close_all()

    def _drop_sample_info_table(self):
        """
        Drops the sample_info table.
        """
        SampleInfo.__table__.drop(bind=self.engine)
