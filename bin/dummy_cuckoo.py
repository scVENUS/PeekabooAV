#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# dummy_cuckoo.py                                                             #
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


from time import sleep
from sys import stderr
from datetime import datetime


def main():
    job_id = 0
    f_log = open('./dummy_cuckoo.log', 'a')
    while True:
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        msg = '%s [lib.cuckoo.core.scheduler] INFO: Task #%d: reports generation completed ...\n' % (timestamp, job_id)
        f_log.write(msg)
        stderr.write(msg)
        sleep(1)
        # gcd(p, q) == 1
        # m = (p * q) - 1
        # n = (n + 5) % m
        job_id = (job_id + 5) % 14
        f_log.flush()
    f_log.close()


if __name__ == '__main__':
    main()
