#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# dummy_cuckoo_submit.py                                                      #
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


from random import choice
from datetime import datetime


def main():
    with open('./dummy_submit.log', 'a') as f_log:
        job_id = choice(range(0, 14))
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S,%f')[:-3]
        msg = '%s added as task with ID %d' % (timestamp, job_id)
        f_log.write(msg + '\n')
        print(msg)


if __name__ == '__main__':
    main()
