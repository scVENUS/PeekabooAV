#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# setup.py                                                                    #
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


from setuptools import setup, find_packages
from codecs import open
from os import path, system
from sys import path as pythonpath

# Add peekaboo to PYTHONPATH
pythonpath.append(path.dirname(path.dirname(path.abspath(__file__))))
from peekaboo import __version__, __author__, __license__, __description__

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

# get the dependencies and installs
with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    all_reqs = f.read().split('\n')

install_requires = [x.strip() for x in all_reqs if 'git+' not in x]
dependency_links = [x.strip().replace('git+', '')
                    for x in all_reqs if 'git+' not in x]

setup(
    name='PeekabooAV',
    version=__version__,
    description=__description__,
    long_description=long_description,
    url='https://github.com/scVENUS/PeekabooAV.git',
    download_url='https://github.com/scVENUS/PeekabooAV/archive/master.zip',
    license=__license__,
    classifiers=[
      'Development Status :: 4 - Beta',
      'Operating System :: POSIX',
      'Programming Language :: Python',
      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 3',
      'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
      'Natural Language :: English',
      'Natural Language :: German',
      'Topic :: Communications :: Email :: Filters',
    ],
    keywords='Cuckoo, Amavis',
    packages=find_packages(exclude=['docs', 'tests*']),
    include_package_data=True,
    author=__author__,
    install_requires=install_requires,
    dependency_links=dependency_links,
    author_email='felix.bauer@atos.net, sebastian.deiss@atos.net',
    entry_points={
        'console_scripts': [
            'peekaboo = peekaboo.daemon:run',
        ],
    }
)
