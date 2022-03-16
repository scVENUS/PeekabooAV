#!/usr/bin/env python

###############################################################################
#                                                                             #
# Peekaboo Extended Email Attachment Behavior Observation Owl                 #
#                                                                             #
# setup.py                                                                    #
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


from codecs import open
from os import path
from sys import path as pythonpath
from setuptools import setup, find_packages

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

install_requires = []
for req in all_reqs:
    # for git repo references, extract the egg/package name from the end and
    # prepend it with @ as per pip Github issue 3939
    if 'git+' in req:
        egg = req.split('=')[-1]
        req = "%s @ %s" % (egg, req)

    install_requires.append(req.strip())

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
      'Programming Language :: Python :: 3',
      'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
      'Natural Language :: English',
      'Natural Language :: German',
      'Topic :: Communications :: Email :: Filters',
    ],
    keywords='Cuckoo, Amavis',
    packages=find_packages(exclude=['docs', 'tests*']),
    include_package_data=True,
    # package_files augments MANIFEST.in in what is packaged into a
    # distribution. Files to add must be inside a package. Thus files in the
    # root of our source directory cannot be packaged with this. Files inside
    # packages will stay there, totally obscured to the user. Meant for default
    # configuration or other package-internal data.
    #  package_files=[...],
    #
    # data_files is another way to augment what is installed from the
    # distribution. Allows paths outside packages for both sources and targets.
    # Absolute paths are strongly discouraged because they exhibit confusing if
    # not downright broken behaviour. Relative paths are added to the
    # distribution and then installed into
    # site-packages/<package>-<ver>.egg/<relative path> (setup.py) or <python
    # prefix>/<relative path> (pip). The latter works well with venvs and
    # distribution-provided pip (e.g. /usr/local/<relative path>).
    # We go this route for providing sample files because using setup.py
    # directly is discouraged anyway and "only" tucks the files away in the egg
    # directory, providing the most consistent option.
    data_files=[
        ("share/doc/peekaboo", [
            "README.md",
            "CHANGELOG.md",
            "peekaboo.conf.sample",
            "ruleset.conf.sample",
            "analyzers.conf.sample",
        ]),
        ("share/doc/peekaboo/systemd", [
            "systemd/peekaboo.service",
        ]),
        ("share/doc/peekaboo/amavis", [
            "amavis/10-ask_peekaboo",
        ]),
    ],
    # overriding the whole install_data command allows for arbitrary
    # installation mechanics but does not solve the problem of adding files to
    # a binary distribution (e.g. wheel, which pip uses internally always) in
    # such a way that they will later be put at the correct location. Thus they
    # would go around pip entirely, be missing from any actual wheel
    # distribution package, pollute the system directly and not be removed upon
    # uninstall or upgrade.
    #  cmdclass={
    #      'install_data': OffsetDataInstall,
    #  },
    author=__author__,
    python_requires='>=3.6',
    install_requires=install_requires,
    author_email='felix.bauer@atos.net',
    entry_points={
        'console_scripts': [
            'peekaboo = peekaboo.daemon:run',
            'peekaboo-util = peekaboo.cli:main',
        ],
    }
)
