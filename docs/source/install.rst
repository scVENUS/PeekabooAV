============
Installation
============

This chapter explains how to install Peekaboo and its dependencies.
In this chapter we assume that you want to use Peekaboo's extended capabilities to perform behavioural analysis of
files and directores with Cuckoo. Further, we assume that you want to install AMaViSd to run
analysis of email attachments. Also, we assume that you use a Debian based Linux distribution.

We are going to use python virtual environments to install cuckoo and Peekaboo
together with their respective dependencies, because they might conflict with
each other when trying to install all of them in the same environment
(virtual or host).
Most notably cuckoo only supports python 2 while Peekaboo prefers python 3.


Packages
========
Install the required packages:

.. code-block:: shell

    sudo apt-get install virtualenv \
                         postfix \
                         amavisd-new \
                         libjpeg-dev \
                         zlib1g-dev \
                         libffi-dev \
                         libssl-dev \
                         build-essential \
                         python-dev \
                         python3-dev \
                         tcpdump

**Note for AMaViSd**:
Write the hosts FQDN into ``/etc/hosts``. The first line should look like

.. code-block:: none

   127.0.0.1	host.example.com host localhost

You can verify the configuration by typing ``hostname --fqdn``.
This step is important for AMaViSd.


Depending on which DBMS you choose, there are additional packages to install.
We install the software itself and library development packages using the
system package manager.
Python modules are installed into the virtual environments individually using
pip and use the installed library development packages to build.

SQLite
------

.. code-block:: shell

    $ sudo apt-get install sqlite3 libsqlite3-dev

MySQL
-----

.. code-block:: shell

    $ sudo apt-get install mysql-server mysql-client libmysqlclient-dev

PostgreSQL
----------

.. code-block:: shell

    $ sudo apt-get install postgresql libpq-dev


Cuckoo
======
Create a new python virtual environment and install cuckoo into it using pip:

.. code-block:: shell

    $ sudo virtualenv --python=python2 /opt/cuckoo
    $ sudo /opt/cuckoo/bin/pip install cuckoo

Again depending on your choice of DBMS you now need to install the necessary
python packages into the virtual environment:

SQLite
------

.. code-block:: shell

    $ sudo /opt/cuckoo/bin/pip install pysqlite

MySQL
-----

.. code-block:: shell

    $ sudo /opt/cuckoo/bin/pip install mysqlclient

PostgreSQL
----------

.. code-block:: shell

    $ sudo /opt/cuckoo/bin/pip install psycopg2

Finalization
------------

In order to test your new Cuckoo installation you should run it once:

.. code-block:: shell

    $ /opt/cuckoo/bin/cuckoo

**Note**: We're assuming these actions to be executed by the user the tools
will be running as.
If doing more than testing and development, a separate run user should be
created for Cuckoo.


Peekaboo
========

Using pip
---------

A released version of Peekaboo can be installed directly via pip as follows:

.. code-block:: shell

    $ sudo virtualenv --python=python3 /opt/peekaboo
    $ sudo /opt/peekaboo/bin/pip install peekabooav

The same steps for installing a DBMS-specific module as for Cuckoo above apply,
e.g.:

MySQL
-----

.. code-block:: shell

    $ sudo /opt/peekaboo/bin/pip install mysqlclient

Peekaboo can also be installed from the source directory which is useful in
development or when trying out unreleased versions.

Using the source code
---------------------

Start with either an unpacked tarball of the source or check it out using git:

.. code-block:: shell

    $ git clone https://github.com/scVENUS/PeekabooAV.git
    $ cd PeekabooAV

Optionally a specific release, commit or branch can be found and checkout out:

.. code-block:: shell

    $ git tag
    $ git branch
    $ git checkout v1.x.x

The below commands again create a virtual environment and install Peekaboo
together with all its dependencies into it:

.. code-block:: shell

    $ sudo virtualenv --python=python3 /opt/peekaboo
    $ sudo /opt/peekaboo/bin/pip install .

**Note**: Do not use ``./setup.py install`` for installation since there are
bugs in setuptools which make dependency resolution fail sometimes.

**Note**: If you want to install Peekaboo for your system wide Python, leave
out the virtualenv command and just run the system pip as ``root``.
Dependencies can and will be provided by distribution packages if installed
before running pip.
It will however install additional dependencies into ``/usr/local``.
This might include updates of already installed system packages and
pip will remove the old versions from the system python directories.
This can get very confusing and complicated over time, leading to unexpected
behaviour.
Again, virtual environments are recommended here.
