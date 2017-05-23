============
Installation
============

This chapter explains how to install Peekaboo and its dependencies.
In this chapter we assume that you want to use Peekaboo's extended capabilities to perform behavioural analysis of
files and directores with Cuckoo. Further, we assume that you want to install AMaViSd and our patch for it to run
analysis of email attachments. Also, we assume that you use a Debian based Linux distribution.


Packages
========
Install the required packages:

.. code-block:: shell

    sudo apt-get install python-virtualenv \
                         python-pip \
                         postfix \
                         amavisd-new \
                         libjpeg-dev \
                         zlib1g-dev \
                         libffi-dev \
                         libssl-dev \
                         build-essential \
                         python-dev \
                         tcpdump

**Note for AMaViSd**:
Write the hosts FQDN into ``/etc/hosts``. The first line should look like

.. code-block:: none

   127.0.0.1	host.example.com host localhost

You can verify the configuration by typing ``hostname --fqdn``.
This step is important for AMaViSd.


Depending on which DBMS you choose, there are additional packages to install.

SQLite
------

    $ sudo apt-get install python-sqlite sqlite3

MySQL
-----

    $ sudo apt-get install mysql-server mysql-client python-mysqldb

PostgreSQL
----------

    $ sudo apt-get install postgresql python-psycopg2


Cuckoo
======
Download Cuckoo 2.0.0 from https://github.com/cuckoosandbox/cuckoo/archive/2.0.0.tar.gz

.. code-block:: shell

    mkdir /opt/cuckoo
    tar xvfz 2.0.0.tar.gz -C /opt/cuckoo

Obtain Cuckoo's monitoring binaries 

    $ python stuff/monitor.py

Now, install cuckoo

    $ cd /opt/cuckoo/cuckoo-2.0.0/
    $ python setup.py install

In order to test your new Cuckoo installation you should run it once

    $ cuckoo


Peekaboo
========

Get Peekaboo
------------

    $ git clone https://github.com/scVENUS/PeekabooAV.git


Install Dependencies
--------------------

    $ pip install -r requirements.txt

Install
-------

    $ python setup.py install

**Note**: If you want to install Peekaboo for your system wide Python, you must run this command as ``root``.
