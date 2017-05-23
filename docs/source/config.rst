=============
Configuration
=============

This chapter explains how to configure Peekaboo.


Setup Directories and Users
===========================
We assume that the user you run Peekaboo with is ``peekaboo``.
First, create a directory for Peekaboo and its components

.. code-block:: shell

   sudo adduser peekaboo
   usermod -a -G amavis peekaboo
   sudo -u peekaboo mkdir -p /opt/peekaboo/bin

If you plan to use AMaViSd to analyse email attachments with Peekaboo,
the Peekaboo user must be a member of the ``amavis`` group in order to access
the files from an email created by AMaViSd.

You may choose VirtualBox as hypervisor. If so, you must add the Peekaboo user to the
``vboxusers`` group.

    $ sudo usermod -a -G vboxusers peekaboo


Virtualenv
==========

You may run Peekaboo in a virtualenv. The setup is done by typing the following command:

.. code-block:: shell

   sudo -u peekaboo mkdir /opt/peekaboo/virtualenv
   sudo -u peekaboo virtualenv /opt/peekaboo/virtualenv


Configuration File
==================
Peekaboo requires a configuration file to be supplied on startup.
If no configuration file is supplied on startup, Peekaboo will look for a file
named ``peekaboo.conf`` in your current working directory. For details, please run

    $ peekaboo --help

You can configure Peekaboo according to the sample configuration in
``peekaboo.conf.sample`` and save it to ``/opt/peekaboo/peekaboo.conf``.


Database Configuration
======================
Peekaboo supports multiple databases. We did tests with SQLite, MySQL, and PostgreSQL.
However, Peekaboo should also work with other databases. For a full list of supported
database management systems, please visit the website of the 3rd party module *SQLAlchemy*.

MySQL
-----

    $ mysql -u root -p

.. code-block:: sql
   
   mysql> CREATE USER 'peekaboo'@localhost IDENTIFIED BY 'password';
   mysql> CREATE DATABASE peekaboo;
   mysql> GRANT ALL PRIVILEGES ON peekaboo.* TO 'peekaboo'@localhost;
   mysql> FLUSH PRIVILEGES;
   mysql> exit


PostgreSQL
----------

.. code-block:: shell
   
   sudo -u postgres psql postgres
   \password postgres

Crate User
++++++++++
   
    $ sudo -u postgres createuser peekaboo --encrypted --login --host=localhost --pwprompt

Create Database
+++++++++++++++

    $ sudo -u postgres createdb peekaboo --host=localhost --encoding=UTF-8 --owner=peekaboo


``systemd``
===========
Simply copy ``systemd/peekaboo.service`` to ``/etc/systemd/system/peekaboo.service``.
If you don't use the systems Python interpreter (``/usr/bin/python``) and have placed the configuration file
in ``/opt/peekaboo/peekaboo.conf``, no changes to this file are reuired.

Finally, run ``systemctl daemon-reload``, so ``systemd`` recognizes Peekaboo.


Helpers & 3rd Party Applications
================================
Peekaboo requires a little tool called ``chwon2me`` in order to change the ownership of files and directories
to be analyed by Peekaboo.
Also, Peekaboo can run behavioural analysis of file and directories by utilizing Cuckoo sandbox for this purpose.
Further, email attachments can be supplied to Peekaboo for analysis using our patched version of AMaViSd.

The remaining sections cover the setup of these components.

Compile ``chown2me``
--------------------

.. code-block:: shell

   cd bin/
   make chown2me
   cp chown2me /opt/peekaboo/bin
   sudo setcap cap_chown+ep /opt/peekaboo/bin/chown2me
   chown peekaboo:amavis /opt/peekaboo/bin/chown2me

Cuckoo
------
Please refer to the Cuckoo documentation available at https://cuckoo.sh/docs/index.html.

AMaViSd
-------
First, replace your AMaViSd with our patched version of AMaViSd.

Now, edit ``/etc/amavis/amavis.conf``:

.. code-block:: none
   
   $mydomain = 'peekaboo.test';
   $myhostname = 'host.peekaboo.test';
   
   # Optional for development if you want to receive the results of AMaViSd via email
   $notify_method = 'smtp:[127.0.0.1]:10025';
   $forward_method = 'smtp:[127.0.0.1]:10025'; 


Put the following code into ``/etc/amavis/conf.d/15-av_scanners``:

.. code-block:: none
   
   ['Peekaboo',
   \&ask_daemon, ["{}\n", "/opt/peekaboo/peekaboo.sock"],
   qr/wurde als "(unknown|checked|good|ignored)" eingestuft/m,
   qr/wurde als "bad" eingestuft/m ],


and for mail notifications for the user ``peekaboo`` add this line to
``/etc/amavis/conf.d/25-amavis_helpers``:

.. code-block:: none
   
   $virus_admin = 'peekaboo';

Let AMaViSd use unique directories for temporary files. This configuration is mandatory for Peekaboo.
So, edit ``/etc/amavis/conf.d/50-user``:

.. code-block:: none
   
   $max_requests = 1;


Postfix
-------

In order to make Postifx forward emails to AMaViSd edit ``/etc/postfix/main.cf``:

.. code-block:: none
   
   $myhostname = 'host.peekaboo.test'
   $mydomain = 'peekaboo.test'
   
   content_filter=smtp-amavis:[127.0.0.1]:10024 
