=============
Configuration
=============

This chapter explains how to configure Peekaboo.


Setup Directories and Users
===========================
We assume that the user you run Peekaboo with is ``peekaboo``.
First, create a directory for Peekaboo and its components

.. code-block:: shell

    groupadd -g 150 peekaboo
    useradd -g 150 -u 150 -m -d /opt/peekaboo peekaboo
    gpasswd -a amavis peekaboo
    gpasswd -a peekaboo amavis

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
First, replace your AMaViSd with our patched version of AMaViSd. To do so, download the AMaViSd 2.11.0 source code
and extract ``amavisd.conf-default`` and ``amavisd``.

.. code-block:: shell

    curl https://www.ijs.si/software/amavisd/amavisd-new-2.11.0.tar.xz -o amavisd-new-2.11.0.tar.xz
    tar xvf amavisd-new-2.11.0.tar.xz  amavisd-new-2.11.0/amavisd.conf-default
    tar xvf amavisd-new-2.11.0.tar.xz  amavisd-new-2.11.0/amavisd

Now, you can apply our patch.

.. code-block:: shell

    cd amavisd-new-2.11.0/
    patch -p4 < ../peekaboo-amavisd.patch
    patch -p1 < ../debian-find_config_files.patch
    mv amavisd /usr/sbin/amavisd-new


Next, edit ``/etc/amavis/amavis.conf``:

.. code-block:: perl
   
   $mydomain = 'peekaboo.test';
   $myhostname = 'host.peekaboo.test';
   
   # Optional for development if you want to receive the results of AMaViSd via email
   $notify_method = 'smtp:[127.0.0.1]:10025';
   $forward_method = 'smtp:[127.0.0.1]:10025'; 


Put the following code into ``/etc/amavis/conf.d/15-av_scanners``:

.. code-block:: perl

    @av_scanners = (
        ['Peekaboo-Analysis',
        \&ask_daemon, ["{}\n", "/var/lib/peekaboo/peekaboo.sock"],
        qr/wurde als "(unknown|checked|good|ignored)" eingestuft/m,
        qr/wurde als "bad" eingestuft/m ],
    );

    1;  # ensure a defined return


Now change ``/etc/amavis/conf.d/15-content_filter_mode`` to:

.. code-block:: perl

    @bypass_virus_checks_maps = (
        \%bypass_virus_checks, \@bypass_virus_checks_acl, \$bypass_virus_checks_re);


and for mail notifications for the user ``peekaboo`` add this line to

``/etc/amavis/conf.d/25-amavis_helpers``:

.. code-block:: perl
   
   $virus_admin = 'peekaboo';

Let AMaViSd use unique directories for temporary files. This configuration is mandatory for Peekaboo.
So, edit ``/etc/amavis/conf.d/50-user``:

.. code-block:: perl
   
   $max_requests = 1;
   $enable_dump_info  = 1;       # set to 1 to enable dump_info feature
   $dump_info_tempdir = '/tmp';  # base directory where dump_info() will put its stuff


Postfix
-------

In order to make Postifx forward emails to AMaViSd edit ``/etc/postfix/main.cf``:

.. code-block:: none
   
   $myhostname = 'host.peekaboo.test'
   $mydomain = 'peekaboo.test'
   
   content_filter=smtp-amavis:[127.0.0.1]:10024 
