=============
Configuration
=============

This chapter explains how to configure Peekaboo.


Setup Directories and Users
===========================
We assume that the user you run Peekaboo with is ``peekaboo``.
Its home directory will be used by Peekaboo to store transient data.
``/var/lib/peekaboo`` is a good choice for this path and the default:

.. code-block:: shell

    $ groupadd -g 150 peekaboo
    $ useradd -g 150 -u 150 -m -d /var/lib/peekaboo peekaboo

If you plan to use AMaViSd to analyse email attachments with Peekaboo,
the Peekaboo user must be a member of the ``amavis`` group in order to access
the files from an email created by AMaViSd:

.. code-block:: shell

    $ gpasswd -a peekaboo amavis

**Note**: Extending the supplementary group list of the ``peekaboo`` user is
the preferred way to achieve access to submitted files.
A separate group can be employed for that if ``peekaboo`` would otherwise gain
access to more files than necessary and the client application supports
changing file ownership to that group before submit.
Alternatively, option ``group`` of ``peekaboo.conf`` can be used to affect the
group Peekaboo changes to when started as root.

In order for clients to submit files to Peekaboo, you will need to open its unix
domain socket up for connections by users other than ``peekaboo``.
The preferred way for that is to create a separate group, make all users who
will be submitting files to Peekaboo members of that group and then configure
the Peekaboo daemon to change group ownership of its socket to that group upon
startup using option ``socket_group``. Note that the ``peekaboo`` user itself
needs to be a member of that group in order to be allowed to change ownership
of its socket to it.

.. code-block:: shell

    $ groupadd -g 151 peekaboo-clients
    $ gpasswd -a peekaboo peekaboo-clients
    $ gpasswd -a amavis peekaboo-clients

If there's only a single client, i.e. amavis, the socket owner group can also
just be its primary group, of which ``peekaboo`` may already be a member in
order to access submitted files.

It is also possible, although not recommended, to open up the socket to all
users on the system by adjusting option ``socket_mode``.

You may choose VirtualBox as hypervisor. If so, you must add the Peekaboo user to the
``vboxusers`` group.

.. code-block:: shell

    $ sudo usermod -a -G vboxusers peekaboo


Configuration File
==================
Peekaboo requires a configuration file to be supplied on startup.
If no configuration file is supplied on startup, Peekaboo will look for a file
named ``/opt/peekaboo/etc/peekaboo.conf``. For details, please run

.. code-block:: shell

    $ /opt/peekaboo/bin/peekaboo --help

You can configure Peekaboo according to the sample configuration in
``/opt/peekaboo/share/doc/peekaboo/peekaboo.conf.sample`` and save it
to ``/opt/peekaboo/etc/peekaboo.conf``.
The same directory also contains a sample ``ruleset.conf``.


Database Configuration
======================
Peekaboo supports multiple databases. We did tests with SQLite, MySQL, and PostgreSQL.
However, Peekaboo should also work with other databases. For a full list of supported
database management systems, please visit the website of the 3rd party module *SQLAlchemy*.

MySQL
-----

.. code-block:: shell

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
   
   $ sudo -u postgres psql postgres
   \password postgres

Crate User
++++++++++
   
.. code-block:: shell

    $ sudo -u postgres createuser peekaboo --encrypted --login --host=localhost --pwprompt

Create Database
+++++++++++++++

.. code-block:: shell

    $ sudo -u postgres createdb peekaboo --host=localhost --encoding=UTF-8 --owner=peekaboo


``systemd``
===========
Simply copy ``systemd/peekaboo.service`` to ``/etc/systemd/system/peekaboo.service``.
If you don't use the system's Python interpreter (``/usr/bin/python``) and have placed the configuration file
in ``/opt/peekaboo/etc/peekaboo.conf``, no changes to this file are required.

Finally, run ``systemctl daemon-reload``, so ``systemd`` recognizes Peekaboo.


Helpers & 3rd Party Applications
================================
Also, Peekaboo can run behavioural analysis of file and directories by utilizing Cuckoo sandbox for this purpose.
Further, email attachments can be supplied to Peekaboo for analysis directly from AMaViSd.

The remaining sections cover the setup of these components.

Cuckoo
------
Please refer to the Cuckoo documentation available at https://cuckoo.sh/docs/index.html.

Cortex
------

Extensive documentation on setup of Cortex is available at
https://github.com/TheHive-Project/CortexDocs.

We assume that Cortex is installed in a separate virtual machine or container
and accessible via its REST API.
The following paragraphs give a short reference how to set up Cortex for use
with Peekaboo and CAPEv2 backend analyzer.
We show ``curl`` commands for configuring Cortex via the REST API.
The same objective can be achieved interactively as well.

When starting out with a freshly installed Cortex VM or container,
it wants to initialize its database.
This is shown as a message upon first connect using a web browser
and can be triggered by pressing the respective button.
Using curl this can be triggered like so, assuming the host name is ``cortex``
and TLS is deployed:

.. code-block:: shell

   $ curl -XPOST -H 'Content-Type: application/json' https://cortex:9001/api/maintenance/migrate -d '{}'

After that a superadmin needs to be created:

.. code-block:: shell

   $ curl -XPOST -H 'Content-Type: application/json' https://cortex:9001/api/user \
      -d '{"login":"admin","name":"admin","password":secret:here,"roles":["superadmin"],"organization":"cortex"}'

There's an intentional syntax error in the previous command to replace with an
actual password.
This solves the chicken-and-egg problem of having no users in a freshly
initialized database by not requiring any authentication.
So the time window up to this step should be kept as short as possible.
From then on, the superadmin and their password can be used to access Cortex
securely.

Now an organization called e.g. ``peekaboo`` can be created, an organization
admin user created and an api key generated and retrieved for the purposes of
further configuration:

.. code-block:: shell

   $ curl -XPOST -u admin -H 'Content-Type: application/json' https://cortex:9001/api/organization \
      -d '{ "name": "peekaboo", "description": "Peekaboo organization", "status": "Active"}'
   Enter host password for user 'admin': <password configured above>
   $ curl -XPOST -u admin -H 'Content-Type: application/json' https://cortex:9001/api/user \
      -d '{ "name": "Peekaboo org Admin", "roles": ["read","analyze","orgadmin"], "organization": "peekaboo", "login": "peekaboo-admin" }'
   Enter host password for user 'admin': <password configured above>
   $ ORG_ADMIN_KEY=$(curl -s -XPOST -u admin -H 'Content-Type: application/json' \
      https://cortex:9001/api/user/peekaboo-admin/key/renew)
   Enter host password for user 'admin': <password configured above>

From now on, further curl requests can use the API key from this shell.
Beware that it becomes visible in the process arguments during execution.
So do this on a secure machine or give the user a password instead and manually
enter that.

Now we're ready to create a Peekaboo analyzer user and retrieve their API key:

.. code-block:: shell

   $ curl -XPOST -H "Authorization: Bearer $ORG_ADMIN_KEY" -H 'Content-Type: application/json' \
      https://cortex:9001/api/user -d '{ "name": "Peekaboo", "roles": ["read","analyze"], "organization": "peekaboo", "login": "peekaboo-analyze" }'
   $ curl -XPOST -H "Authorization: Bearer $ORG_ADMIN_KEY" -H 'Content-Type: application/json' \
      https://cortex:9001/api/user/peekaboo-analyze/key/renew

Place the API key in Peekaboo's ``analyzer.conf`` in the ``api_token`` option of
section ``cortex`` so that Peekaboo can authenticate requests to the API.

Finally, we can configure Cortex analyzers using curl as well.
The following is an example of configuring CAPEv2 as a Cortex analyzer:

.. code-block:: shell

   $ curl -XPOST -H "Authorization: Bearer $ORG_ADMIN_KEY" -H 'Content-Type: application/json' \
      https://cortex:9001/api/organization/analyzer/CAPE_File_Analysis_0_2 \
      -d '{"name": "CAPE_File_Analysis_0_2", "configuration": {"url": "http://cape:8000/api"}}'

This particular analyzer is not upstream as of this writing.
But the principle is the same for all analyzers.
Additional configuration options can be added as necessary.

AMaViSd
-------
First, install the ``10-ask_peekaboo`` plugin as
``/etc/amavis/conf.d/10-ask_peekaboo``.
It is available from the ``amavis`` subdirectory of the PeekabooAV installation
and has been tested with AMaViS 2.11.0.


Put the following code into ``/etc/amavis/conf.d/15-av_scanners``:

.. code-block:: perl

    @av_scanners = (
        ['Peekaboo-Analysis', \&ask_peekaboo]
    );

    1;  # ensure a defined return


A third parameter can be added for custom configuration.
This is an array which currently supports adjustment of the Peekaboo API base
URL as well as the polling interval in positions 0 and 1, respectively.
Overriding them with their default values would look like this:

.. code-block:: perl

    @av_scanners = (
        ['Peekaboo-Analysis', \&ask_peekaboo, ["http://127.0.0.1:8100", 5]]
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

Next, create an ``/etc/amavis/conf.d/50-peekaboo`` and fill it with:

.. code-block:: perl
   
   # force a fresh child for each request
   $max_requests = 1;

   # if not autodetectable or misconfigured, override hostname and domain
   $mydomain = 'peekaboo.test';
   $myhostname = 'host.peekaboo.test';

   # Optional for development if you want to receive the results of AMaViSd via email
   $notify_method = 'smtp:[127.0.0.1]:10025';
   $forward_method = 'smtp:[127.0.0.1]:10025';

Finally, restart AMaViSd

.. code-block:: shell

    systemctl restart amavis


Postfix
-------

In order to make Postifx forward emails to AMaViSd edit ``/etc/postfix/main.cf``:

.. code-block:: none
   
   $myhostname = 'host.peekaboo.test'
   $mydomain = 'peekaboo.test'
   
   content_filter=smtp-amavis:[127.0.0.1]:10024 
