.. _development-environment:

=======================
Development Environment
=======================

This chapter describes how to setup a development environment to develop Peekaboo on your local machine.
For development, there is no need to have a working Cuckoo installation or a working mail system with AMaViSd runing.


**Note:** Again, we assume that you use a Debian based Linux distribution.


Virtualenv
==========
In order to develop Python applications you should always use virtualenv. So, you can setup virtualenv as shown next.

.. code-block:: shell

    sudo apt-get install virtualenv
    virtualenv --python=python3 /path/to/your/venv
    /path/to/your/venv/bin/pip install -r dev_requirements.txt


Dummy Cuckoo
============
For development and testing purposes we developed some scripts to simulate the behaviour required for us to
communicate with Cuckoo. These scripts can be found in the ``bin/`` folder of our repository.

* ``dummy_cukcoo.py``: Simulates the Cuckoo output if an analysis task is completed.
* ``dummy_cuckoo_submit.py``: Simulates the Cuckoo output when submitting a file or directory to cuckoo.

To develop in api mode:

* ``dummy_cuckoo_api.py``: Simulates the Cuckoo API. It listens on port ``127.0.0.1:5002``.


For further information about Cuckoo, please refer to the Cuckoo documentation available at
https://cuckoo.sh/docs/index.html.


Peekaboo
========
Simply

* Clone the git repository
* Derive your own config from ``peekaboo.conf.sample`` and save it to ``peekaboo.conf``
* Install Peekaboo in `development mode <setuptools_develop_>`_ into the virtual
  environment so that changes to the source take effect without reinstallation:
  ``/path/to/your/venv/bin/pip install -e .``
  (Option -e to pip enables development mode in setuptools.)
* Run Peekaboo with: ``/path/to/your/venv/bin/peekaboo -c peekaboo.conf``
* For command line options run ``/path/to/your/venv/bin/peekaboo --help``
* To get a fully functional development environment,
  also install the dev requirements (git-lint, sphinx, ...) like so:
  ``/path/to/your/venv/bin/pip install -r dev-requirements.txt``

Summary:

.. code-block:: shell

    $ /path/to/your/venv/bin/pip install -e .
    $ /path/to/your/venv/bin/pip install -r dev-requirements.txt

.. _setuptools_develop: https://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode

Code Quality
============

To improve and keep code quality we're using `git-lint`_.
It checks the changed lines for style and syntax issues on each commit and
supports various languages and formats.
In our case it supports python through pylint and pycodestyle as well as rst
for the documentation.

**Note**: There's various projects with "git" and "lint" in their name.
Particularly beware that "gitlint" is not the `git-lint`_ we use.

The tools themselves are already installed by the pip commands in the previous
section.
Configure and activate git-lint for your local git repo as follows:

git-lint's ``config.yaml`` needs to be adjusted so that pylint uses its default
and our local configuration.
The override by git-lint using the ``--rcfile`` option would otherwise
disable our local ``pylintrc``.

Also, all commands are changed to reference the linters by absolute path inside
the virtual environment so that it does not need to be added to the search
path which might cause confusion if there's tool overlap with the system or
other venvs.
(But of course you can also just run ``. /path/to/your/venv/bin/activate``
starting each development session and be done with it.)

.. code-block:: shell

    $ venv=/path/to/your/venv
    $ sed -i -e "s,command:  *,command: $venv/bin/," \
        -e "/--rcfile=.*\/pylintrc/d" \
        $venv/lib/python3*/site-packages/gitlint/configs/config.yaml

Finally these commands fix up and activate the pre-commit hook for `git`.

.. code-block:: shell

    $ sed -i "s,git lint,$venv/bin/git-lint," $venv/bin/pre-commit.git-lint.sh
    $ ln -sfn $venv/bin/pre-commit.git-lint.sh .git/hooks/pre-commit

**Note**: git-lint keeps a cache in ``$HOME/.git-lint/cache``.
If it should start to behave curiously, this can be deleted to get back to a
clean baseline.

git-lint will abort the commit if **any** issues are found.
Use your best judgement as to what is legitimate advise and what is nitpicking
and override with option ``--no-verify`` as required.

Finally, pylint and pycodestyle can be run on the code as a whole using the
following commands:

.. code-block:: shell

    $ /path/to/your/venv/bin/pylint peekaboo bin/*.py
    $ /path/to/your/venv/bin/pycodestyle peekaboo bin

Expect a maintainer to do this for your pull request.

As said, we have a local ``pylintrc`` which can be used to silence accepted
"issues".
Similar configuration files for other tools could potentially be added as well.

Also, local overrides particularly for pylint can be added in the code using
the ``pylint: disable=foo`` syntax per individual line or wrapping a block of
code in ``pylint: disable=foo`` and ``pylint: enable=foo`` (where ``foo`` is
the symbolic name of a warning or error).
Please do not forget to turn warnings back on and please do not pollute the
code with loads of these overrides.

.. _git-lint: https://pypi.org/project/git-lint/

Testing PyPI Interaction
========================

We test PyPI interaction for unreleased versions, e.g. when testing the
installer, using `devpi`_.

Quick start: Install devpi, start server, configure devpi client, create user,
log in, create overlay, configure client to use overlay by default, create
source distribution, upload and test installation using pip:

.. code-block:: shell

    $ /path/to/your/venv/bin/pip install -U devpi-web devpi-client
    $ /path/to/your/venv/bin/devpi-server --start --init
    $ /path/to/your/venv/bin/devpi use http://localhost:3141
    $ /path/to/your/venv/bin/devpi user -c testuser password=123
    $ /path/to/your/venv/bin/devpi login testuser --password=123
    $ /path/to/your/venv/bin/devpi index -c dev bases=root/pypi
    $ /path/to/your/venv/bin/devpi use testuser/dev
    $ cd PeekabooAV
    $ ./setup.py sdist
    $ /path/to/your/venv/bin/devpi upload
    $ t=$(mktemp -d)
    $ virtualenv --python=python3 "$t"
    $ PIP_INDEX_URL=http://localhost:3141/testuser/dev/+simple/ "$t"/bin/pip install peekabooav
    $ rm -rf "$t"

Overriding the index to use for testing using ``PIP_INDEX_URL`` can also be
used with other tools such as Ansible or the Peekaboo Installer.

.. _devpi: https://pypi.org/project/devpi/
