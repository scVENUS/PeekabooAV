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

    sudo apt-get install python-virtualenv
    virtualenv /path/to/your/venv
    /path/to/your/venv/bin/pip install -r dev_requirements.txt


Dummy Cuckoo
============
For development and testing purposes we developed some scripts to simulate the behaviour required for us to
communicate with Cuckoo. These scripts can be found in the ``bin/`` folder of our repository.

* ``dummy_cukcoo.py``: Simulates the Cuckoo output if an analysis task is completed.
* ``dummy_cuckoo_submit.py``: Simulates the Cuckoo output when submitting a file or directory to cuckoo.


For further information about Cuckoo, please refer to the Cuckoo documentation available at
https://cuckoo.sh/docs/index.html.


Peekaboo
========
Simply

* Clone the git repository
* ``/path/to/your/venv/bin/pip install -r requirements.txt``
* ``/path/to/your/venv/bin/pip install -r dev-requirements.txt``
* Derive your own config from ``peekaboo.conf.sample`` and save it to ``peekaboo.conf``
* Compile ``chown2me`` as described in the installation chapter.
* Run Peekaboo with: ``/path/to/your/venv/bin/python peekaboo_debug.py``
* For command line options run ``/path/to/your/venv/bin/python peekaboo_debug.py --help``
