# PeekabooAV #

[![Testsuite](https://github.com/scVENUS/PeekabooAV/actions/workflows/testsuite.yml/badge.svg)](https://github.com/scVENUS/PeekabooAV/actions/workflows/testsuite.yml)

**Peekaboo Extended Email Attachment Behavior Observation Owl**

* PeekabooAV is an Anti Virus software
* It gets email attachments from AMaViSd, checks them, uses Cuckoo for behavioral checks, and evaluates and rates fully automatic
* PeekabooAV is written in Python, multi-threaded, scalable, has a very powerful ruleset, and is easy to extend and personalize
* It is able to detect: malware by its behavior, exploitation of zero days, and targeted attacks

* We develop and work in Germany
* PeekabooAV is entirely open source
* can run 100% local and does not require any external service
* any file with any application can be scanned

If you run mail on-site, distrust security vendors and need a high level of security and secrecy
PeekabooAV is for you.

For news and announcements follow us on twitter [@peekabooAV](https://twitter.com/peekabooav).



## Getting Started ##

### Prerequisites ####

* [Python](https://www.python.org/downloads/) (3.6+ required)
* [Cuckoo 2.0](https://github.com/cuckoosandbox/cuckoo)
* [AMaViSd 2.11.0](https://www.ijs.si/software/amavisd/)
* Installer is available: [PeekabooAV-Installer](https://github.com/scVENUS/PeekabooAV-Installer)


### Installation ###

Install from PyPI into a new virtual environment:
```shell
virtualenv --python=python3 /path/to/venv
/path/to/venv/bin/pip install peekabooav
```

Or use this repository:
```shell
git clone https://github.com/scVENUS/PeekabooAV.git
virtualenv --python=python3 /path/to/venv
/path/to/venv/bin/pip install .
```

This will pull in all required packages and install them into the virtualenv.

### Configuration ###
Take a look at ``peekaboo.conf.sample`` and ``ruleset.conf.sample``.


## Running the tests ##

Runs the unit tests
```shell
/path/to/venv/bin/python tests/test.py
```


## Usage ##

Now, you can run PeekabooAV with
```shell
/path/to/venv/bin/peekaboo -c /path/to/your/peekaboo.conf
```

**Note:** If you put your PeekabooAV configuration file at
``/opt/peekaboo/etc/peekaboo.conf`` you can omit the ``-c`` option.
Also, for detailed command line options run
```shell
peekaboo --help
```

### Development Quickstart ###

Just install Peekaboo using pip like above but in editable/development mode:

```shell
/path/to/venv/bin/pip install -e .
```

Now you can run it as before but changes to the source code will take effect
without reinstallation.
See the [development documentation](docs/source/development.rst) for details.

## Contributing ##
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.


## Versioning ##

We use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/scVENUS/PeekabooAV/releases).

## Past and present Developers and Contributors ##

* **Felix Bauer** - *Security Analyst and Project Leader* - [@Jack28](https://github.com/Jack28)
* **Michael Weiser** - *Developer* - [@michaelweiser](https://github.com/michaelweiser)
* **Sebastian Deiss** - *Former Technical Lead* - [@SebastianDeiss](https://github.com/SebastianDeiss)

## License ##

This project is licensed under the GPL 3 license - see the [LICENSE.txt](LICENSE.txt) file for details.
