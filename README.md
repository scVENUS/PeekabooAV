# PeekabooAV #

**Peekaboo Extended Email Attachment Behavior Observation Owl**

* PeekabooAV is an Anti Virus software
* It gets email attachments from AMaViSd, checks them, uses Cuckoo for behavioral checks, and evaluates and rates fully automatic
* PeekabooAV is written in Python, multi-threaded, scalable, has a very powerful ruleset, and is easy to extend and personalize
* It is able to detect: malware by its behavior, exploitation of zero days, and targeted attacks

For news and announcements follow us on twitter [@peekabooAV](https://twitter.com/peekabooav).


## Getting Started ##

### Prerequisites ####

* [Python 2.7](https://www.python.org/downloads/)
* [Cuckoo 2.0](https://github.com/cuckoosandbox/cuckoo)
* [AMaViSd 2.11.0](https://www.ijs.si/software/amavisd/)


### Installation ###

Clone the repository
```shell
git clone https://github.com/scVENUS/PeekabooAV.git
```

Install dependencies
```shell
pip install -r requirements.txt
```

Compile ``chown2me``
```shell
cd bin/
make chown2me
sudo setcap cap_chown+ep chown2me
```

Install PeekabooAV
```shell
python setup.py install
```

### Configuration ###
Take a look at ``peekaboo.conf.sample`` and ``ruleset.conf.sample``.


## Running the tests ##

Runs the unit tests
```shell
python test.py 
```


## Usage ##

Now, you can run PeekabooAV with
```shell
peekaboo -c /path/to/your/peekaboo.conf
```

**Note:** If you have your PeekabooAV configuration file named ``peekaboo.conf``
and put it in the base directory of the repository you can omit the ``-c`` option.  
Also, for detailed command line options run
```shell
peekaboo --help
```

### Usage without Installation ###

You can now run PeekabooAV without installing it using the ``peekaboo_debug.py`` script.
```shell
python peekaboo_debug.py -c /path/to/your/peekaboo.conf
```

**Note:** ``peekaboo_debug.py`` provides the same command line options like ``peekaboo``.
They can be displayed by running

```shell
python peekaboo_debug.py --help
```


## Contributing ##
Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.


## Versioning ##

We use [SemVer](http://semver.org/) for versioning. For the versions available,
see the [tags on this repository](https://github.com/scVENUS/PeekabooAV/releases).

## Authors ##

* **Felix Bauer** - *Security Analyst and Project Leader* - [@Jack28](https://github.com/Jack28)
* **Sebastian Deiss** - *Technical Lead* - [@SebastianDeiss](https://github.com/SebastianDeiss)

## License ##

This project is licensed under the GPL 3 license - see the [LICENSE.txt](LICENSE.txt) file for details.
