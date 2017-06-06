# PeekabooAV #

Peekaboo Extended Email Attachment Behavior Observation Owl

* PeekabooAV is an Anti Virus software
* It gets email attachments from AMaViSd, checks them, uses Cuckoo for behavioral checks, and evaluates and rates fully automatic
* PeekabooAV is written in Python, multi-threaded, scalable, has a very powerful ruleset, and is easy to extend and personalize
* It is able to detect: malware by its behavior, exploitation of zero days, and targeted attacks

**The main developers are:**

* Felix Bauer
* Sebastian Deiss
* Christoph Herrmann

For news and announcements follow us on twitter [@peekabooAV](https://twitter.com/peekabooav).


## Requirements ##

* [Python 2.7](https://www.python.org/downloads/)
* [Cuckoo 2.0](https://github.com/cuckoosandbox/cuckoo)
* Our patched version of AMaViSd 2.11.0


## Installation ##

### Get PeekabooAV ###
Clone the repository.

```shell
git clone https://github.com/scVENUS/PeekabooAV.git
```

### Install Dependencies ###
```shell
pip install -r requirements.txt
```

#### Compile ``chown2me`` ####
```shell
cd bin/
make chown2me
sudo setcap cap_chown+ep chown2me
```

### Install PeekabooAV ###
```shell
python setup.py install
```

### Advanced Installations ###
For a more advanced installation, please refer to our documentation located in the ``docs`` folder.


## Configuration ##
Take a look at ``peekaboo.conf.sample``.


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
You can run PeekabooAV without installing it using the ``peekaboo_debug.py`` script.
```shell
python peekaboo_debug.py -c /path/to/your/peekaboo.conf
```

**Note:** ``peekaboo_debug.py`` provides the same command line options like ``peekaboo``.
They can be displayed by running

```shell
python peekaboo_debug.py --help
```
