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

For news and announcements follow us on twitter @peekabooAV.


## Requirements ##

* [Python 2.7](https://www.python.org/downloads/)
* [Cuckoo 2.0](https://github.com/cuckoosandbox/cuckoo)
* Our patched version of AMaViSd 2.11.0


## Installation ##

### Get Peekaboo ###
Use the following commands to clone the Peekaboo repositories to your system:

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
chown cuckoo:cuckoo chown2me
```

### Configuration ###
Simply copy ``peekaboo.conf.sample`` to ``peekaboo.conf`` and edit it to fit your requirements.

### Startup ###
Now, you can run Peekaboo with
```shell
python peekaboo_debug.py -c /path/to/your/peekaboo.conf
```

**Note:** If you put your ``peekaboo.conf`` in the base directory
of the repository you can ommit the ``-c`` option.
Also, for detailed command line options run
```shell
python peekaboo_debug.py --help
```

### Advanced Installations ###
For a more advanced installation, please refer to our documentation located in the ``docs`` folder.
