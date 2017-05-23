# Peekaboo #

Peekaboo Extended Email Attachment Behavior Observation Owl  

Currently, the main use case of Peekaboo is to listen for connections from
AMaViSd, which supplies a path in file system for every e-mail
processed.
Peekaboo will check the files using cuckoo sandbox and
supply analysis results back to AMaViSd (bad | checked | good | ignored).
Also, Peekaboo will run a static analysis using its own ruleset before
submitting any files to Cuckoo.

* bad - for files that match any of the configured signature rules
* good - for files that are manually marked as good
* ignored - for files that file type does not match file types for analysis
* checked - for every file that has been analyzed and is not bad


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
