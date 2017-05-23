.. Peekaboo documentation master file, created by
   sphinx-quickstart on Mon Apr 10 12:58:45 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Peekaboo's documentation!
====================================

Peekaboo Extended Email Attachment Behavior Observation Owl

Status: **DRAFT**.

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


.. toctree::
   install
   config
   development
   :maxdepth: 3
