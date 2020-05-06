# Notable changes between releases

See documentation for details.

## devel

- New database schema version 8.
  Removes tables PeekabooMetadata and AnalysisJournal, and adds field
  analysis\_time to SampleInfo.
- Generic rules can now make use of the new analyser `knownreport`
- Introduce cortexreport toolbox analyser to connect to Cortex by TheHive.
  There already are a few sub analysers that can be used.

## 2.0

- Embedded Cuckoo mode and python2 support are deprecated now and scheduled for
  removal in a future release. Warnings to that effect are printed at startup
  if embed mode is in use or python2 is detected. Both are more than likely to
  be gone in release 2.1 so update your setup now!
- Generic rules allow to evaluate expressions with sample, cuckooreport and
  olereport and filereport
- Distribute and install sample configuration files in/from PyPI source
  distribution
- Make list of rules to run configurable in members and order. See
  `ruleset.conf.sample` section `[rules]` for details.
- Lower default for in-flight lock staleness to 15 minutes.
- Detect unknown config sections and options and refuse to start if any are
  found.
- Submit the sample with its original filename if available when using the REST
  API. (#81, #82)
- Improve REST API access robustness by introducing configurable urllib3 retry
  handling with backoff and defined endless retry or failure report to client.
  (#43)
- Introduce peekaboo-util.py with subcommands scan-file (as a super charged
  replacement for scan\_file.py (#107)), ping and raw (for diagnosis, scripting
  and debugging).
- Add database indices to speed up processing and lower database CPU load.
  Rename analyses\_time column to analysis\_time in analysis\_jobs table.
  Raises schema version to 7. (#124)
- No longer require configuration of a primary group to drop privileges to.
  Instead use the droppriv user's primary group and supplementary group list by
  default.
- Add new options socket\_group and socket\_mode to explicitly open up the
  socket to client connections with a secure default.

## 1.7

- give threads names for easier identification
- add configuration for rule `cuckoo_analysis_failed` to override what
  constitutes failure and what reliably indicates success
- localise client communication, i.e. have the system report findings in
  English by default but provide gettext-compatible translation templates for
  other languages
- add German translation (which was hard-coded in the source before)
- add configuration option to force language of client communication beyond
  `$LANG` and friends
- massively speed up shutdown
- make the `malware_reports` directory configurable
- add reporting of an overall analysis result (not just per sample-results) to
  correctly convey failures in addition to good/bad decisions to the client
- usage of separate python virtualenvs for peekaboo and cuckoo is now
  recommended because we use newer module versions than cuckoo
- make internal configuration defaults work so that `peekaboo.conf` can be
  mostly empty in standard setups
- log multiple analysis jobs per sample in `analysis_jobs` to get an actual job
  log
- multi-node concurrency coordinated via DB, see section `[cluster]` in
  `peekaboo.conf.sample`
- remove `analysis_results` table from DB schema for simplicity and
  performance, bump version to 6
- many bug fixes, internal cleanups and improviments

## 1.6.2

- bug fix release
- no individual change log before this
