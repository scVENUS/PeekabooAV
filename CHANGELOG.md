# Notable changes between releases

See documentation for details.

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
