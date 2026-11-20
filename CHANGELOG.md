# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository skeleton: Go module, command, configuration reader and writer, sample
  `/etc/paneldns-agent.conf`, README, security policy, code owners.
- Zone readers (t040): named.conf parser with includes, glob includes, views and per-zone
  `check-names`/integrity/format options; `named-compilezone` reader with the built-in RFC 1035
  parser as fallback; PowerDNS local API reader; system-zone list, `EXCLUDE` matching and the
  DNSSEC/private-type strip list.
