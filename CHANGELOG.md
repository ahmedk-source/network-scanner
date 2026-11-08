# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-08

First stable release. The CLI and the Python API are considered stable.

### Added

- `netscan scan` — host discovery + TCP connect port scanning.
  - Discovery methods: `tcp` (default), `cache`, `none`, `arp`
    (optional Scapy extra), `auto` (ARP with TCP fallback).
  - Target syntax: single address, CIDR, `start-end` range, hostname,
    comma-separated list, and `auto` (local `/24`).
  - Port presets: `common` (116 curated ports), `web`, `all`,
    plus arbitrary lists and ranges.
  - Banner grabbing, including a polite `HEAD` request for HTTP services
    and `Server:` header extraction.
  - Bounded concurrency, retries for timeouts, reverse DNS with a hard
    timeout, MAC addresses from ARP replies and the OS neighbour table.
- `netscan ports` — list presets or expand a port specification
  (table or JSON).
- Reports in three formats from one shared model: table, JSON
  (schema v1), CSV (one row per open port).
- Safety defaults: public addresses refused unless `--allow-public`,
  4096-host cap (`--max-hosts`), `--dry-run` preview.
- Python API: `expand_targets`, `discover`, `parse_ports`,
  `scan_hosts`, `ScanOptions`, `HostResult`, `PortResult`.
- Exit codes: `0` success, `2` usage error, `130` cancelled.
- 219 automated tests (real loopback servers, no mocked sockets for the
  scanner), strict `mypy`, `ruff` lint + format, CI on
  Python 3.11–3.13 for Linux, Windows and macOS.

## [Unreleased]

Planned, not yet implemented:

- IPv6 support for targets and discovery.
- Optional SYN scan for users who already have administrator privileges.
- Nmap-style XML output.
- Per-port state for closed vs. filtered results.
