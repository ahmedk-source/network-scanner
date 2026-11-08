# netscan

[![CI](https://github.com/ahmedk-source/network-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmedk-source/network-scanner/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests 219 passing](https://img.shields.io/badge/tests-219%20passing-brightgreen)](tests/)

A small, dependency-free TCP network scanner in Python: find the devices on
your LAN, then list the TCP ports they expose — with service names and
banners.

It is built around a simple, honest idea: a normal `connect()` socket.
No raw packets, no root, no administrator account for the default scan —
the same technique `nmap -sT` uses, but tiny, readable and easy to extend
for a learning or home-lab project.

> **Use responsibly.** Only scan networks you own or are explicitly
> authorised to test. See [SECURITY.md](SECURITY.md).

## Features

- **Host discovery** without privileges:
  - `tcp` — a refused connection counts as "host is up", so it works
    even when every interesting port is closed (the default).
  - `cache` — read the OS neighbour table (`arp -a` / `ip neigh`).
  - `none` — assume every target is up (useful behind filters).
  - `arp` / `auto` — broadcast ARP via [Scapy](https://scapy.net/)
    (optional extra, needs administrator privileges). `auto` tries ARP
    first and falls back to TCP probes with a warning.
- **Connect port scanning** with bounded concurrency
  (default 200 workers, capped internal queue).
- **Banner grabbing** — HTTP services get a harmless `HEAD` request and
  the `Server:` header is reported; SSH/FTP-style services that speak
  first are read directly. Banners are cleaned to one printable line.
- **Flexible targets** — single address, CIDR block, `start-end` range,
  hostname, comma-separated lists, or `auto` (the local `/24`).
- **Port presets** — `common` (116 curated ports), `web`, or `all`
  (1–65535), plus arbitrary lists and ranges.
- **Safe by default** — public addresses are refused unless you pass
  `--allow-public`; scans are capped at 4096 hosts by default
  (`--max-hosts`).
- **Reports** in three formats from one shared model: human table,
  JSON (schema v1, scriptable), CSV (one row per open port).
- **Python API** — use the same building blocks from your own scripts
  (see [examples/scan_localhost.py](examples/scan_localhost.py)).
- **Exit codes** — `0` success, `2` usage error, `130` cancelled (Ctrl+C).
  Errors print a clean message, never a traceback.

## Requirements

- Python 3.11 or newer. No runtime dependencies for the default scan.
- Optional, for ARP discovery: `pip install "network-scanner[arp]"`
  (Scapy + administrator / Npcap privileges).

## Quick start

```console
$ pip install -e .          # or: pipx install ./  or just: python -m netscan
$ netscan --help
$ netscan ports             # list the built-in presets
```

Scan your own network:

```console
$ netscan scan 192.168.1.0/24 -p common
```

Scan one host on the first 1024 ports:

```console
$ netscan scan 192.168.1.10 -p 1-1024
```

Scan a range, show a live progress line, and save JSON:

```console
$ netscan scan 192.168.1.10-13 --progress --format json -o scan.json
```

Preview a scan without sending a single packet:

```console
$ netscan scan 192.168.1.0/24 -p common --dry-run
```

For a first safe try, target only `127.0.0.1` (your own machine):

```console
$ netscan scan 127.0.0.1 -p 80,22,443
```

### Example output

```text
Scanning 254 address(es) on 116 port(s) (discovery: tcp) ...

Target      192.168.1.0/24 (254 hosts)
Discovery   tcp
Ports       common (116 ports)
Duration    4.21s

Hosts  4 up / 254 probed

Address      MAC                Hostname    Open ports
-----------  -----------------  ----------  ----------------
192.168.1.1  aa:bb:cc:dd:ee:01  router.lan  22, 80, 443
192.168.1.12 aa:bb:cc:dd:ee:0c  -           554, 8080
192.168.1.30 aa:bb:cc:dd:ee:1e  printer.lan  9100
192.168.1.42 aa:bb:cc:dd:ee:2a  -           -

Open ports
----------
192.168.1.1  router.lan
Port  Service  Banner
----  -------  -------------
  22  ssh      ssh      SSH-2.0-OpenSSH_9.6
  80  http     nginx/1.27
 443  https    -
```

### Target syntax

| Syntax | Meaning |
| --- | --- |
| `192.168.1.10` | one address |
| `192.168.1.0/24` | CIDR block (network/broadcast excluded) |
| `192.168.1.10-13` | short range (last octet) |
| `192.168.1.10-192.168.1.20` | full range |
| `router.lan` | hostname (resolved to IPv4) |
| `192.168.1.1,192.168.1.2` | comma-separated list |
| *(nothing)* / `auto` | the local `/24` |

### Port syntax

| Syntax | Meaning |
| --- | --- |
| `common` | 116 curated ports (default) |
| `web` | 80, 443, 3000, 8000, 8080, 8443, 8888 |
| `all` | 1–65535 |
| `22,80,443` | explicit list |
| `1-1024` | range |
| `80,1-3` | mixed (combined with commas) |

### Discovery methods (`-m`)

| Method | How it works | Needs privileges? |
| --- | --- | --- |
| `tcp` (default) | Connect to 80/443/22/445/3389 — open *or* refused means "up". | No |
| `arp` | Broadcast ARP request per `/24` via Scapy, collects MAC addresses. | Yes (Scapy + admin) |
| `auto` | ARP if Scapy is available, otherwise TCP. Falls back with a warning. | Only for ARP |
| `cache` | Only hosts already in the OS neighbour table. Instant, but incomplete. | No |
| `none` | Skip discovery; scan every target. | No |

## Command reference

```text
usage: netscan [-h] [--version] COMMAND ...

positional arguments:
  COMMAND
    scan      discover hosts and scan their TCP ports
    ports     list the built-in presets or expand a port specification

╭─ netscan scan ──────────────────────────────────────────────────────────╮
│  netscan scan [TARGET ...] [-p SPEC] [-m {auto,tcp,arp,cache,none}]    │
│      [--timeout SECONDS] [--workers N] [--retries N]                  │
│      [--banners | --no-banners] [--resolve] [--allow-public]          │
│      [--max-hosts N] [--format {table,json,csv}] [-o PATH]            │
│      [--dry-run] [--progress] [-v] [-q] [--no-color]                  │
╰─ netscan ports ───────────────────────────────────────────────────────╯
│  netscan ports [SPEC] [--format {table,json}]                         │
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-p`, `--ports` | `common` | Port specification or preset. |
| `-m`, `--method` | `auto` | Discovery method. |
| `--timeout` | `0.5` | Connect timeout per port, in seconds. |
| `--workers` | `200` | Concurrent connections. |
| `--retries` | `0` | Retries for ports that *time out* (refusals are final). |
| `--no-banners` | — | Skip banner grabbing (faster, quieter). |
| `--resolve` | — | Reverse-resolve hostnames (can be slow on broken DNS). |
| `--allow-public` | — | Allow targets outside private address ranges. |
| `--max-hosts` | `4096` | Hard cap on expanded targets. |
| `--format` | `table` | `table`, `json` or `csv`. |
| `-o`, `--output` | stdout | Write the report to a file instead. |
| `--dry-run` | — | Print the plan, send no packets. |
| `--progress` | — | Live `Scanned N/M hosts` line on stderr (table format). |
| `-v`, `--verbose` | — | Report the discovery outcome before scanning. |
| `-q`, `--quiet` | — | Hide headers and progress, keep the table. |
| `--no-color` | — | Disable ANSI colour (also honours `NO_COLOR`). |

## Python API

```python
from netscan import ScanOptions, discover, expand_targets, parse_ports, scan_hosts

targets = expand_targets(["192.168.1.0/30"])
found = discover(targets)                       # TCP probes, no privileges
report = scan_hosts(
    found.hosts, parse_ports("web"),
    ScanOptions(timeout=0.5, workers=100),
    macs=found.macs,
)
for host in report:
    print(host.address, host.mac, host.port_numbers)
```

See [examples/scan_localhost.py](examples/scan_localhost.py) for a
runnable version that only ever touches `127.0.0.1`.

## JSON report (schema v1)

```json
{
  "schema": 1,
  "tool": "netscan",
  "version": "1.0.0",
  "started_at": "2026-11-08T04:30:00+00:00",
  "duration_seconds": 4.212,
  "targets": ["192.168.1.0/24"],
  "hosts_scanned": 254,
  "method": "tcp",
  "port_spec": "common",
  "ports_scanned": 116,
  "warnings": [],
  "hosts": [
    {
      "address": "192.168.1.1",
      "mac": "aa:bb:cc:dd:ee:01",
      "hostname": "router.lan",
      "open_ports": [
        {"port": 22, "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.6"}
      ]
    }
  ],
  "summary": {"hosts_scanned": 254, "hosts_up": 4, "open_ports": 11}
}
```

## How it works

```
   targets ──expand──▶ IPv4 list ──discover──▶ up hosts + MACs
                                                    │
                                          scan_ports (TCP connect, bounded pool)
                                                    ▼
                                          HostResult / PortResult ──▶ table | JSON | CSV
```

- `targets.py` — strict parsing of addresses, CIDR, ranges and hostnames.
- `discovery.py` — TCP probes, OS neighbour cache, optional Scapy ARP.
- `scanner.py` — TCP connect scan, retries on timeouts only, banner
  grabbing with a hard size/time budget, DNS with a hard timeout.
- `ports.py` — curated service table (same answer on every OS) + the
  platform database as fallback.
- `output.py` — table, JSON and CSV rendered from one report model.
- `console.py` — ASCII-only terminal output (safe on legacy Windows
  code pages), ANSI colour only when the stream is a TTY.

### Design trade-offs

- **Connect scan, not SYN scan.** A connect scan completes the TCP
  handshake, needs no privileges, and shows up in the target's logs —
  the right default for a tool that is also used for learning.
- **Discovery by TCP refusal.** If a host answers with "connection
  refused", it is unambiguously alive, even if no useful service is
  open. This makes discovery work through firewalls that block ICMP.
- **Bounded concurrency.** `windowed_map` keeps at most `2 × workers`
  futures in flight instead of queuing thousands of sockets.
- **IPv4 only.** Home and office LANs are still overwhelmingly IPv4;
  one address family keeps discovery, output and tests easy to reason
  about.

## Development

```console
$ python -m venv .venv
$ .venv/bin/pip install ".[dev]"        # Windows: .venv\Scripts\python -m pip install ".[dev]"
$ .venv/bin/python -m pytest --cov=netscan          # 219 tests, 90%+ coverage gate
$ .venv/bin/python -m ruff check src tests          # lint
$ .venv/bin/python -m ruff format --check src tests # formatting
$ .venv/bin/python -m mypy                          # strict types
```

Layout:

```text
src/netscan/    library + CLI (fully typed, dependency-free at runtime)
tests/          219 tests — real loopback servers, no mocked sockets for the scanner
examples/       runnable Python-API example
.github/        CI: pytest + ruff + mypy on Python 3.11–3.13 (Linux, Windows, macOS)
```

Contributing and project conventions: see [CONTRIBUTING.md](CONTRIBUTING.md).
Found a bug? See [SECURITY.md](SECURITY.md) for how to report it safely.

## Project status

1.0.0 — stable CLI and Python API. IPv6, UDP scanning and SYN scanning
are intentionally out of scope for this version; see the
[CHANGELOG](CHANGELOG.md) for what changed and what is planned.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Ahmed Khaled.
