# Contributing

Thanks for stopping by. This is a small project, and contributions that
keep it small, typed and readable are welcome.

## Ground rules

- **Only scan networks you own or are authorised to test.** The same
  rule applies to bug reports: never attach a scan of somebody else's
  network, and do not test exploits or hostile payloads against systems
  you do not own. See [SECURITY.md](SECURITY.md).
- **No new runtime dependencies** without a strong reason. The default
  scan must keep working on a bare `python -m pip install .` with only
  the standard library. Optional features live behind extras (like
  `arp`, which is how Scapy is integrated).
- **Keep the code fully typed.** `mypy` runs in strict mode on `src/`;
  new public functions need type annotations and docstrings.
- **ASCII-only terminal output.** No spinners, emoji or box drawing —
  output must render on legacy Windows code pages.

## Getting set up

```console
python -m venv .venv
.venv/bin/pip install ".[dev]"        # Windows: .venv\Scripts\python -m pip install ".[dev]"
```

## The four checks (CI runs all of them)

```console
.venv/bin/python -m pytest --cov=netscan     # 219 tests, coverage gate: 90%
.venv/bin/python -m ruff check src tests
.venv/bin/python -m ruff format --check src tests
.venv/bin/python -m mypy                     # strict on src/, tests included
```

All four must pass on Linux, Windows and macOS, Python 3.11–3.13,
before a pull request is merged.

## How to add a feature

1. Open an issue first if the change is large (new discovery method,
   new output format, IPv6, ...). Small fixes can go straight to a PR.
2. Add tests with the change. Prefer real loopback servers over mocked
   sockets — see `tests/conftest.py` (`server_factory` fixture). Tests
   must not depend on the network you happen to be on, and must never
   reach outside `127.0.0.0/8` or private ranges.
3. Keep the CLI and the Python API in sync: every new flag needs tests
   in `tests/test_cli.py`, and library changes need coverage in the
   matching module test file.
4. Update `README.md` (usage / flags) and `CHANGELOG.md` (under
   `## [Unreleased]`) in the same pull request.

## Code style

- `ruff` with `line-length = 100`, double quotes, `py311` target.
  `ruff format` is the source of truth — run it, do not hand-format.
- Docstrings explain *why*, not *what*. Say what the code deliberately
  does not do (e.g. why timeouts are retried but refusals are not).
- Errors caused by user input derive from `netscan.errors.NetscanError`
  so the CLI can print a clean message and exit with code 2 instead of
  a traceback.

## Reporting a bug

Include: `netscan --version`, your OS and Python version, the exact
command you ran, and the full output. Read output, not screenshots —
they are easier to copy and paste.
