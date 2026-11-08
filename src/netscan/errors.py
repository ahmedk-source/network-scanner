"""Exception hierarchy for netscan.

Every error that is caused by user input or by a predictable runtime condition
derives from :class:`NetscanError`, so the CLI can turn it into a clean message
and a usage exit code instead of a traceback.
"""

from __future__ import annotations


class NetscanError(Exception):
    """Base class for all expected errors raised by netscan."""


class TargetError(NetscanError):
    """A target specification is invalid, too large or not permitted."""


class PortSpecError(NetscanError):
    """A port specification is invalid."""


class DiscoveryError(NetscanError):
    """Host discovery could not run with the requested method."""


class OutputError(NetscanError):
    """A report could not be written to the requested destination."""
