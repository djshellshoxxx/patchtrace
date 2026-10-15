"""`patchtrace kev`: the CISA Known Exploited Vulnerabilities catalog (adapter over `kev.cli`, GUI plan 8.12)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..kev.cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..kev.cli import run
    return run(args, cancel)


COMMAND = CliCommand('kev', 'CISA KEV catalog: status, plan, fetch, import, lookup', _build, _run)
