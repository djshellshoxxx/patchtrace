"""`patchtrace diaphora`: optional Diaphora result import (adapter over `diaphora.cli`, SPEC-DA-01 Mode A)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..diaphora.cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..diaphora.cli import run
    return run(args, cancel)


COMMAND = CliCommand('diaphora', 'import an existing Diaphora result as optional evidence', _build, _run)
