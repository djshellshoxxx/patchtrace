"""`patchtrace corrections`: manual match corrections as a document (adapter over `corrections_cli`)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..corrections_cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..corrections_cli import run
    return run(args, cancel)


COMMAND = CliCommand('corrections', 'manual match corrections: list, export, import, undo', _build, _run)
