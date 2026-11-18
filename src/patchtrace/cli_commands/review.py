"""`patchtrace review`: review state of relations and findings, analyst notes (adapter over `review_cli`)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..review_cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..review_cli import run
    return run(args, cancel)


COMMAND = CliCommand('review', 'set the review state of a match or finding, add an analyst note', _build, _run)
