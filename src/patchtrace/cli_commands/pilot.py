"""`patchtrace pilot leads|why|review`: patch-intent leads (PIL plan s8). The feature loads inside build and run."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..pilot.cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..pilot.cli import run
    return run(args, cancel)


COMMAND = CliCommand('pilot', 'rank changed functions against an advisory: leads, why, review', _build, _run)
