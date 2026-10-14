"""`patchtrace panels list|check`: the GUI panel manifest (GUI plan 8.12). The feature loads inside build and run."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..gui.cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..gui.cli import run
    return run(args, cancel)


COMMAND = CliCommand('panels', 'list or check the GUI panel manifest', _build, _run)
