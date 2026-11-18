"""Offline runtime CLI registry adapter."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..runtime_cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..runtime_cli import run
    return run(args, cancel)


COMMAND = CliCommand('runtime', 'inspect or install a local offline runtime archive', _build, _run)
