"""Lazy registry adapter for the bounded headless version observer."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..version_cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..version_cli import run
    return run(args, cancel)


COMMAND = CliCommand('version', 'version and available source/build provenance', _build, _run)
