"""`patchtrace fabric list|show|resolve|stats`: read-only views of the anchor fabric (FAB-integration-plan.md s8).

The feature loads inside build and run, so listing or running another verb never imports it.
"""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..fabric.cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..fabric.cli import run
    return run(args, cancel)


COMMAND = CliCommand('fabric', 'read the anchor fabric: list, show, resolve or stats (read-only)', _build, _run)
