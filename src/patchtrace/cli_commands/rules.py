"""`patchtrace rules`: detection rules from reviewed changes (adapter over `rules.cli`, YRX plan section 8).

The feature loads inside build and run, so listing or running another verb never imports it. The hidden verb
`_rules-worker` is the frozen executable's engine child.
"""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..rules.cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..rules.cli import run
    return run(args, cancel)


COMMAND = CliCommand('rules', 'detection rules: probe, propose, show, decide, test, export, history', _build, _run)
