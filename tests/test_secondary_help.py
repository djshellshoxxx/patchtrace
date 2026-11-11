"""`secondary --help` must not print the hidden BinExport worker's SUPPRESS placeholder (regression)."""
from __future__ import annotations

import argparse

from patchtrace import cli


def _secondary_subparser() -> argparse.ArgumentParser:
    parser = cli._parser()
    top = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return top.choices['secondary']


def test_secondary_help_hides_worker_without_suppress_placeholder():
    text = _secondary_subparser().format_help()
    assert '==SUPPRESS==' not in text
    assert '\n    _binexport-worker' not in text  # the listing line; the usage choices may still name it
    assert 'binexport-check' in text  # visible siblings are still listed


def test_hidden_worker_still_parses():
    sub = _secondary_subparser()
    args = sub.parse_args(['_binexport-worker', '--request', 'req.json'])
    assert args.action == '_binexport-worker' and args.request == 'req.json'
