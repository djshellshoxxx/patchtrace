"""`patchtrace compare`: adapter over the Qt-free compare_cli dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace import compare_cli
    return compare_cli.register(sub, common, _HANDLERS)


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['compare'](args, cancel)


COMMAND = CliCommand('compare', 'run the primary Ghidriff analysis for one project pair (static only)', _build, _run)
