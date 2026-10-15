"""`patchtrace graph`: adapter over the Qt-free callgraph dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace.callgraph import cli
    cli.register(sub, common, _HANDLERS)
    return sub.choices['graph']


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['graph'](args, cancel)


COMMAND = CliCommand('graph', 'call-graph explorer over stored Ghidriff call lists (read-only)', _build, _run)
