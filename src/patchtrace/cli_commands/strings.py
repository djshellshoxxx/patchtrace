"""`patchtrace strings`: adapter over the Qt-free strings dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace.strings import cli
    cli.register(sub, common, _HANDLERS)
    return sub.choices['strings']


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['strings'](args, cancel)


COMMAND = CliCommand('strings', 'string changes between the two builds (static; never executes them)', _build, _run)
