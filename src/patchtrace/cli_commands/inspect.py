"""`patchtrace inspect`: adapter over the Qt-free pe_overview dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace.pe_overview import cli
    return cli.register(sub, common, _HANDLERS)


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['inspect'](args, cancel)


COMMAND = CliCommand('inspect', 'version, manifest and signature facts of both files (static; no execution)', _build, _run)
