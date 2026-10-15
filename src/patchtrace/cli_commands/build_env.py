"""`patchtrace build-env`: adapter over the Qt-free buildenv dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace.buildenv import cli
    cli.register(sub, common, _HANDLERS)
    return sub.choices['build-env']


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['build-env'](args, cancel)


COMMAND = CliCommand('build-env', 'build environment of the older and newer file (reads only)', _build, _run)
