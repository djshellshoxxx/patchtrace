"""`patchtrace project`: adapter over the Qt-free project_cli dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace import project_cli
    return project_cli.register(sub, common, _HANDLERS)


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['project'](args, cancel)


COMMAND = CliCommand('project', 'create, inspect, import into, back up and re-orient a project', _build, _run)
