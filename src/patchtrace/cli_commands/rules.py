"""`patchtrace rules`: adapter over the Qt-free YARA-X rule-authoring dispatcher (feature imported lazily)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import common

_HANDLERS: dict = {}


def _build(sub: _SubParsersAction) -> ArgumentParser:
    from patchtrace.yarax import cli
    cli.register(sub, common, _HANDLERS)
    return sub.choices['rules']


def _run(args: Namespace, cancel: Event) -> int:
    return _HANDLERS['rules'](args, cancel)


COMMAND = CliCommand('rules', 'detection rules from an accepted function pair (YARA-X in a capped child)', _build, _run)
