"""`patchtrace search`: passthrough adapter over the Qt-free search dispatcher (it parses its own argv)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import add_passthrough


def _build(sub: _SubParsersAction) -> ArgumentParser:
    return add_passthrough(sub, 'search', 'patchtrace search [PROJECT] [options]  (search --help)')


def _run(args: Namespace, cancel: Event) -> int:
    from patchtrace.search.cli import main
    return main(args.rest)


COMMAND = CliCommand('search', "search a project's saved names, strings, APIs, code, notes (offline)", _build, _run)
