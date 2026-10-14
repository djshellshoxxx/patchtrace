"""`patchtrace kev`: passthrough adapter over the Qt-free KEV dispatcher (it parses its own argv)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import add_passthrough


def _build(sub: _SubParsersAction) -> ArgumentParser:
    return add_passthrough(sub, 'kev', 'patchtrace kev {status,plan,fetch,import,lookup,diff,prune} [options]  (kev --help)')


def _run(args: Namespace, cancel: Event) -> int:
    from patchtrace.kev.cli import main
    return main(args.rest)


COMMAND = CliCommand('kev', 'CISA Known Exploited Vulnerabilities snapshot: import, look up, status (offline)', _build, _run)
