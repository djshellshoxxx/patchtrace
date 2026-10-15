"""`patchtrace kb`: passthrough adapter over the Qt-free kbcorrelation dispatcher (it parses its own argv)."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction
from threading import Event

from . import CliCommand
from ._support import add_passthrough


def _build(sub: _SubParsersAction) -> ArgumentParser:
    return add_passthrough(sub, 'kb', 'patchtrace kb ACTION [options]  (kb --help lists actions)')


def _run(args: Namespace, cancel: Event) -> int:
    from patchtrace.kbcorrelation.cli import main
    return main(args.rest or ['--help'])


COMMAND = CliCommand('kb', 'KB / CVE advisory correlation (offline; coverage always stated)', _build, _run)
