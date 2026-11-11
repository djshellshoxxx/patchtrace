"""`patchtrace doctor`: one health report that starts no process (adapter over `doctor_cli`)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..doctor_cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..doctor_cli import run
    return run(args, cancel)


COMMAND = CliCommand('doctor', 'health report: version, dependencies, verbs, bundle, runtime candidates', _build, _run)
