"""`patchtrace export`: a project as a json, md or html report, report/1 or report/2 (adapter over `report2.cli`)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..report2.cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..report2.cli import run
    return run(args, cancel)


COMMAND = CliCommand('export', 'export a project as a report (json, md, html; report/1 or 2)', _build, _run)
