"""`patchtrace profile list|show|validate|save|delete`: analysis profiles (adapter over `enrichment.profile_cli`)."""
from __future__ import annotations

from . import CliCommand


def _build(sub):
    from ..enrichment.profile_cli import add_parser  # function-level: listing the verbs imports no feature
    return add_parser(sub)


def _run(args, cancel):
    from ..enrichment.profile_cli import run
    return run(args, cancel)


COMMAND = CliCommand('profile', 'analysis profiles: list, show, validate, save, delete', _build, _run)
