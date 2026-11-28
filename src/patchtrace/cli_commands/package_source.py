"""Lazy registry adapter for local cabinet source inspection."""
from . import CliCommand


def _build(sub):
    from ..acquisition.package_cli import add_parser
    return add_parser(sub)


def _run(args, cancel):
    from ..acquisition.package_cli import run
    return run(args, cancel)


COMMAND = CliCommand('package-source', 'inspect local Windows cabinet source identity and SHA-256', _build, _run)
