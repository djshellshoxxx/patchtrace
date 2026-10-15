"""Shared adapter helpers: the passthrough parser (the feature parses its own argv, so even `--help` is kept) and --json."""
from __future__ import annotations

from argparse import ArgumentParser, Namespace, _SubParsersAction


def add_passthrough(sub: _SubParsersAction, name: str, usage: str) -> ArgumentParser:
    parser = sub.add_parser(name, add_help=False, usage=usage)

    def keep_all(args=None, namespace=None):  # the registry's set_defaults arrive after this call, so read lazily
        return Namespace(**parser._defaults, rest=list(args or ())), []

    parser.parse_known_args = keep_all
    return parser


def common(parser: ArgumentParser) -> ArgumentParser:
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    return parser
