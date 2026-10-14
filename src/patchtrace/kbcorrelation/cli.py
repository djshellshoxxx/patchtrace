"""`kb` command assembler (KB-integration-plan 8.1; slice K3). Qt-free; offline.

``main(argv)`` takes the arguments after ``kb``. ``kb index ...`` goes to ``cli_index``; the pair verbs live in
``cli_pairs``; this module adds ``search``, ``attach``, ``explain`` and ``export``. Slice K4a adds ``leads`` with one
import of ``cli_leads`` here and one entry each in ``REGISTRARS`` and ``HANDLERS``.

Hook for ``patchtrace/cli.py`` (A-8; 4 lines, applied by the integrator; ``kb`` parses its own arguments, so no
argparse entry is needed and the command-name set of the failure envelope is untouched):

    from .kbcorrelation import cli as kb_cli          # with the other dispatcher imports
    COMMANDS = (..., 'backend', 'kb')                  # the command tuple
    if argv[:1] == ['kb']:                             # in main(), right after the stdout/stderr reconfigure loop
        return kb_cli.main(argv[1:])

Output is one ``enrichment-cli/1`` document per call; exit codes 0/2/3/4/5.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from . import cli_index, cli_pairs
from .cli_index import IndexPorts, Parser, add_common, present, run_cli, workspace_root


@dataclass
class Context:
    """Builds the production service lazily so ``--help`` and argument errors never import ``intelligence``."""
    env: object | None = None

    def _env(self):
        if self.env is None:
            from .wiring import build_env
            self.env = build_env()
        return self.env

    def service(self, args):
        from .service import KbService
        return KbService(workspace_root(args), self._env())

    def index_ports(self) -> IndexPorts:
        env = self._env()
        return IndexPorts(advisory=env.advisory, clock=env.clock)


def _register_core(sub) -> None:
    sub.add_parser('index', help='offline index: import, status, verify, plan (see "kb index --help")')
    search = add_common(sub.add_parser('search', help='find the CVEs and products of a KB or CVE in loaded documents'))
    search.add_argument('lead', metavar='KB|CVE', help='KB5012345, 5012345 or CVE-2024-12345')
    scope = search.add_mutually_exclusive_group()
    scope.add_argument('--months', metavar='YYYY-Mon[,..]', help='finite scope: release months (at most 24)')
    scope.add_argument('--scope-file', type=Path, metavar='F', help='JSON file with "months" and/or "doc_ids"')
    search.add_argument('--offline', action='store_true', help='accepted for clarity; search never fetches')
    search.add_argument('--product', metavar='ID', help='keep one product scope; others are listed as not applicable')
    search.add_argument('--investigation', metavar='ID', help='continue an investigation instead of starting one')
    attach = add_common(sub.add_parser('attach', help='finish or inspect the context attach of a project'))
    attach.add_argument('project', metavar='PROJECT')
    attach.add_argument('--investigation', required=True, metavar='INV')
    attach.add_argument('--repair', action='store_true', help='finish an interrupted attach (idempotent)')
    explain = add_common(sub.add_parser('explain', help='show a project\'s advisory context'))
    explain.add_argument('project', metavar='PROJECT')
    explain.add_argument('--cve', metavar='CVE')
    export = add_common(sub.add_parser('export', help='write the advisory context as JSON or escaped Markdown'))
    export.add_argument('project', metavar='PROJECT')
    export.add_argument('file', metavar='FILE.json|FILE.md')
    export.add_argument('--overwrite', action='store_true')


def cmd_search(args, context, out) -> int:
    return present(out, 'kb search', args, context.service(args).search(
        args.lead, months=args.months, scope_file=args.scope_file, product=args.product,
        investigation=args.investigation))


def cmd_attach(args, context, out) -> int:
    return present(out, 'kb attach', args, context.service(args).attach(
        args.project, args.investigation, repair_it=args.repair))


def cmd_explain(args, context, out) -> int:
    return present(out, 'kb explain', args, context.service(args).explain(args.project, args.cve))


def cmd_export(args, context, out) -> int:
    return present(out, 'kb export', args, context.service(args).export(args.project, args.file,
                                                                         overwrite=args.overwrite))


HANDLERS = {'search': cmd_search, 'attach': cmd_attach, 'explain': cmd_explain, 'export': cmd_export,
            **cli_pairs.HANDLERS}
REGISTRARS = [_register_core, cli_pairs.register]


def build_parser() -> Parser:
    parser = Parser(prog='patchtrace kb', description='KB / CVE advisory correlation: offline, never fetches, never '
                    'runs a target. Coverage is stated for every answer.')
    sub = parser.add_subparsers(dest='action', required=True, parser_class=Parser)
    for register in REGISTRARS:
        register(sub)
    return parser


def main(argv: list[str] | None = None, *, env=None, stdout=None, stderr=None) -> int:
    """Run ``kb <verb> ...``. ``env`` replaces the production ports (tests)."""
    argv = list(sys.argv[1:] if argv is None else argv)
    context = Context(env)
    if argv[:1] == ['index']:
        if '-h' in argv[1:] or '--help' in argv[1:]:
            return cli_index.main(argv[1:], stdout=stdout, stderr=stderr)
        return cli_index.main(argv[1:], ports=context.index_ports(), stdout=stdout, stderr=stderr)
    return run_cli('kb', build_parser, HANDLERS, argv, ports=context, stdout=stdout, stderr=stderr)
