"""`patchtrace diaphora inspect|import|show` (SPEC-DA-01 CLI, Mode A only). Qt-free; envelope `enrichment-cli/1`.

Exit codes follow the umbrella: 0 ok, 2 environment/input, 3 runtime, 4 no results, 5 cancelled.
Nothing here runs Diaphora, IDA or an analysed binary.
"""
from __future__ import annotations

import argparse
import threading
from pathlib import Path

from .contracts import DiaphoraError

_INPUT_CODES = {'PT-DIAPHORA-INPUT', 'PT-DIAPHORA-DB', 'PT-DIAPHORA-PAIR', 'PT-DIAPHORA-ORIENTATION',
                'PT-DIAPHORA-PROVENANCE'}


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('diaphora', help='import an existing Diaphora result as optional evidence (SPEC-DA-01)')
    actions = parser.add_subparsers(dest='action', required=True)
    inspect = actions.add_parser('inspect', help='read a .diaphora result without a project (counts only)')
    inspect.add_argument('result', type=Path)
    imp = actions.add_parser('import', help='bind a .diaphora result to the project pair and store it')
    imp.add_argument('project', type=Path)
    imp.add_argument('--diff', type=Path, required=True, help='the .diaphora result database')
    imp.add_argument('--manifest', type=Path, default=None, help='diaphora-diff/1 sidecar binding result and pair')
    imp.add_argument('--user-attest-pair', action='store_true',
                     help='without a manifest: you attest the result was made from exactly this older/newer pair')
    show = actions.add_parser('show', help='summarise stored Diaphora sets and their reconciliation with Ghidriff')
    show.add_argument('project', type=Path)
    for each in (inspect, imp, show):
        each.add_argument('--json', action='store_true', help='print one enrichment-cli/1 JSON document')
    return parser


def _fail(exc: DiaphoraError):
    from ..cli import CANCELLED, ENVIRONMENT, RUNTIME, CliError
    code = CANCELLED if exc.code == 'PT-DIAPHORA-CANCEL' else ENVIRONMENT if exc.code in _INPUT_CODES else RUNTIME
    return CliError(code, str(exc))


def run(args: argparse.Namespace, cancel: threading.Event) -> int:
    from ..cli import NO_RESULTS, OK, _emit, _open
    try:
        if args.action == 'inspect':
            from .result_import import inspect_result
            info = inspect_result(args.result, cancel)
            result = {'result_sha256': info.result_sha256, 'size': info.size, 'diaphora_version': info.version,
                      'date': info.date, 'tables': list(info.tables), 'matches': info.counts,
                      'unmatched': info.unmatched}
            _emit(args, 'diaphora inspect', 'complete', result, [],
                  f'Diaphora {info.version or "unknown"}: {sum(info.counts.values())} matches {info.counts}, '
                  f'{info.unmatched} unmatched. Not bound to any pair.')
            return OK
        service = _open(args.project)
        try:
            from . import bridge
            from . import service as svc
            if args.action == 'import':
                entry, match_set = svc.import_into_project(service, args.diff, manifest=args.manifest,
                                                           user_attest_pair=args.user_attest_pair, cancel=cancel)
                report = bridge.reconcile(service.project.matches, match_set)
                result = {'entry': entry.id, 'trust': match_set.trust, 'matches': len(match_set.matches),
                          'unmatched': len(match_set.unmatched), 'duplicate_rows': match_set.duplicate_rows,
                          'counts': report.counts(), 'diaphora_only': len(report.diaphora_only),
                          'limitations': list(report.limitations)}
                _emit(args, 'diaphora import', 'complete', result, [],
                      f'{len(match_set.matches)} matches stored ({match_set.trust}); {report.counts()}')
                return OK if match_set.matches else NO_RESULTS
            rows = svc.stored_sets(service)
            sets = []
            for entry, match_set in rows:
                report = bridge.reconcile(service.project.matches, match_set)
                sets.append({'entry': entry.id, 'trust': match_set.trust, 'diaphora_version': match_set.engine_version,
                             'matches': len(match_set.matches), 'unmatched': len(match_set.unmatched),
                             'counts': report.counts(), 'diaphora_only': len(report.diaphora_only)})
            _emit(args, 'diaphora show', 'complete', {'sets': sets}, [],
                  '\n'.join(f'{s["entry"][:12]}: {s["matches"]} matches ({s["trust"]}); {s["counts"]}' for s in sets)
                  or 'No Diaphora result stored.')
            return OK if sets else NO_RESULTS
        finally:
            service.close()
    except DiaphoraError as exc:
        raise _fail(exc) from None
