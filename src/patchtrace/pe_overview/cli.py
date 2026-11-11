"""`patchtrace inspect`: version, manifest and signature facts of the older and newer file (SPEC-51 D2-5).

Qt-free dispatcher; `cli_commands/inspect.py` is the registry adapter. Envelope `enrichment-cli/1`, exit codes
0 ok, 2 invalid arguments, 3 runtime failure or partial result, 4 no PE input, 5 cancelled. Offline by default:
structure and digest are read from the hash-verified project copy; chain trust and revocation are never invented.
`--trust cache|online` name Windows-only revocation modes; this build has no Windows catalog slice (D2-4), so they
exit 3 `PT-PE-TRUST-UNAVAILABLE` after the consent rule has been checked (online needs `--consent-online`, exit 2
`PT-PE-CONSENT-REQUIRED`). Output holds no absolute path.
"""
from __future__ import annotations

import threading
from argparse import ArgumentParser, Namespace, _SubParsersAction
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .cache import TRUST_MODES
from .labels import catalog_label, embedded_label

SIDES = ('older', 'newer')
CONTRACT = 'pe-inspect/1'


def register(sub: _SubParsersAction, common, handlers: dict) -> ArgumentParser:
    handlers['inspect'] = dispatch
    parser = common(sub.add_parser('inspect', help='version, manifest and signature facts of the older and newer '
                                   'file (static; never executes them)'))
    parser.add_argument('project', type=Path)
    parser.add_argument('--side', choices=('older', 'newer', 'both'), default='both')
    parser.add_argument('--trust', choices=TRUST_MODES, default='offline',
                        help='offline reads structure and digest only; cache and online need Windows')
    parser.add_argument('--consent-online', action='store_true',
                        help='required with --trust online: Windows may contact revocation servers named in the file')
    return parser


def _check_trust(args: Namespace) -> None:
    from ..cli import ENVIRONMENT, RUNTIME, CliError
    if args.trust == 'online' and not args.consent_online:
        raise CliError(ENVIRONMENT, 'PT-PE-CONSENT-REQUIRED: --trust online needs --consent-online; Windows would '
                       'contact revocation servers named inside the file, which tells them the certificate is '
                       'being checked')
    if args.consent_online and args.trust != 'online':
        raise CliError(ENVIRONMENT, '--consent-online is only valid with --trust online')
    if args.trust != 'offline':
        raise CliError(RUNTIME, f'PT-PE-TRUST-UNAVAILABLE: --trust {args.trust} needs the Windows catalog and '
                       'revocation probe, which this build does not include')


def _read_side(artifact, root: Path, cancel: threading.Event) -> tuple[dict[str, Any], Any]:
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..intelligence.tools.common import display_text
    from . import inspect_pe
    from .metadata import inspect_metadata
    record: dict[str, Any] = {'side': artifact.side, 'name': display_text(Path(artifact.name).name, 200),
                              'sha256': artifact.sha256, 'status': 'unreadable', 'error': None}
    try:
        with VerifiedArtifactReader.open_artifact(artifact, root, cancel.is_set) as reader:
            overview = inspect_pe(reader, cancel=cancel.is_set)
            if overview.status == 'not_pe':
                record['status'] = 'not_pe'
                return record, None
            meta = inspect_metadata(reader, overview, cancel.is_set)
    except ArtifactBytesError as exc:
        record['status'], record['error'] = ('cancelled', None) if cancel.is_set() else ('unreadable', exc.code)
        return record, None
    if meta.status == 'cancelled' or cancel.is_set():
        record['status'] = 'cancelled'
        return record, None
    record['status'] = 'partial' if meta.status == 'partial' else 'read'
    return record, meta


def _side_json(record: dict[str, Any], meta) -> dict[str, Any]:
    from .compare import describe_metadata
    if meta is None:
        return record
    return record | {
        'labels': {'embedded': embedded_label(meta.signatures), 'catalog': catalog_label('not_checked')},
        'facts': [{'field': f, 'value': v, 'source': s} for f, v, s in describe_metadata(meta)],
        'signatures': [asdict(s) for s in meta.signatures],
        'warnings': [w.code for w in meta.warnings]}


def _text(rows: list[dict[str, Any]], comparison) -> str:
    lines = []
    for row in rows:
        head = f'{row["side"].upper()} {row["name"]} sha256 {row["sha256"][:16]}'
        if row['status'] not in ('read', 'partial'):
            lines.append(f'{head}: {row["status"]}' + (f' ({row["error"]})' if row['error'] else ''))
            continue
        suffix = ' (partial; see warnings)' if row['status'] == 'partial' else ''
        lines.append(f'{head}: {row["labels"]["embedded"]}; catalog: {row["labels"]["catalog"]}{suffix}')
        lines += [f'  {f["field"]}: {f["value"]}' for f in row['facts']]
    changed = [r for r in comparison if r.status == 'changed']
    if changed:
        lines.append('Changed between older and newer:')
        lines += [f'  {r.field}: {r.older} -> {r.newer} ({r.reason})' for r in changed]
    return '\n'.join(lines)


def dispatch(args: Namespace, cancel: threading.Event) -> int:
    from ..cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, _emit, _open
    from .compare import compare_metadata
    _check_trust(args)
    wanted = SIDES if args.side == 'both' else (args.side,)
    service = _open(args.project)
    try:
        by_side = {a.side: a for a in service.project.artifacts}
        missing = [side for side in wanted if side not in by_side]
        if missing:
            raise CliError(ENVIRONMENT, f'the project has no {" or ".join(missing)} artifact')
        read = []
        for side in wanted:
            read.append(_read_side(by_side[side], service.root, cancel))
            if read[-1][0]['status'] == 'cancelled':
                break
    finally:
        service.close()
    statuses = [record['status'] for record, _meta in read]
    if 'cancelled' in statuses:
        _emit(args, 'inspect', 'cancelled', None, [], '')
        return CANCELLED
    metas = {record['side']: meta for record, meta in read}
    comparison = compare_metadata(metas['older'], metas['newer']) if len(read) == 2 and all(
        record['status'] == 'read' for record, _meta in read) else ()
    rows = [_side_json(record, meta) for record, meta in read]
    result = {'contract': CONTRACT, 'sides': rows,
              'trust': {'mode': args.trust, 'consent_online': bool(args.consent_online), 'network_used': False},
              'comparison': [asdict(r) for r in comparison]}
    if all(s == 'not_pe' for s in statuses):
        code, status = NO_RESULTS, 'no-results'
    elif all(s == 'read' for s in statuses):
        code, status = OK, 'complete'
    else:
        code, status = RUNTIME, 'partial'
    _emit(args, 'inspect', status, result, [], _text(rows, comparison))
    return code
