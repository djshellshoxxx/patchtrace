"""`kb index` verbs: import, status, verify, plan (KB-integration-plan 8.1; slice K1). Offline: no verb here fetches.

An own dispatcher (``main(argv)``, ``build_parser``) for the arguments after ``kb index``. The ``kb`` assembler (slice
K3) and the ``cli.py`` hook (A-8) call it; nothing here edits ``cli.py``. Output follows the ``enrichment-cli/1``
envelope; exit codes: 0 ok, 2 invalid arguments or an unreadable/malformed local file, 3 runtime failure or a damaged
workspace, 4 nothing to report yet (an empty index), 5 cancelled.

Workspace (interim, K1): ``<workspace>/objects/<sha[:2]>/<sha>.gz`` holds each source's exact bytes (gzip, mtime 0) and
``<workspace>/kbc-index.json`` lists them. The index is rebuilt by re-parsing the objects, so a parser change never
leaves stale rows. Slice K2 replaces this with ``kbc.sqlite3`` and reuses the same ``objects/`` layout.

``import`` is all-or-nothing: every file is parsed and validated first, and a single rejected file leaves the index
and the object store unchanged. CSAF files need the advisory port (``IndexPorts.advisory``, bound by the ``kb``
command); without it they are refused with an explicit message.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .contracts import CONTRACT
from .index import ReverseIndex
from .limits import DEFAULT_LIMITS
from .ports import AdvisoryPort, ClockPort
from .products import clean_text, safe_label
from .sources import net_plan
from .sources.cvrf import SourceError
from .sources.importer import ImportedDocument, gunzip_bounded, import_bytes
from .sources.scope import MONTHS, coverage_text

CLI_CONTRACT = 'enrichment-cli/1'
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
MANIFEST_NAME = 'kbc-index.json'
MANIFEST_CONTRACT = 'kbc-index-k1/1'
PROBLEMS_SHOWN = 50


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise CliError(ENVIRONMENT, f'{self.prog}: {message}')


class _SystemClock:
    def now_utc(self) -> str:
        return datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


@dataclass(frozen=True)
class IndexPorts:
    """Sibling-package behaviour bound by the caller. Both are optional; the defaults are safe."""
    advisory: AdvisoryPort | None = None
    clock: ClockPort | None = None

    def now(self) -> str:
        return (self.clock or _SystemClock()).now_utc()


def default_workspace(env: dict[str, str] | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\kb``, else ``$XDG_DATA_HOME/PatchTrace/kb``, else ``~/.local/share/PatchTrace/kb``."""
    env = os.environ if env is None else env
    if env.get('LOCALAPPDATA'):
        return Path(env['LOCALAPPDATA']) / 'PatchTrace' / 'kb'
    if env.get('XDG_DATA_HOME'):
        return Path(env['XDG_DATA_HOME']) / 'PatchTrace' / 'kb'
    return Path.home() / '.local' / 'share' / 'PatchTrace' / 'kb'


# ---------------------------------------------------------------------------------------------- parser

def build_parser(prog: str = 'patchtrace kb index') -> argparse.ArgumentParser:
    parser = _Parser(prog=prog, description='Offline KB reverse index: import local documents, show status, verify, '
                     'and preview (never perform) a sync.')
    sub = parser.add_subparsers(dest='action', required=True, parser_class=_Parser)

    def common(p):
        p.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        p.add_argument('--workspace', type=Path, help='workspace directory (default: the per-user PatchTrace kb dir)')
        return p

    imp = common(sub.add_parser('import', help='import saved CVRF month or CSAF JSON files (all or nothing)'))
    imp.add_argument('files', nargs='+', type=Path, metavar='FILE')
    common(sub.add_parser('status', help='list the loaded documents and their coverage'))
    common(sub.add_parser('verify', help='re-hash and re-parse every stored document'))
    plan = common(sub.add_parser('plan', help='preview the exact requests of a sync (no network)'))
    group = plan.add_mutually_exclusive_group(required=True)
    group.add_argument('--months', metavar='YYYY-MM[,..]', help='comma-separated months (at most 24)')
    group.add_argument('--since', metavar='YYYY-MM', help='every month from here to --until (default: this month)')
    plan.add_argument('--until', metavar='YYYY-MM', help='last month of --since (default: the current month)')
    plan.add_argument('--with-index', action='store_true', help='also list the document-id index request')
    return parser


# ---------------------------------------------------------------------------------------------- output

def _emit(out, args, status: str, result, warnings: list[str], text: str, error: str | None = None) -> None:
    if args is not None and getattr(args, 'json', False):
        doc = {'contract': CLI_CONTRACT, 'command': f'kb index {args.action}', 'status': status, 'result': result,
               'warnings': warnings}
        if error is not None:
            doc['error'] = error
        out.write(json.dumps(doc, sort_keys=True) + '\n')
    else:
        out.write(text + ('\n' if text and not text.endswith('\n') else ''))


# ---------------------------------------------------------------------------------------------- workspace

def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f'.{path.name}.{os.getpid()}.tmp')
    try:
        with open(tmp, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(5):  # antivirus can hold a freshly written file on Windows
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 4:
                    raise
                time.sleep(0.05 * (attempt + 1))
    finally:
        if tmp.exists():
            tmp.unlink()


def _workspace(args) -> Path:
    return (args.workspace or default_workspace()).expanduser()


def _read_manifest(ws: Path) -> list[dict]:
    path = ws / MANIFEST_NAME
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        rows = data['documents']
        for row in rows:
            for key in ('doc_id', 'sha256', 'kind', 'size', 'imported_at', 'name'):
                row[key]
        return rows
    except (OSError, ValueError, KeyError, TypeError):
        raise CliError(RUNTIME, f'the workspace index file {MANIFEST_NAME} is damaged; run "kb index verify"') from None


def _write_manifest(ws: Path, rows: list[dict]) -> None:
    body = {'contract': MANIFEST_CONTRACT, 'documents': sorted(rows, key=lambda r: r['doc_id'])}
    _atomic_write(ws / MANIFEST_NAME, (json.dumps(body, indent=2, sort_keys=True) + '\n').encode('utf-8'))


def _read_file(path: Path) -> bytes:
    cap = DEFAULT_LIMITS.cvrf_doc_bytes
    try:
        with open(path, 'rb') as handle:
            data = handle.read(cap + 1)
    except OSError:
        raise SourceError('PT-KBC-INPUT', 'the file cannot be read') from None
    if len(data) > cap:
        raise SourceError('PT-KBC-LIMIT', f'the file is larger than the {cap} byte limit')
    return data


def _plain(raw: bytes) -> bytes:
    return gunzip_bounded(raw, DEFAULT_LIMITS.cvrf_doc_bytes) if raw[:2] == b'\x1f\x8b' else raw


def _load_index(ws: Path, rows: list[dict], ports: IndexPorts) -> tuple[ReverseIndex, list[dict]]:
    index = ReverseIndex()
    unreadable = []
    for row in rows:
        try:
            raw = _plain((ws / 'objects' / row['sha256'][:2] / f'{row["sha256"]}.gz').read_bytes())
            if hashlib.sha256(raw).hexdigest() != row['sha256']:
                raise SourceError('PT-KBC-VERIFY', 'the stored bytes no longer match their SHA-256')
            index.add(import_bytes(raw, now=row['imported_at'], advisory=ports.advisory))
        except (SourceError, OSError) as exc:
            reason = exc.message if isinstance(exc, SourceError) else 'the stored object cannot be read'
            unreadable.append({'doc_id': row['doc_id'], 'name': row['name'], 'reason': reason})
    return index, unreadable


def _problems(doc: ImportedDocument) -> list[dict]:
    return [{'doc_id': doc.doc_id, **p.as_dict()} for p in doc.problems if p.level != 'info'][:PROBLEMS_SHOWN]


def _coverage_block(index: ReverseIndex, now: str) -> dict:
    coverage = index.coverage(now=now)
    return {'state': coverage.state, 'text': coverage_text(coverage), 'corpus_digest': index.corpus_digest(),
            'detail': coverage.model_dump(mode='json')}


# ---------------------------------------------------------------------------------------------- verbs

def cmd_import(args, ports: IndexPorts, out) -> int:
    ws = _workspace(args)
    now = ports.now()
    rows = _read_manifest(ws)
    known = {r['doc_id'] for r in rows}
    parsed: list[tuple[ImportedDocument, bytes, str]] = []
    rejected = []
    for path in args.files:
        name = clean_text(path.name, 200)
        try:
            raw = _plain(_read_file(path))
            parsed.append((import_bytes(raw, now=now, advisory=ports.advisory), raw, name))
        except SourceError as exc:
            rejected.append({'file': name, 'code': exc.code, 'message': exc.message})
    if rejected:
        result = {'contract': CONTRACT, 'documents': [], 'rejected': rejected, 'index_changed': False}
        text = '\n'.join(f'rejected {r["file"]}: {r["code"]}: {r["message"]}' for r in rejected) \
            + '\nThe index is unchanged.'
        _emit(out, args, 'failed', result, [], text, error=f'{len(rejected)} file(s) rejected; the index is unchanged')
        print(f'error: {len(rejected)} file(s) rejected; the index is unchanged', file=sys.stderr)
        return ENVIRONMENT
    fresh = []
    seen = set(known)
    for doc, raw, name in parsed:
        if doc.doc_id not in seen:
            seen.add(doc.doc_id)
            fresh.append((doc, raw, name))
    try:
        for doc, raw, _ in fresh:
            target = ws / doc.source.object_path
            if not target.exists():
                _atomic_write(target, gzip.compress(raw, mtime=0))
        if fresh:
            rows += [{'doc_id': d.doc_id, 'sha256': d.source.sha256, 'kind': d.source.kind, 'size': d.source.size,
                      'imported_at': now, 'name': n} for d, _, n in fresh]
            _write_manifest(ws, rows)
    except OSError as exc:
        raise CliError(RUNTIME, f'the workspace cannot be written ({safe_label(type(exc).__name__)})') from None
    index, unreadable = _load_index(ws, rows, ports)
    docs = []
    for doc, _, name in parsed:
        docs.append({**doc.summary(), 'name': name, 'already_present': doc.doc_id in known})
    totals = {k: sum(d[k] for d in docs) for k in ('vulnerabilities', 'edges', 'mention_only', 'disputed', 'edge_rows')}
    problems = [p for doc, _, _ in parsed for p in _problems(doc)][:PROBLEMS_SHOWN]
    result = {'contract': CONTRACT, 'documents': docs, 'rejected': [], 'index_changed': bool(fresh), 'totals': totals,
              'problems': problems, 'unreadable': unreadable, 'coverage': _coverage_block(index, now)}
    lines = [f'{d["name"]}: {d["kind"]} {d["release_id"] or ""} {d["edges"]} edges, {d["mention_only"]} mention-only, '
             f'{d["disputed"]} disputed' + (' (already present)' if d['already_present'] else '') for d in docs]
    lines += [f'{len(fresh)} new document(s); index {"changed" if fresh else "unchanged"}.',
              result['coverage']['text']]
    _emit(out, args, 'complete', result, [], '\n'.join(lines))
    return OK


def cmd_status(args, ports: IndexPorts, out) -> int:
    ws = _workspace(args)
    now = ports.now()
    rows = _read_manifest(ws)
    index, unreadable = _load_index(ws, rows, ports)
    docs = [{**d.summary(), 'name': next((r['name'] for r in rows if r['doc_id'] == d.doc_id), '')}
            for d in index.documents]
    active = index.active_ids()
    for entry in docs:
        entry['active'] = entry['doc_id'] in active
    result = {'contract': CONTRACT, 'documents': docs, 'unreadable': unreadable, 'coverage': _coverage_block(index, now),
              'scopes': [s.model_dump(mode='json') for s in index.scopes()],
              'state': 'empty' if not rows else ('partial' if unreadable else 'ready')}
    if not rows:
        _emit(out, args, 'unavailable', result, [], 'The index is empty: nothing is loaded. Run "kb index import".')
        return NO_RESULTS
    lines = [f'{d["name"]}: {d["kind"]} {d["release_id"] or ""} {d["edges"]} edges, {d["mention_only"]} mention-only'
             + ('' if d['active'] else ' (superseded)') for d in docs]
    lines += [f'unreadable {u["name"]}: {u["reason"]}' for u in unreadable] + [result['coverage']['text']]
    _emit(out, args, 'partial' if unreadable else 'complete', result,
          [f'{len(unreadable)} document(s) unreadable'] if unreadable else [], '\n'.join(lines))
    return RUNTIME if unreadable else OK


def cmd_verify(args, ports: IndexPorts, out) -> int:
    ws = _workspace(args)
    rows = _read_manifest(ws)
    problems = []
    checked = []
    for row in rows:
        path = ws / 'objects' / row['sha256'][:2] / f'{row["sha256"]}.gz'
        entry = {'doc_id': row['doc_id'], 'name': row['name'], 'hash': 'ok', 'parse': 'ok'}
        try:
            raw = _plain(path.read_bytes())
        except (OSError, SourceError):
            entry.update(hash='missing or unreadable', parse='skipped')
            problems.append(f'{row["name"]}: the stored object is missing or unreadable')
            checked.append(entry)
            continue
        if hashlib.sha256(raw).hexdigest() != row['sha256'] or len(raw) != row['size']:
            entry.update(hash='mismatch', parse='skipped')
            problems.append(f'{row["name"]}: the stored bytes differ from the recorded SHA-256 or size')
        elif row['kind'] == 'csaf' and ports.advisory is None:
            entry['parse'] = 'skipped (advisory port not bound)'
        else:
            try:
                doc = import_bytes(raw, now=row['imported_at'], advisory=ports.advisory)
                if doc.doc_id != row['doc_id']:
                    raise SourceError('PT-KBC-VERIFY', 'the document identity changed')
            except SourceError as exc:
                entry['parse'] = f'failed: {exc.message}'
                problems.append(f'{row["name"]}: {exc.message}')
        checked.append(entry)
    listed = {r['sha256'] for r in rows}
    orphans = sorted(p.stem for p in (ws / 'objects').glob('*/*.gz') if p.stem not in listed) \
        if (ws / 'objects').is_dir() else []
    warnings = [f'{len(orphans)} stored object(s) are not listed in the index'] if orphans else []
    result = {'contract': CONTRACT, 'checked': checked, 'problems': problems, 'orphans': orphans,
              'state': 'empty' if not rows else ('damaged' if problems else 'ok')}
    if not rows:
        _emit(out, args, 'unavailable', result, warnings, 'The index is empty: nothing to verify.')
        return NO_RESULTS
    if problems:
        _emit(out, args, 'failed', result, warnings, '\n'.join(problems), error=f'{len(problems)} problem(s) found')
        return RUNTIME
    _emit(out, args, 'complete', result, warnings, f'{len(rows)} document(s) verified: hashes and parses agree.')
    return OK


def cmd_plan(args, ports: IndexPorts, out) -> int:
    now = ports.now()
    now_release = f'{now[:4]}-{MONTHS[int(now[5:7]) - 1]}'
    try:
        if args.months is not None:
            months = [m for m in (p.strip() for p in args.months.split(',')) if m]
        else:
            months = list(net_plan.months_since(args.since, args.until or now_release))
        plan = net_plan.build_plan(months, now_release=now_release, include_index=args.with_index)
    except SourceError as exc:
        raise CliError(ENVIRONMENT, exc.message) from None
    except ValueError:
        raise CliError(ENVIRONMENT, 'invalid month list') from None
    _emit(out, args, 'complete', {'contract': CONTRACT, 'plan': plan.model_dump(mode='json'),
                                  'text': net_plan.render_plan(plan)}, [], net_plan.render_plan(plan))
    return OK


HANDLERS = {'import': cmd_import, 'status': cmd_status, 'verify': cmd_verify, 'plan': cmd_plan}


def main(argv: list[str] | None = None, *, ports: IndexPorts | None = None, stdout=None, stderr=None) -> int:
    """Run ``kb index <verb> ...``. ``argv`` excludes the ``kb index`` prefix."""
    argv = list(sys.argv[1:] if argv is None else argv)
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    ports = ports or IndexPorts()
    args = None
    try:
        args = build_parser().parse_args(argv)
        return HANDLERS[args.action](args, ports, out)
    except CliError as exc:
        print(f'error: {exc}', file=err)
        if '--json' in argv:
            action = args.action if args is not None else next((a for a in argv if a in HANDLERS), '?')
            out.write(json.dumps({'contract': CLI_CONTRACT, 'command': f'kb index {action}', 'status': 'failed',
                                  'result': None, 'warnings': [], 'error': str(exc)}, sort_keys=True) + '\n')
        return exc.code
    except KeyboardInterrupt:
        print('cancelled', file=err)
        return CANCELLED
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    except Exception as exc:  # contract: an unexpected failure is a runtime error, never a bare traceback
        print(f'error: {type(exc).__name__}', file=err)
        if '--json' in argv:
            out.write(json.dumps({'contract': CLI_CONTRACT, 'command': 'kb index', 'status': 'failed',
                                  'result': None, 'warnings': [], 'error': type(exc).__name__}, sort_keys=True)
                      + '\n')
        return RUNTIME

