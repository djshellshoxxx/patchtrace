"""`kb index` verbs: import, status, verify, plan (KB-integration-plan 8.1; slices K1 and K3). Offline: no verb fetches.

An own dispatcher (``main(argv)``, ``build_parser``) for the arguments after ``kb index``; ``kbcorrelation/cli.py``
assembles it into ``kb``. Output follows the ``enrichment-cli/1`` envelope; exit codes: 0 ok, 2 invalid arguments or an
unreadable/malformed local file, 3 runtime failure or a damaged workspace, 4 nothing to report yet (an empty index),
5 cancelled. This module also holds the envelope, parser and ``run_cli`` helpers every ``kb`` verb module shares.

Workspace: K2's :class:`WorkspaceStore` (``kbc.sqlite3`` plus ``objects/<sha[:2]>/<sha>.gz``). The index is rebuilt by
re-parsing the stored objects, so a parser change never leaves stale rows. The K1 interim ``kbc-index.json`` is gone.

``import`` rejects as a whole: every file is parsed and validated first, and a single rejected file leaves the
workspace unchanged. CSAF files need the advisory port (``IndexPorts.advisory``, bound by ``wiring``); without it they
are refused with an explicit message.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
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
from .store import DB_NAME, KbcStoreError, WorkspaceStore
from .store import default_workspace as _default_workspace

CLI_CONTRACT = 'enrichment-cli/1'
OK, ENVIRONMENT, RUNTIME, NO_RESULTS, CANCELLED = 0, 2, 3, 4, 5
PROBLEMS_SHOWN = 50
ARGUMENT_CODES = ('PT-KBC-INPUT', 'PT-KBC-SCOPE', 'PT-KBC-UNSUPPORTED', 'PT-KBC-CONSENT')


class CliError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


class Parser(argparse.ArgumentParser):
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
    winbindex: Callable[[Path, Path, str, str], dict] | None = None  # (workspace, file, name, date) -> summary

    def now(self) -> str:
        return (self.clock or _SystemClock()).now_utc()


def default_workspace(env: dict[str, str] | None = None) -> Path:
    """``%LOCALAPPDATA%\\PatchTrace\\kb``, else ``$XDG_DATA_HOME/PatchTrace/kb``, else ``~/.local/share/PatchTrace/kb``."""
    return _default_workspace(env)


# ---------------------------------------------------------------------------------------------- parser

def add_common(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    parser.add_argument('--workspace', type=Path, help='workspace directory (default: the per-user PatchTrace kb dir)')
    return parser


def build_parser(prog: str = 'patchtrace kb index') -> argparse.ArgumentParser:
    parser = Parser(prog=prog, description='Offline KB reverse index: import local documents, show status, verify, '
                    'and preview (never perform) a sync.')
    sub = parser.add_subparsers(dest='action', required=True, parser_class=Parser)
    imp = add_common(sub.add_parser('import', help='import saved CVRF month or CSAF JSON files (all or nothing)'))
    imp.add_argument('files', nargs='+', type=Path, metavar='FILE')
    imp.add_argument('--winbindex', metavar='NAME', help='FILE is a saved Winbindex record of this file name (for '
                     'example afd.sys), stored for "kb pairs"; one file, .json or .json.gz')
    imp.add_argument('--data-date', metavar='YYYY-MM-DD', help='data date of the Winbindex record (default: today)')
    add_common(sub.add_parser('status', help='list the loaded documents and their coverage'))
    add_common(sub.add_parser('verify', help='re-hash and re-parse every stored document'))
    plan = add_common(sub.add_parser('plan', help='preview the exact requests of a sync (no network)'))
    group = plan.add_mutually_exclusive_group(required=True)
    group.add_argument('--months', metavar='YYYY-MM[,..]', help='comma-separated months (at most 24)')
    group.add_argument('--since', metavar='YYYY-MM', help='every month from here to --until (default: this month)')
    plan.add_argument('--until', metavar='YYYY-MM', help='last month of --since (default: the current month)')
    plan.add_argument('--with-index', action='store_true', help='also list the document-id index request')
    return parser


# ---------------------------------------------------------------------------------------------- output

def emit(out, command: str, as_json: bool, status: str, result, warnings: list[str], text: str,
         error: str | None = None) -> None:
    """One ``enrichment-cli/1`` document (``--json``) or the plain text; the only writer to stdout."""
    if as_json:
        doc = {'contract': CLI_CONTRACT, 'command': command, 'status': status, 'result': result, 'warnings': warnings}
        if error is not None:
            doc['error'] = error
        out.write(json.dumps(doc, sort_keys=True) + '\n')
    else:
        out.write(text + ('\n' if text and not text.endswith('\n') else ''))


def present(out, command: str, args, outcome) -> int:
    """Emit a service ``Outcome`` (envelope or text) and return its exit code; a failure also goes to stderr."""
    emit(out, command, bool(getattr(args, 'json', False)), outcome.status, outcome.result, outcome.warnings,
         outcome.text, outcome.error)
    if outcome.error:
        print(f'error: {outcome.error}', file=sys.stderr)
    return outcome.exit


def _emit(out, args, status: str, result, warnings: list[str], text: str, error: str | None = None) -> None:
    emit(out, f'kb index {args.action}', bool(getattr(args, 'json', False)), status, result, warnings, text, error)


def run_cli(prefix: str, build: Callable[[], argparse.ArgumentParser], handlers: dict, argv: list[str], *, ports,
            stdout=None, stderr=None) -> int:
    """Parse ``argv`` and run ``handlers[args.action](args, ports, out)``; every failure becomes an envelope and an
    exit code (2 arguments, 3 runtime, 5 cancelled), never a traceback."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    args = None

    def failed(status: str, message: str | None) -> None:
        if '--json' not in argv:
            return
        action = args.action if args is not None else next((a for a in argv if a in handlers), '?')
        doc = {'contract': CLI_CONTRACT, 'command': f'{prefix} {action}', 'status': status, 'result': None,
               'warnings': []}
        if message is not None:
            doc['error'] = message
        out.write(json.dumps(doc, sort_keys=True) + '\n')

    try:
        args = build().parse_args(argv)
        return handlers[args.action](args, ports, out)
    except CliError as exc:
        print(f'error: {exc}', file=err)
        failed('failed', str(exc))
        return exc.code
    except KbcStoreError as exc:
        print(f'error: {exc.code}: {exc.message}', file=err)
        failed('failed', f'{exc.code}: {exc.message}')
        return ENVIRONMENT if exc.code in ARGUMENT_CODES else RUNTIME
    except KeyboardInterrupt:
        print('cancelled', file=err)
        failed('cancelled', None)
        return CANCELLED
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    except Exception as exc:  # contract: an unexpected failure is a runtime error, never a bare traceback
        print(f'error: {type(exc).__name__}', file=err)
        failed('failed', type(exc).__name__)
        return RUNTIME


# ---------------------------------------------------------------------------------------------- workspace

def workspace_root(args) -> Path:
    return (args.workspace or default_workspace()).expanduser()


def open_existing(root: Path) -> WorkspaceStore | None:
    """The workspace if it exists (read verbs never create one), else None."""
    return WorkspaceStore(root, create=False) if (root / DB_NAME).is_file() else None


def read_input_file(path: Path) -> bytes:
    cap = DEFAULT_LIMITS.cvrf_doc_bytes
    try:
        with open(path, 'rb') as handle:
            data = handle.read(cap + 1)
    except OSError:
        raise SourceError('PT-KBC-INPUT', 'the file cannot be read') from None
    if len(data) > cap:
        raise SourceError('PT-KBC-LIMIT', f'the file is larger than the {cap} byte limit')
    return data


def plain_bytes(raw: bytes) -> bytes:
    return gunzip_bounded(raw, DEFAULT_LIMITS.cvrf_doc_bytes) if raw[:2] == b'\x1f\x8b' else raw


def label_of(source) -> str:
    return f'{source.kind} {source.release_id}' if source.release_id else f'{source.kind} {source.doc_id[:12]}'


def load_index(ws: WorkspaceStore, ports: IndexPorts) -> tuple[ReverseIndex, list[dict]]:
    """Rebuild the index document by document; a damaged one is reported and left out, never hiding the others."""
    index = ReverseIndex()
    unreadable = []
    for source in ws.sources():
        try:
            raw = ws.read_object(source.sha256)
            doc = import_bytes(raw, now=source.retrieved_at, advisory=ports.advisory, limits=ws.limits)
            if doc.doc_id != source.doc_id:
                raise SourceError('PT-KBC-VERIFY', 'the document identity changed')
            index.add(doc)
        except (SourceError, KbcStoreError) as exc:
            unreadable.append({'doc_id': source.doc_id, 'name': label_of(source), 'reason': exc.message})
    return index, unreadable


def _problems(doc: ImportedDocument) -> list[dict]:
    return [{'doc_id': doc.doc_id, **p.as_dict()} for p in doc.problems if p.level != 'info'][:PROBLEMS_SHOWN]


def coverage_block(index: ReverseIndex, now: str) -> dict:
    coverage = index.coverage(now=now)
    return {'state': coverage.state, 'text': coverage_text(coverage), 'corpus_digest': index.corpus_digest(),
            'detail': coverage.model_dump(mode='json')}


# ---------------------------------------------------------------------------------------------- verbs

def _import_winbindex(args, ports: IndexPorts, out) -> int:
    if ports.winbindex is None:
        raise CliError(ENVIRONMENT, 'Winbindex records are not supported by this build')
    if len(args.files) != 1:
        raise CliError(ENVIRONMENT, '--winbindex takes exactly one record file')
    try:
        summary = ports.winbindex(workspace_root(args), args.files[0], args.winbindex,
                                  args.data_date or ports.now()[:10])
    except KbcStoreError as exc:
        _emit(out, args, 'failed', {'contract': CONTRACT, 'winbindex': None, 'index_changed': False}, [],
              f'rejected {clean_text(args.files[0].name, 200)}: {exc.code}: {exc.message}\nThe index is unchanged.',
              error=f'{exc.code}: {exc.message}')
        print(f'error: {exc.code}: {exc.message}', file=sys.stderr)
        return ENVIRONMENT if exc.code in (*ARGUMENT_CODES, 'PT-KBC-LIMIT') else RUNTIME
    text = (f'{summary["stored_as"]}: {summary["rows"]} build row(s), {summary["skipped"]} entr(ies) skipped'
            + (' (replaced)' if summary['replaced'] else '') + '.')
    _emit(out, args, 'complete', {'contract': CONTRACT, 'winbindex': summary, 'index_changed': True},
          summary['warnings'], text)
    return OK


def cmd_import(args, ports: IndexPorts, out) -> int:
    if args.winbindex:
        return _import_winbindex(args, ports, out)
    if args.data_date:
        raise CliError(ENVIRONMENT, '--data-date applies only with --winbindex')
    root = workspace_root(args)
    now = ports.now()
    parsed: list[tuple[ImportedDocument, bytes, str]] = []
    rejected = []
    for path in args.files:
        name = clean_text(path.name, 200)
        try:
            raw = plain_bytes(read_input_file(path))
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
    with WorkspaceStore(root) as ws:
        known = {s.doc_id for s in ws.sources()}
        added: set[str] = set()
        try:
            for doc, raw, _ in parsed:
                if doc.doc_id not in known and doc.doc_id not in added and ws.add_document(doc, raw):
                    added.add(doc.doc_id)
        except OSError as exc:
            raise CliError(RUNTIME, f'the workspace cannot be written ({safe_label(type(exc).__name__)})') from None
        index, unreadable = load_index(ws, ports)
    docs = [{**doc.summary(), 'name': name, 'already_present': doc.doc_id in known} for doc, _, name in parsed]
    totals = {k: sum(d[k] for d in docs) for k in ('vulnerabilities', 'edges', 'mention_only', 'disputed', 'edge_rows')}
    problems = [p for doc, _, _ in parsed for p in _problems(doc)][:PROBLEMS_SHOWN]
    result = {'contract': CONTRACT, 'documents': docs, 'rejected': [], 'index_changed': bool(added), 'totals': totals,
              'problems': problems, 'unreadable': unreadable, 'coverage': coverage_block(index, now)}
    lines = [f'{d["name"]}: {d["kind"]} {d["release_id"] or ""} {d["edges"]} edges, {d["mention_only"]} mention-only, '
             f'{d["disputed"]} disputed' + (' (already present)' if d['already_present'] else '') for d in docs]
    lines += [f'{len(added)} new document(s); index {"changed" if added else "unchanged"}.',
              result['coverage']['text']]
    _emit(out, args, 'complete', result, [], '\n'.join(lines))
    return OK


def cmd_status(args, ports: IndexPorts, out) -> int:
    now = ports.now()
    ws = open_existing(workspace_root(args))
    try:
        sources = ws.sources() if ws else ()
        index, unreadable = load_index(ws, ports) if ws else (ReverseIndex(), [])
    finally:
        if ws:
            ws.close()
    names = {s.doc_id: label_of(s) for s in sources}
    active = index.active_ids()
    docs = [{**d.summary(), 'name': names.get(d.doc_id, ''), 'active': d.doc_id in active} for d in index.documents]
    result = {'contract': CONTRACT, 'documents': docs, 'unreadable': unreadable,
              'coverage': coverage_block(index, now), 'scopes': [s.model_dump(mode='json') for s in index.scopes()],
              'state': 'empty' if not sources else ('partial' if unreadable else 'ready')}
    if not sources:
        _emit(out, args, 'unavailable', result, [], 'The index is empty: nothing is loaded. Run "kb index import".')
        return NO_RESULTS
    lines = [f'{d["name"]}: {d["kind"]} {d["release_id"] or ""} {d["edges"]} edges, {d["mention_only"]} mention-only'
             + ('' if d['active'] else ' (superseded)') for d in docs]
    lines += [f'unreadable {u["name"]}: {u["reason"]}' for u in unreadable] + [result['coverage']['text']]
    _emit(out, args, 'partial' if unreadable else 'complete', result,
          [f'{len(unreadable)} document(s) unreadable'] if unreadable else [], '\n'.join(lines))
    return RUNTIME if unreadable else OK


def _verify_one(ws: WorkspaceStore, source, ports: IndexPorts, problems: list[str]) -> dict:
    name = label_of(source)
    entry = {'doc_id': source.doc_id, 'name': name, 'hash': 'ok', 'parse': 'ok'}
    try:
        raw = ws.read_object(source.sha256)
    except KbcStoreError as exc:
        entry.update(hash='missing or unreadable' if exc.code == 'PT-KBC-STORAGE' else 'mismatch', parse='skipped')
        problems.append(f'{name}: {exc.message}')
        return entry
    if len(raw) != source.size:
        entry.update(hash='mismatch', parse='skipped')
        problems.append(f'{name}: the stored bytes differ from the recorded SHA-256 or size')
    elif source.kind == 'csaf' and ports.advisory is None:
        entry['parse'] = 'skipped (advisory port not bound)'
    else:
        try:
            doc = import_bytes(raw, now=source.retrieved_at, advisory=ports.advisory, limits=ws.limits)
            if doc.doc_id != source.doc_id:
                raise SourceError('PT-KBC-VERIFY', 'the document identity changed')
        except SourceError as exc:
            entry['parse'] = f'failed: {exc.message}'
            problems.append(f'{name}: {exc.message}')
    return entry


def cmd_verify(args, ports: IndexPorts, out) -> int:
    ws = open_existing(workspace_root(args))
    problems: list[str] = []
    try:
        sources = ws.sources() if ws else ()
        checked = [_verify_one(ws, s, ports, problems) for s in sources]
        orphans = list(ws.unreferenced_objects()) if ws else []
    finally:
        if ws:
            ws.close()
    warnings = [f'{len(orphans)} stored object(s) are not listed in the index'] if orphans else []
    result = {'contract': CONTRACT, 'checked': checked, 'problems': problems, 'orphans': orphans,
              'state': 'empty' if not sources else ('damaged' if problems else 'ok')}
    if not sources:
        _emit(out, args, 'unavailable', result, warnings, 'The index is empty: nothing to verify.')
        return NO_RESULTS
    if problems:
        _emit(out, args, 'failed', result, warnings, '\n'.join(problems), error=f'{len(problems)} problem(s) found')
        return RUNTIME
    _emit(out, args, 'complete', result, warnings, f'{len(sources)} document(s) verified: hashes and parses agree.')
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
    return run_cli('kb index', build_parser, HANDLERS, argv, ports=ports or IndexPorts(), stdout=stdout,
                   stderr=stderr)
