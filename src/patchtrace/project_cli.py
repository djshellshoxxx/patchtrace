"""`patchtrace project`: the headless project lifecycle (docs/specs/cli-project-compare.md section 3).

Qt-free dispatcher over `ProjectService`; `cli_commands/project.py` is the registry adapter. Leaves: create, sample,
info, runs, import-json, backup, swap. Envelope `enrichment-cli/1`; exit codes 0 ok, 2 invalid arguments, input or
environment, 3 runtime or storage failure (a locked project included), 4 no runs recorded, 5 cancelled. No input
file is executed or modified, nothing is fetched and nothing prompts. `info` and `runs` change no project byte
except the advisory lock file.
"""
from __future__ import annotations

import re
import threading
from argparse import ArgumentParser, Namespace, _SubParsersAction
from collections import Counter
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, get_args

from .cli import ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, _emit
from .hostile_text import escape_text

LOCK_FILE = '.patchtrace.lock'
TEXT_LIMIT = 300
TOOL_KEYS = ('ghidra_version', 'python_version', 'pyghidra_version', 'java_runtime_version')
DERIVED_KIND_LIMIT = 64
SWAP_EFFECT = ('the older and the newer artifact exchange sides, every match is mirrored (added <-> removed, '
               'split <-> merged), the project revision rises by one and every interpretation, finding and '
               'annotation (notes, bookmarks, manual-correction records) is marked stale; analysis runs and '
               'preserved raw results are kept')
_LOCKED = 'project is locked by another writer'
_ERROR_CODE = re.compile(r'(PT-[A-Z0-9]+(?:-[A-Z0-9]+)*):')


def safe(value: object, limit: int = TEXT_LIMIT) -> str:
    """Untrusted text for one terminal line: control and bidirectional characters escaped, length bounded."""
    text = escape_text(str(value))
    return text if len(text) <= limit else text[:limit - 3] + '...'


def open_error(exc: ValueError) -> CliError:
    """A held lock is a runtime condition (exit 3) and names the lock file; any other refusal is the analyst's."""
    message = str(exc)
    if _LOCKED in message:
        return CliError(RUNTIME, f'{message} (lock file {LOCK_FILE} in the project directory: close the desktop '
                        'window or the other patchtrace process that has this project open, then retry; do not '
                        'delete the lock file)')
    return CliError(ENVIRONMENT, message)


def _os_error(exc: OSError, what: str, code: int = ENVIRONMENT) -> CliError:
    return CliError(code, f'PT-STORAGE: {what} ({exc.strerror or type(exc).__name__})')  # no absolute path


def commit_error(exc: Exception) -> CliError:
    """A refusal raised while a project is changed: storage failures exit 3, rejected input exits 2."""
    if isinstance(exc, OSError):
        return _os_error(exc, 'project files cannot be written', RUNTIME)
    message = str(exc)
    if not message.startswith('PT-'):  # a contract violation reported by the model layer; its text quotes the input
        return CliError(ENVIRONMENT, f'PT-SCHEMA: the input violates the analysis contract ({type(exc).__name__})')
    return CliError(RUNTIME if message.startswith('PT-STORAGE') else ENVIRONMENT, message)


@contextmanager
def open_service(path: Path) -> Iterator[Any]:
    """The writer's view of a project (`ProjectService.open`), closed on exit."""
    from .service import ProjectService
    try:
        service = ProjectService.open(path)
    except ValueError as exc:
        raise open_error(exc) from None
    except OSError as exc:
        raise _os_error(exc, 'project cannot be opened') from None
    try:
        yield service
    finally:
        service.close()


@contextmanager
def open_reader(path: Path) -> Iterator[tuple[Any, Any]]:
    """(store, project) for a read-only leaf: no legacy cleanup and no interrupted-run repair, so nothing is saved."""
    from .persistence import ProjectStore
    try:
        store = ProjectStore(path)
    except ValueError as exc:
        raise open_error(exc) from None
    except OSError as exc:
        raise _os_error(exc, 'project cannot be opened') from None
    try:
        try:
            project = store.load(recover_interrupted=False)
        except ValueError as exc:
            raise open_error(exc) from None
        yield store, project
    finally:
        store.close()


def _tally(values: Iterable[str], model: type, field: str) -> dict[str, int]:
    """Counts for every value the contract allows for `model.field`, zero included, in contract order."""
    counts = Counter(values)
    return {key: counts.get(key, 0) for key in get_args(model.model_fields[field].annotation)}


def _nonzero(counts: dict[str, int]) -> str:
    return ', '.join(f'{key} {count}' for key, count in counts.items() if count)


def counted(total: int, counts: dict[str, int]) -> str:
    return f'{total} ({_nonzero(counts)})' if total else '0'


def artifacts(project) -> list[dict[str, Any]]:
    return [{'side': a.side, 'name': a.name, 'size': a.size, 'sha256': a.sha256}
            for a in sorted(project.artifacts, key=lambda a: a.side != 'older')]


def match_counts(project) -> dict[str, Any]:
    from .models import FunctionMatch
    return {'total': len(project.matches),
            'by_category': _tally((m.category for m in project.matches), FunctionMatch, 'category')}


def latest_completed(project) -> str | None:
    return next((run.id for run in reversed(project.runs) if run.status == 'completed'), None)


def error_code(error: str | None) -> str | None:
    found = _ERROR_CODE.match(error or '')
    return found.group(1) if found else None


def _artifact_lines(rows: list[dict[str, Any]]) -> list[str]:
    return [f'{a["side"]}: {safe(a["name"])} {a["sha256"]} ({a["size"]} bytes)' for a in rows]


# --- create, sample -----------------------------------------------------------------------------------------

def _check_new_directory(root: Path) -> None:
    from .persistence import creation_directory_available
    if (root / 'project.sqlite3').exists():
        raise CliError(ENVIRONMENT, 'project directory already contains a project')  # as `acquire fetch`
    if not creation_directory_available(root):
        raise CliError(ENVIRONMENT, 'the project directory must be absent or empty')


def _new_project(args: Namespace, command: str, make) -> int:
    _check_new_directory(args.project)
    try:
        service = make()
    except ValueError as exc:  # the service has already rolled its partial files back
        raise open_error(exc) from None
    except OSError as exc:
        raise _os_error(exc, 'project cannot be created') from None
    try:
        project = service.project
        result = {'project': str(service.root), 'project_id': project.id, 'name': project.name,
                  'revision': project.revision, 'artifacts': artifacts(project),
                  'identical': len({a.sha256 for a in project.artifacts}) == 1}
        lines = _artifact_lines(result['artifacts'])
        lines.append(f'project: {safe(service.root, 4000)} (id {project.id})')
        if project.sample:
            result |= {'sample': True, 'run_id': project.runs[-1].id, 'matches': match_counts(project)}
            lines.append(f'Synthetic sample: authored fixtures and an authored result with {len(project.matches)} '
                         'matches; no engine and no model was run.')
        elif result['identical']:
            lines.append('The two inputs are identical (same SHA-256): an identical run was recorded and there is '
                         'nothing to compare.')
    finally:
        service.close()
    lines.append('Inputs were copied and hash-verified; they were not executed or modified.')
    _emit(args, command, 'complete', result, [], '\n'.join(lines))
    return OK


def _create(args: Namespace, cancel: threading.Event) -> int:
    from .service import ProjectService
    return _new_project(args, 'project create',
                        lambda: ProjectService.create(args.older, args.newer, args.name, args.project))


def _sample(args: Namespace, cancel: threading.Event) -> int:
    from .service import ProjectService
    return _new_project(args, 'project sample', lambda: ProjectService.sample(args.project))


# --- info ---------------------------------------------------------------------------------------------------

def _derived(connection) -> dict[str, dict[str, int]]:
    """Enrichment entries per kind. The table is read if it exists and never created here."""
    import sqlite3
    try:
        if connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'"
                              ).fetchone() is None:
            return {}
        rows = connection.execute('SELECT kind, COUNT(*), SUM(stale) FROM enrichment_entries GROUP BY kind '
                                  f'ORDER BY kind LIMIT {DERIVED_KIND_LIMIT}').fetchall()
    except sqlite3.Error:
        raise CliError(RUNTIME, 'PT-STORAGE: derived results cannot be read from the project database') from None
    return {str(kind): {'entries': int(count), 'stale': int(stale or 0)} for kind, count, stale in rows}


def _summary(store, project) -> dict[str, Any]:
    from .models import AnalysisRun, AnalystAnnotation, Finding, FunctionMatch
    findings = [finding for run in project.interpretations for finding in run.findings]
    rows = artifacts(project)
    by_side = {a.side: a for a in project.artifacts}
    for row in rows:
        row |= {'format': by_side[row['side']].format, 'architecture': by_side[row['side']].architecture}
    kinds = get_args(AnalystAnnotation.model_fields['kind'].annotation)
    return {
        'project': {'id': project.id, 'name': project.name, 'created': project.created,
                    'revision': project.revision, 'schema_version': project.schema_version,
                    'database_version': store.connection.execute('PRAGMA user_version').fetchone()[0],
                    'sample': project.sample},
        'artifacts': rows,
        'orientation': {row['side']: row['sha256'] for row in rows},
        'runs': {'total': len(project.runs), 'latest_completed': latest_completed(project),
                 'by_status': _tally((r.status for r in project.runs), AnalysisRun, 'status')},
        'matches': match_counts(project) | {
            'by_review': _tally((m.review for m in project.matches), FunctionMatch, 'review'),
            'manual': sum(m.manual for m in project.matches)},
        'findings': {'total': len(findings), 'interpretations': len(project.interpretations),
                     'by_review': _tally((f.review for f in findings), Finding, 'review'),
                     'stale': sum(f.stale for f in findings)},
        'annotations': {kind: {'total': sum(a.kind == kind for a in project.annotations),
                               'stale': sum(a.kind == kind and a.stale for a in project.annotations)}
                        for kind in kinds},
        'derived': _derived(store.connection)}


def _summary_text(result: dict[str, Any]) -> str:
    project, runs, matches = result['project'], result['runs'], result['matches']
    findings, notes = result['findings'], result['annotations']
    review = f'; review: {_nonzero(matches["by_review"])}; manual {matches["manual"]}' if matches['total'] else ''
    derived = ', '.join(f'{safe(kind, 40)} {row["entries"]} ({row["stale"]} stale)'
                        for kind, row in result['derived'].items()) or 'none stored'
    lines = [f'project: {safe(project["name"])} (id {safe(project["id"], 128)}; revision {project["revision"]})',
             f'contract: snapshot schema {project["schema_version"]}, database version '
             f'{project["database_version"]}; created {safe(project["created"], 40)}; synthetic sample: '
             f'{"yes" if project["sample"] else "no"}',
             *(f'{line}, {a["format"]} {a["architecture"]}' for line, a in
               zip(_artifact_lines(result['artifacts']), result['artifacts'], strict=True)),
             f'runs: {counted(runs["total"], runs["by_status"])}; latest completed: '
             f'{safe(runs["latest_completed"], 128) if runs["latest_completed"] else "none"}',
             f'matches: {counted(matches["total"], matches["by_category"])}{review}',
             f'findings: {counted(findings["total"], findings["by_review"])} in {findings["interpretations"]} '
             f'interpretation(s); stale {findings["stale"]}',
             f'annotations: notes {notes["note"]["total"]}, bookmarks {notes["bookmark"]["total"]}, manual '
             f'corrections {notes["match-override"]["total"]}, validation records {notes["validation"]["total"]}; '
             f'stale {sum(row["stale"] for row in notes.values())}',
             f'derived results: {derived}']
    return '\n'.join(lines)


def _info(args: Namespace, cancel: threading.Event) -> int:
    with open_reader(args.project) as (store, project):
        result = _summary(store, project)
    _emit(args, 'project info', 'complete', result, [], _summary_text(result))
    return OK


# --- runs ---------------------------------------------------------------------------------------------------

def output_dir(root: Path, run_id: str) -> str | None:
    """`runs/<id>` or `runs/quarantine-<id>` when it exists; only a canonical UUID is ever joined to the root."""
    from uuid import UUID

    from .ingestion import safe_path
    try:
        if str(UUID(run_id)) != run_id:
            return None
        return next((name for name in (f'runs/{run_id}', f'runs/quarantine-{run_id}')
                     if safe_path(root, name).is_dir()), None)
    except (ValueError, OSError):
        return None


def _run_row(run, root: Path, current: str | None) -> dict[str, Any]:
    output = output_dir(root, run.id)
    return {'id': run.id, 'status': run.status, 'backend': run.backend, 'backend_version': run.backend_version,
            'created': run.created,
            'tools': {key: run.settings[key] for key in TOOL_KEYS if isinstance(run.settings.get(key), str)},
            'error': run.error, 'error_code': error_code(run.error), 'raw_path': run.raw_path,
            'raw_sha256': run.raw_sha256, 'output_dir': output,
            'quarantined': bool(output and output.startswith('runs/quarantine-')),
            'current': run.id == current}


def _runs_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return 'No analysis runs recorded.'
    lines = [f'  {"run":<36}  {"status":<9}  {"backend":<16}  {"version":<14}  {"recorded":<32}  result']
    for row in rows:
        where = row['raw_path'] or row['output_dir']
        lines.append(f'{"*" if row["current"] else " "} {safe(row["id"], 128):<36}  {row["status"]:<9}  '
                     f'{safe(row["backend"], 24):<16}  {safe(row["backend_version"], 24):<14}  '
                     f'{safe(row["created"], 40):<32}  {safe(where) if where else "-"}')
        if row['error']:
            lines.append(f'    error: {safe(row["error"])}')
    return '\n'.join(lines)


def _runs(args: Namespace, cancel: threading.Event) -> int:
    with open_reader(args.project) as (store, project):
        current = latest_completed(project)
        rows = [_run_row(run, store.root, current) for run in reversed(project.runs)]
    _emit(args, 'project runs', 'complete', {'runs': rows, 'latest_completed': current}, [], _runs_text(rows))
    return OK if rows else NO_RESULTS


# --- import-json --------------------------------------------------------------------------------------------

def _import_json(args: Namespace, cancel: threading.Event) -> int:
    with open_service(args.project) as service:
        runs_dir = service.root / 'runs'
        had_runs_dir = runs_dir.exists()
        try:
            prepared = service.prepare_import(args.file)
        except (ValueError, OSError) as exc:
            raise commit_error(exc) from None
        try:
            service.apply_import(prepared)
        except BaseException as exc:  # Ctrl+C included: a staged raw copy must not outlive a refused import
            service.discard_import(prepared)
            if not had_runs_dir:
                try:
                    runs_dir.rmdir()  # only when the refused import created it and it is empty again
                except OSError:
                    pass
            if isinstance(exc, ValueError | OSError):
                raise commit_error(exc) from None
            raise
        project, run = service.project, prepared.run
        result = {'run_id': run.id, 'backend': run.backend, 'revision': project.revision,
                  'raw_path': run.raw_path, 'raw_sha256': run.raw_sha256, 'matches': match_counts(project)}
    text = (f'imported run {run.id} ({run.backend}); project revision {result["revision"]}\n'
            f'matches: {counted(result["matches"]["total"], result["matches"]["by_category"])}\n'
            f'raw result preserved: {safe(run.raw_path)} sha256 {run.raw_sha256}')
    _emit(args, 'project import-json', 'complete', result, [], text)
    return OK


# --- backup -------------------------------------------------------------------------------------------------

def _verify_backup(path: Path, source) -> None:
    """Re-open the copy read-only: integrity check, snapshot hash, artifact and raw hashes, same snapshot."""
    from .persistence import ProjectStore
    try:
        store = ProjectStore(path)
        try:
            copy = store.load(recover_interrupted=False)
        finally:
            store.close()
        if copy != source:
            raise ValueError('the copied snapshot differs from the source project')
    except (ValueError, OSError) as exc:
        reason = str(exc).removeprefix('PT-STORAGE: ').removeprefix('PT-SCHEMA: ')
        raise CliError(RUNTIME, f'PT-STORAGE: backup did not verify and must not be relied on ({reason}); the copy '
                       f'was left at {path} for inspection') from None


def _backup(args: Namespace, cancel: threading.Event) -> int:
    with open_service(args.project) as service:
        try:
            destination = args.out.resolve()
            unusable = destination.exists() or destination.is_relative_to(service.root)
        except OSError as exc:
            raise _os_error(exc, 'backup destination cannot be checked') from None
        if unusable:
            raise CliError(ENVIRONMENT, 'PT-STORAGE: backup destination must be new and outside project')
        try:
            path = service.backup(destination)
        except ValueError as exc:
            raise CliError(RUNTIME, str(exc)) from None
        except OSError as exc:
            raise _os_error(exc, 'backup could not be written', RUNTIME) from None
        source = service.project
    _verify_backup(path, source)
    result = {'backup': str(path), 'project_id': source.id, 'revision': source.revision, 'verified': True}
    text = (f'backup: {safe(path, 4000)}\nverified: the copy was re-opened (database integrity, snapshot hash, '
            f'artifact and raw-result hashes) and holds revision {source.revision} of project {source.id}')
    _emit(args, 'project backup', 'complete', result, [], text)
    return OK


# --- swap ---------------------------------------------------------------------------------------------------

def _swap(args: Namespace, cancel: threading.Event) -> int:
    if not args.confirm:
        raise CliError(ENVIRONMENT, f'PT-CLI-CONFIRM: `project swap` changes the project: {SWAP_EFFECT}. '
                       'Re-run with --confirm to do it.')
    with open_service(args.project) as service:
        before = service.project
        invalidated = {'interpretations': sum(not run.context.stale for run in before.interpretations),
                       'findings': sum(not f.stale for run in before.interpretations for f in run.findings),
                       'annotations': sum(not a.stale for a in before.annotations)}
        try:
            service.swap_orientation()
        except (ValueError, OSError) as exc:
            raise commit_error(exc) from None
        project = service.project
        result = {'revision': project.revision, 'artifacts': artifacts(project), 'matches': match_counts(project),
                  'invalidated': invalidated}
    lines = ['older and newer exchanged:', *_artifact_lines(result['artifacts']),
             f'project revision {result["revision"]}; {result["matches"]["total"]} matches mirrored; marked stale: '
             f'{invalidated["interpretations"]} interpretation(s), {invalidated["findings"]} finding(s), '
             f'{invalidated["annotations"]} annotation(s)']
    _emit(args, 'project swap', 'complete', result, [], '\n'.join(lines))
    return OK


# --- parser and dispatch ------------------------------------------------------------------------------------

_LEAVES = {'create': _create, 'sample': _sample, 'info': _info, 'runs': _runs, 'import-json': _import_json,
           'backup': _backup, 'swap': _swap}


def register(sub: _SubParsersAction, common, handlers: dict) -> ArgumentParser:
    handlers['project'] = dispatch
    parser = sub.add_parser('project', help='create, inspect, import into, back up and re-orient a project',
                            description='Project lifecycle without the desktop. Input files are copied and '
                            'hash-verified, never executed or modified; nothing is fetched and nothing prompts.')
    leaves = parser.add_subparsers(dest='action', required=True, metavar='ACTION')

    def leaf(name: str, summary: str) -> ArgumentParser:
        added = common(leaves.add_parser(name, help=summary, description=summary))
        added.set_defaults(command_label=f'project {name}')
        return added

    create = leaf('create', 'create a project from an older and a newer PE file (static checks only)')
    create.add_argument('--older', type=Path, required=True, metavar='FILE', help='the older build')
    create.add_argument('--newer', type=Path, required=True, metavar='FILE', help='the newer build')
    create.add_argument('--project', type=Path, required=True, metavar='DIR', help='new project directory')
    create.add_argument('--name', default='', help='project name (default: Untitled comparison)')
    sample = leaf('sample', 'create the synthetic sample project (authored fixtures; no engine is run)')
    sample.add_argument('--project', type=Path, required=True, metavar='DIR', help='new project directory')
    leaf('info', 'read-only summary: artifacts, runs, matches, findings, notes, derived results'
         ).add_argument('project', type=Path)
    leaf('runs', 'list every recorded analysis run, newest first (read-only)').add_argument('project', type=Path)
    imported = leaf('import-json', 'import an existing Ghidriff JSON result for exactly this pair')
    imported.add_argument('project', type=Path)
    imported.add_argument('file', type=Path, metavar='FILE', help='Ghidriff JSON (strict JSON, at most 100 MiB)')
    backup = leaf('backup', 'write a complete, verified copy of the project to a new directory')
    backup.add_argument('project', type=Path)
    backup.add_argument('--out', type=Path, required=True, metavar='DIR',
                        help='backup directory; must not exist and must be outside the project')
    swap = leaf('swap', 'exchange older and newer (marks interpretations, findings and annotations stale)')
    swap.add_argument('project', type=Path)
    swap.add_argument('--confirm', action='store_true', help='required: confirms the change (there is no prompt)')
    return parser


def dispatch(args: Namespace, cancel: threading.Event) -> int:
    return _LEAVES[args.action](args, cancel)
