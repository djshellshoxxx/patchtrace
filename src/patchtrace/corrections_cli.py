"""`patchtrace corrections list|export|import|undo` (docs/specs/manual-corrections-exchange.md section 5). No Qt.

Output is the `enrichment-cli/1` envelope; with `--json` stdout carries exactly one document. Exit codes: 0 done;
2 invalid arguments, a project that cannot be opened, and every refusal of the exchange rules
(`PT-CORR-*`); 3 storage, lock or write failure; 4 nothing to report (no manual correction to list or to undo);
5 cancelled. Nothing is executed, no network is used and nothing is asked: confirmation is a flag. Every change of
the project goes through `ProjectService`; an import is one commit or none.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import tempfile
from pathlib import Path

from . import corrections_exchange as exchange
from .cli_commands import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, emit
from .hostile_text import escape_text

SUMMARY = 'manual match corrections: list, export, import, undo'
_COLUMNS = ('#', 'category', 'review', 'older', 'newer', 'undo', 'note')


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('corrections', help=SUMMARY)
    actions = parser.add_subparsers(dest='action', required=True)

    def leaf(name: str, help_: str) -> argparse.ArgumentParser:
        item = actions.add_parser(name, help=help_)
        item.set_defaults(command_label=f'corrections {name}')
        item.add_argument('project', type=Path, help='project directory')
        item.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return item

    leaf('list', 'the manual corrections of the project (reads only)')
    item = leaf('export', f'write the corrections as a {exchange.CONTRACT} document')
    item.add_argument('--out', type=Path, required=True, metavar='FILE')
    item.add_argument('--include-review', action='store_true',
                      help='also write the review state of relations and findings')
    item = leaf('import', 'apply a document to a project of the same two files: all of it or nothing')
    item.add_argument('file', type=Path, metavar='FILE')
    item.add_argument('--dry-run', action='store_true', help='check everything and report; write nothing')
    item = leaf('undo', 'restore the relations a correction replaced (default: the latest correction)')
    item.add_argument('--annotation', metavar='ID', help='the correction record to undo (see `corrections list --json`)')
    return parser


def open_project(path: Path):
    """`cli._open` without the legacy raw cleanup: a leaf that reads, or that refuses its input, changes no file."""
    from .persistence import ProjectStore
    from .project_cli import open_error
    from .service import ProjectService
    try:
        store = ProjectStore(path)
        try:
            return ProjectService(store.root, store.load(recover_interrupted=False), store)
        except BaseException:
            store.close()
            raise
    except ValueError as exc:
        raise open_error(exc) from None
    except OSError as exc:  # e.g. a path that is too long: no absolute directory in the message
        raise CliError(ENVIRONMENT, f'PT-STORAGE: project cannot be opened ({exc.strerror or type(exc).__name__})') from None


def service_error(exc: ValueError) -> CliError:
    """A refusal by the service is the caller's input (2); a store that could not write is a runtime failure (3)."""
    text = exchange.service_text(exc)
    return CliError(RUNTIME if text.startswith('PT-STORAGE') else ENVIRONMENT, text)


def _cell(text: object, width: int) -> str:
    shown = escape_text(str(text))  # per field: a line break inside a note must not start a new row
    return shown if len(shown) <= width else shown[:width - 3] + '...'


def _members(members: list[dict]) -> str:
    return ', '.join(f'{member["name"]}@{member["address"] or "?"}' for member in members) or '-'


def _table(rows: list[dict]) -> list[str]:
    cells = [_COLUMNS] + [(str(row['index']), row['category'], row['review'], _cell(_members(row['older']), 60),
                           _cell(_members(row['newer']), 60), 'yes' if row['undoable'] else 'no',
                           _cell(row['note'], 160)) for row in rows]
    widths = [max(len(line[column]) for line in cells) for column in range(len(_COLUMNS) - 1)]
    return ['  '.join([*(value.ljust(width) for value, width in zip(line, widths, strict=False)), line[-1]]).rstrip()
            for line in cells]


def _list(args, cancel) -> int:
    service = open_project(args.project)
    try:
        project = service.project
        rows = exchange.list_corrections(project)
        superseded = sum(a.kind == 'match-override' and a.stale for a in project.annotations)
        pair = exchange.pair_of(project).model_dump(mode='json')
    finally:
        service.close()
    result = {'pair': pair, 'corrections': rows, 'superseded_records': superseded}
    if not rows:
        emit(args, 'corrections list', 'complete', result, [], 'No manual corrections.')
        return NO_RESULTS
    lines = [f'Manual corrections: {len(rows)} (older {pair["older_sha256"][:16]}, newer {pair["newer_sha256"][:16]})',
             *_table(rows)]
    latest = next((row for row in rows if row['undoable']), None)
    lines.append(f'Row {latest["index"]} can be undone: patchtrace corrections undo PROJECT' if latest else
                 'No correction can be undone: the records are superseded by a later change of the project.')
    emit(args, 'corrections list', 'complete', result, [], '\n'.join(lines))
    return OK


def _destination(out: Path, project_root: Path) -> Path:
    if out.is_dir():
        raise CliError(ENVIRONMENT, 'PT-CORR-OUTPUT: --out names a directory; give a file name')
    if out.resolve().is_relative_to(project_root):
        raise CliError(ENVIRONMENT, 'PT-CORR-OUTPUT: --out lies inside the project directory, which holds only '
                       'files the project owns; choose a place outside it')
    return out


def _publish(path: Path, data: bytes) -> bool:
    """Atomic: a synced temporary file in the same directory, then an exclusive hard link. False when `path` already is `data`."""
    try:
        if not path.is_symlink() and path.is_file():
            descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
            with os.fdopen(descriptor, 'rb') as stream:
                if stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and stream.read(len(data) + 1) == data:
                    return False
        if path.exists() or path.is_symlink():
            raise CliError(ENVIRONMENT, f'PT-CORR-EXISTS: {path} exists and has other content; it was not changed. '
                           'Choose a new output path')
        descriptor, temporary = tempfile.mkstemp(prefix='.corrections-', suffix='.tmp', dir=path.parent)
        stage = Path(temporary)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(stage, path)
            except FileExistsError:
                raise CliError(ENVIRONMENT, 'PT-CORR-EXISTS: destination appeared during publication; it was kept') from None
        finally:
            stage.unlink(missing_ok=True)
    except OSError as exc:
        raise CliError(RUNTIME, 'PT-CORR-OUTPUT: the document could not be written '
                       f'({exc.strerror or type(exc).__name__}); a previous file is unchanged') from None
    return True


def _export(args, cancel) -> int:
    service = open_project(args.project)
    try:
        destination = _destination(args.out, service.root)
        document = exchange.build_document(service.project, include_review=args.include_review)
        data = exchange.render(document)
    except exchange.ExchangeError as exc:
        raise CliError(RUNTIME, str(exc)) from None
    finally:
        service.close()
    if cancel.is_set():
        emit(args, 'corrections export', 'cancelled', None, [], '')
        return CANCELLED
    written = _publish(destination, data)
    review = document.review
    lost = exchange.unresolvable(document)
    warnings = [f'{lost} correction(s) name a function without a usable address; no import will accept the document '
                'until they are corrected again'] if lost else []
    result = {'contract': exchange.CONTRACT, 'path': str(args.out), 'bytes': len(data),
              'sha256': hashlib.sha256(data).hexdigest(), 'corrections': len(document.corrections),
              'review': None if review is None else {'matches': len(review.matches), 'findings': len(review.findings)},
              'written': written}
    states = '' if review is None else (f', {len(review.matches)} relation review state(s), '
                                        f'{len(review.findings)} finding review state(s)')
    emit(args, 'corrections export', 'complete', result, warnings,
         f'{"Exported" if written else "Already up to date:"} {len(document.corrections)} correction(s){states} '
         f'{"to" if written else "in"} {args.out}; sha256 {result["sha256"]}')
    return OK


def _import_text(plan: exchange.ImportPlan, dry_run: bool, written: bool, after: int) -> str:
    counts = plan.corrections.as_dict()
    review = '' if plan.matches is None else (f'; review states: {plan.matches.new} of {plan.matches.total} '
                                              f'relation(s), {plan.findings.new} of {plan.findings.total} finding(s)')
    if not plan.writes:
        found = (f'all {counts["total"]} correction(s) are already present' if counts['total'] else
                 'the document holds no correction')
        return f'Nothing to import: {found}{review}. Nothing was written.'
    head = (f'Dry run: would import {counts["new"]} of {counts["total"]} correction(s) '
            f'({counts["already_present"]} already present){review}; nothing was written.' if dry_run else
            f'Imported {counts["new"]} of {counts["total"]} correction(s) ({counts["already_present"]} already '
            f'present){review}; project revision {plan.revision_before} -> {after}.')
    rows = [f'  {change["index"]}. {change["action"]} {change["category"]}: '
            f'{_cell(", ".join(change["older"]) or "-", 60)} -> {_cell(", ".join(change["newer"]) or "-", 60)}'
            for change in plan.changes]
    return '\n'.join([head, *rows])


def _import(args, cancel) -> int:
    service = open_project(args.project)
    try:
        document = exchange.read_document(args.file)
        plan = exchange.plan_import(service, document, cancel.is_set)
        written = False if args.dry_run else exchange.commit(service, plan, cancel.is_set)
    except exchange.Cancelled:
        emit(args, 'corrections import', 'cancelled', None, [], '')
        return CANCELLED
    except exchange.ExchangeError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    except ValueError as exc:
        raise service_error(exc) from None
    finally:
        service.close()
    after = plan.candidate.revision
    result = {'contract': exchange.CONTRACT, 'dry_run': bool(args.dry_run), 'written': written,
              'corrections': plan.corrections.as_dict(),
              'review': None if plan.matches is None else {'matches': plan.matches.as_dict(),
                                                           'findings': plan.findings.as_dict()},
              'changes': plan.changes, 'revision': {'before': plan.revision_before, 'after': after}}
    emit(args, 'corrections import', 'complete', result, plan.warnings,
         _import_text(plan, bool(args.dry_run), written, after))
    return OK


def _undo(args, cancel) -> int:
    from .persistence import strict_json
    service = open_project(args.project)
    try:
        before = service.project.revision
        overrides = [a for a in service.project.annotations if a.kind == 'match-override']
        chosen = args.annotation or next((a.id for a in reversed(overrides) if not a.stale), None)  # as the desktop
        if chosen is None:
            emit(args, 'corrections undo', 'complete',
                 {'annotation_id': None, 'match_id': None, 'restored_relations': 0,
                  'revision': {'before': before, 'after': before}}, [],
                 'Nothing to undo: the project has no active manual correction' + (
                     f' ({len(overrides)} earlier correction record(s) are superseded and can no longer be restored).'
                     if overrides else '.'))
            return NO_RESULTS
        try:
            service.restore_match_override(chosen)
        except ValueError as exc:
            raise service_error(exc) from None
        record = next(a for a in overrides if a.id == chosen)  # the service accepted it, so it exists and is well formed
        restored = len(strict_json(record.text)['previous_matches'])
        after = service.project.revision
    finally:
        service.close()
    result = {'annotation_id': chosen, 'match_id': record.target_id, 'restored_relations': restored,
              'revision': {'before': before, 'after': after}}
    emit(args, 'corrections undo', 'complete', result, [],
         f'Undid correction {chosen}: {restored} relation(s) restored; project revision {before} -> {after}.')
    return OK


_LEAVES = {'list': _list, 'export': _export, 'import': _import, 'undo': _undo}


def run(args, cancel) -> int:
    if cancel.is_set():
        emit(args, f'corrections {args.action}', 'cancelled', None, [], '')
        return CANCELLED
    return _LEAVES[args.action](args, cancel)
