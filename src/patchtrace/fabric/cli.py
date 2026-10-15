"""`patchtrace fabric list|show|resolve|stats` (FAB-integration-plan.md s8): read-only views of a project's anchors.

Producers publish anchors and a shell never edits them, so nothing here writes. Never imports Qt. `add_parser` and
`run` are what the CLI-registry adapter `cli_commands/fabric.py` calls. Exit codes follow `enrichment-cli/1`: 0 ok,
2 invalid input, 3 runtime or partial, 4 legitimate no result, 5 cancelled. A stale or unreadable batch, or an anchor
the reader skipped, makes the read partial: a missing anchor is unknown then, not a negative answer. In `--json` mode
stdout is one document.
"""
from __future__ import annotations

import argparse
import contextlib
import re
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path

from ..cli import CANCELLED, ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError
from ..cli import _emit as emit
from ..enrichment.storage import EnrichmentStore
from ..service import ProjectService
from .contracts import PRODUCERS, Anchor, AnchorQuery, Resolution, clean_line
from .limits import FabricError
from .origins import anchor_components
from .store import BatchStatus, EnrichmentAnchorStore

VERBS = {'list': 'list the anchors of a project in canonical order',
         'show': 'show one anchor with its witnesses',
         'resolve': 'resolve a value to one anchor: found, ambiguous or unknown',
         'stats': 'count the anchors and list the stored batches with their flags'}
_SHA256 = re.compile(r'[0-9a-f]{64}')
_UNKNOWN_NOTE = 'Missing evidence is unknown, not a negative result.'


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('fabric', help='read the anchor fabric: list, show, resolve or stats (read-only)',
                            description='Read-only views of the anchors a project holds. Producers publish them and '
                                        'this command never changes them. Missing evidence is unknown, not a '
                                        'negative result.')
    verbs = parser.add_subparsers(dest='action', required=True, parser_class=type(parser))
    listing = _leaf(verbs, 'list')
    listing.add_argument('--kind', help='an anchor kind, for example function, import, string or cwe')
    listing.add_argument('--side', help='older, newer, both or none')
    listing.add_argument('--role', help='observed, stated or hint')
    listing.add_argument('--subject', help='the subject key of the anchors, for example a pair or image key')
    listing.add_argument('--limit', type=int, default=100, help='rows to return, 1 to 500 (default 100)')
    _leaf(verbs, 'show').add_argument('anchor_id', metavar='ANCHOR_ID', help='a lower-case sha256 hex digest')
    resolve = _leaf(verbs, 'resolve')
    resolve.add_argument('--kind', required=True, help='the kind that the value names')
    resolve.add_argument('--side', help='older, newer, both or none (any side when omitted)')
    resolve.add_argument('value', metavar='VALUE', help='a name or a key of that kind')
    _leaf(verbs, 'stats')
    return parser


def _leaf(verbs, name: str) -> argparse.ArgumentParser:
    leaf = verbs.add_parser(name, help=VERBS[name])
    leaf.add_argument('--project', type=Path, required=True, metavar='PATH', help='project directory')
    leaf.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
    leaf.set_defaults(command_label=f'fabric {name}')
    return leaf


def run(args, cancel: threading.Event) -> int:
    command = f'fabric {args.action}'
    if cancel.is_set():
        emit(args, command, 'cancelled', None, [], '')
        return CANCELLED
    try:
        with _open(args.project) as (project_id, store):
            return _ACTIONS[args.action](args, command, project_id, store)
    except FabricError as exc:
        raise CliError(exc.exit_code, str(exc)) from None


@contextlib.contextmanager
def _open(path: Path) -> Iterator[tuple[str, EnrichmentAnchorStore]]:
    try:
        service = ProjectService.open(path, maintenance=False)  # a reader: the legacy raw cleanup is a write
    except ValueError as exc:
        raise CliError(ENVIRONMENT, str(exc)) from None
    try:
        yield service.project.id, EnrichmentAnchorStore(EnrichmentStore(service.store))
    finally:
        service.close()


def _list(args, command: str, project_id: str, store: EnrichmentAnchorStore) -> int:
    page = store.find(project_id, AnchorQuery(kind=args.kind, side=args.side, role=args.role, subject=args.subject,
                                               limit=args.limit))
    result = {'project': project_id, 'total': page.total, 'items': [_row(anchor) for anchor in page.items]}
    if page.items:
        text = '\n'.join([f'{len(page.items)} of {page.total} anchors', *map(_line, page.items)])
    else:
        text = f'no anchor matches. {_UNKNOWN_NOTE}'
    return _conclude(args, command, result, _warnings(store.batches(project_id)), text, empty=not page.items)


def _show(args, command: str, project_id: str, store: EnrichmentAnchorStore) -> int:
    anchor = store.get(project_id, _anchor_id(args.anchor_id))
    result = {'project': project_id, 'anchor': None if anchor is None else anchor.model_dump(mode='json')}
    text = f'no anchor has this id. {_UNKNOWN_NOTE}' if anchor is None else _describe(anchor)
    return _conclude(args, command, result, _warnings(store.batches(project_id)), text, empty=anchor is None)


def _resolve(args, command: str, project_id: str, store: EnrichmentAnchorStore) -> int:
    found = store.resolve(project_id, args.kind, args.value, args.side)
    if found.status == 'unsupported':
        raise FabricError('PT-FAB-UNSUPPORTED', 'This reader answers no resolve question', reason='resolve')
    result = {'project': project_id, 'status': found.status, 'anchor_id': found.anchor_id, 'label': found.label,
              'candidates': list(found.candidates), 'count': found.count}
    return _conclude(args, command, result, _warnings(store.batches(project_id)), _resolution_text(found),
                     empty=found.status == 'unknown')


def _stats(args, command: str, project_id: str, store: EnrichmentAnchorStore) -> int:
    batches = store.batches(project_id)
    total = store.find(project_id, AnchorQuery(limit=1)).total
    digest = store.digest(project_id)
    result = {'project': project_id, 'digest': digest, 'anchors': total, 'batches': [_batch(b) for b in batches]}
    text = '\n'.join([f'anchors {total} in {len(batches)} batches', f'digest {digest}',
                      *(f'  {_batch_line(batch)}' for batch in batches)])
    return _conclude(args, command, result, _warnings(batches), text, empty=False)


def _conclude(args, command: str, result: dict, warnings: list[str], text: str, *, empty: bool) -> int:
    """A partial read beats a no-result: a flagged or skipped row can hide the very anchor that was asked for."""
    if warnings:
        status, code = 'partial', RUNTIME
    else:
        status, code = 'complete', NO_RESULTS if empty else OK
    emit(args, command, status, result, warnings, text)
    return code


def _warnings(batches: Sequence[BatchStatus]) -> list[str]:
    """Why a read may be incomplete; empty when every stored row was read as it was written."""
    found = []
    for batch in batches:
        row = clean_line(batch.row_id, 120)
        if not batch.readable:
            found.append(f'{row} is unreadable and was not used')
        if batch.stale:
            found.append(f'{row} is stale: its guard or origin table moved, so its anchors may be out of date')
        if batch.skipped:
            found.append(f'{row}: {batch.skipped} anchors skipped (unknown to this reader, damaged, or made for the '
                         'other orientation of the pair)')
    return found


def _anchor_id(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise FabricError('PT-FAB-INPUT', 'The anchor id is not a lower-case sha256 hex digest', reason='anchor-id')
    return value


def _row(anchor: Anchor) -> dict:
    producers = {witness.producer for witness in anchor.witnesses}
    return {'anchor_id': anchor.anchor_id, 'kind': anchor.kind, 'key': anchor.key, 'side': anchor.side,
            'role': anchor.role, 'subject': anchor.subject, 'label': anchor.label,
            'witnesses': len(anchor.witnesses), 'independent': len(anchor_components(anchor)),
            'producers': [name for name in PRODUCERS if name in producers]}


def _batch(batch: BatchStatus) -> dict:
    return {'row_id': batch.row_id, 'producer': batch.producer, 'batch': batch.batch, 'anchors': batch.anchors,
            'skipped': batch.skipped, 'stale': batch.stale, 'readable': batch.readable}


def _line(anchor: Anchor) -> str:
    return f'{anchor.anchor_id} {anchor.kind} {anchor.side} {anchor.role} {anchor.label}'


def _describe(anchor: Anchor) -> str:
    row = _row(anchor)
    lines = [f'anchor {anchor.anchor_id}', f'kind {anchor.kind}, side {anchor.side}, role {anchor.role}',
             f'key {anchor.key}', f'subject {anchor.subject or "-"}', f'label {anchor.label}',
             f'witnesses {row["witnesses"]} ({row["independent"]} independent): {", ".join(row["producers"])}']
    return '\n'.join([*lines, *(f'  {w.producer} {w.batch} {w.source}: {w.label}' for w in anchor.witnesses)])


def _resolution_text(found: Resolution) -> str:
    if found.status == 'found':
        return f'found: {found.anchor_id} {found.label}'
    if found.status == 'ambiguous':
        return '\n'.join([f'ambiguous: {found.count} anchors match and none is picked first; candidates:',
                          *(f'  {candidate}' for candidate in found.candidates)])
    return f'unknown: nothing published matches this value. {_UNKNOWN_NOTE}'


def _batch_line(batch: BatchStatus) -> str:
    flags = ''.join(f', {name}' for name, on in (('stale', batch.stale), ('unreadable', not batch.readable)) if on)
    return f'{clean_line(batch.row_id, 120)}: anchors {batch.anchors}, skipped {batch.skipped}{flags}'


_ACTIONS = {'list': _list, 'show': _show, 'resolve': _resolve, 'stats': _stats}
