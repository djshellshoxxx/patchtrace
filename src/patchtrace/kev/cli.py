"""``patchtrace kev status|plan|fetch|import|lookup|diff|prune`` (KEV-integration-plan section 8). Headless: no Qt.

Output is the ``enrichment-cli/1`` envelope. With ``--json`` stdout carries exactly one document whose ``result`` is
``{"contract": "kev/1", "record": ...}``; diagnostics, and the announcement of every request, go to stderr. Exit codes:
0 success (a stale catalog, or a mirror older than the catalog in use, is a ``partial`` result and still 0); 2 invalid
use, consent or input file; 3 runtime, network, provider, integrity or storage failure (and ``status --max-age-days``
exceeded); 4 nothing to report (no catalog, fewer than two stored catalogs); 5 cancelled.

Only ``fetch`` touches the network: it needs ``--source`` (no default) and ``--consent-hosts`` naming exactly the host
of that source, and it prints the request on stderr before it is sent. Everything printed that came from the catalog was
cleaned to one plain line when the catalog was read.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from ..cli_commands import CANCELLED, NO_RESULTS, OK, RUNTIME, CliError, emit
from . import limits
from .contracts import (
    CONTRACT,
    SOURCE_HOSTS,
    KevCatalog,
    KevCatalogMeta,
    KevError,
    KevLookup,
    https_host,
    plan_for,
)
from .join import freshness_of, lookup, split_cve_ids
from .service import Installed, KevService
from .store import default_kev_dir
from .view_model import (
    FOOTER,
    NOT_LISTED_NEGATION,
    KevColumnProvider,
    age_phrase,
    banner_text,
    changes_lines,
    consent_lines,
    detail_text,
    mirror_older_text,
    status_line,
)

SUMMARY = 'CISA KEV catalog: status, plan, fetch, import, lookup'
MAX_SNAPSHOT_FILE_BYTES = 32 * limits.MIB          # equals enrichment.cve.MAX_SNAPSHOT_BYTES (a test pins it)
MAX_STORED_LISTED = 20
NO_CATALOG = 'No KEV catalog is loaded. Use "patchtrace kev fetch" or "patchtrace kev import FILE" first.'
_NO_ENTRY = '-'
_RANSOMWARE = {'known': 'Known', 'unknown': 'Unknown', 'unrecognized': 'Not recognized'}
_TRIAGE = {'yes': 'Yes', 'no': 'No', 'unrecognized': 'Not recognized'}
_MARKDOWN_SPECIAL = re.compile(r'([\\`*_{}\[\]<>()#+!|~&])')


# --- parser ---------------------------------------------------------------------------------------------------

def _count(minimum: int):
    def parse(text: str) -> int:
        if not (text.isascii() and text.isdigit()) or int(text) < minimum:
            raise argparse.ArgumentTypeError(f'must be a whole number, {minimum} or greater')
        return int(text)
    return parse


def add_parser(sub) -> argparse.ArgumentParser:
    parser = sub.add_parser('kev', help=SUMMARY)
    actions = parser.add_subparsers(dest='action', required=True)

    def leaf(name: str, help_: str, *, store: bool = True) -> argparse.ArgumentParser:
        item = actions.add_parser(name, help=help_)
        item.set_defaults(command_label=f'kev {name}')
        if store:
            item.add_argument('--kev-dir', type=Path, default=None, metavar='DIR',
                              help='catalog folder (default: PatchTrace\'s data folder)')
        item.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return item

    leaf('status', 'show the catalog in use and its age (no network)').add_argument(
        '--max-age-days', type=_count(0), default=None, metavar='N',
        help='exit 3 (partial) when the catalog is older than N days')
    plan = leaf('plan', 'show the exact request a fetch would send (no network)', store=False)
    plan.add_argument('--source', required=True, choices=sorted(SOURCE_HOSTS), help='where to download from')
    fetch = leaf('fetch', 'download the catalog after you name the host (one GET)')
    fetch.add_argument('--source', required=True, choices=sorted(SOURCE_HOSTS), help='where to download from')
    fetch.add_argument('--consent-hosts', default='', metavar='HOST',
                       help='must be exactly the host of --source: ' + ', '.join(
                           f'{host} ({source})' for source, host in sorted(SOURCE_HOSTS.items())))
    fetch.add_argument('--accept-shrink', action='store_true',
                       help='replace the catalog in use even if the new one has under 90 percent of its entries')
    imported = leaf('import', 'read a KEV JSON file you saved (no network)')
    imported.add_argument('file', type=Path)
    imported.add_argument('--accept-shrink', action='store_true', help='as for fetch')
    find = leaf('lookup', 'look up CVE IDs in the catalog (no network)')
    find.add_argument('cve', nargs='*', metavar='CVE', help='CVE-YYYY-NNNN (ASCII digits)')
    find.add_argument('--from-cve-snapshot', action='append', default=[], type=Path, metavar='FILE',
                      help='also look up the CVE IDs of a saved CVE snapshot file (repeatable)')
    find.add_argument('--catalog', type=Path, default=None, metavar='FILE',
                      help='use this KEV JSON file instead of the stored catalog (it is not installed)')
    find.add_argument('--md', action='store_true', help='also produce a Markdown report block')
    changes = leaf('diff', 'show what changed between two stored catalogs (no network)')
    changes.add_argument('--from', dest='from_id', metavar='ID', default=None, help='snapshot id (default: previous)')
    changes.add_argument('--to', dest='to_id', metavar='ID', default=None, help='snapshot id (default: in use)')
    prune = leaf('prune', 'delete old stored catalogs (the only deletion)')
    prune.add_argument('--keep', type=_count(1), required=True, metavar='N', help='stored catalogs to keep')
    prune.add_argument('--yes', action='store_true', help='confirm the deletion')
    return parser


# --- helpers --------------------------------------------------------------------------------------------------

def _record(record: str, **fields) -> dict:
    return {'contract': CONTRACT, 'record': record, **fields}


def _announce(message: str) -> None:
    print(f'request: {message}', file=sys.stderr)


def _digest(meta: KevCatalogMeta) -> dict:
    return {'snapshot_id': meta.snapshot_id, 'catalog_version': meta.catalog_version, 'date_released': meta.date_released}


def _kib(size: int) -> str:
    return f'{size / limits.KIB:.1f} KiB'


def _strict_pairs(pairs: list) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError('a key is repeated')
    return result


def _no_constant(name: str):
    raise ValueError(f'{name} is not JSON')


def _snapshot_ids(path: Path) -> list[str]:
    """The CVE IDs of a saved CVE snapshot file (one record or a list). Only ``cve_id`` is read; the rest is ignored."""
    try:
        with open(path, 'rb') as handle:
            raw = handle.read(MAX_SNAPSHOT_FILE_BYTES + 1)
    except OSError:
        raise KevError('PT-KEV-INPUT', 'a saved CVE snapshot file cannot be read') from None
    if len(raw) > MAX_SNAPSHOT_FILE_BYTES:
        raise KevError('PT-KEV-INPUT', 'a saved CVE snapshot file is larger than 32 MiB')
    try:
        document = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=_strict_pairs, parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise KevError('PT-KEV-INPUT', 'a saved CVE snapshot file is not strict JSON') from None
    found = [item.get('cve_id') if isinstance(item, dict) else None
             for item in (document if isinstance(document, list) else [document])]
    if not found or not all(type(item) is str for item in found):
        raise KevError('PT-KEV-INPUT', 'every record of a saved CVE snapshot file needs a cve_id')
    return found


def _requested(args) -> list[str]:
    ids = list(split_cve_ids(' '.join(args.cve)))
    for path in args.from_cve_snapshot:
        ids += _snapshot_ids(path)
    ids = list(dict.fromkeys(ids))
    if not ids:
        raise KevError('PT-KEV-INPUT', 'give at least one CVE ID, or --from-cve-snapshot FILE')
    return ids


def _failed(args, exc: KevError) -> int:
    command = args.command_label
    if exc.code == 'PT-KEV-CANCEL':
        emit(args, command, 'cancelled', None, [], '')
        return CANCELLED
    if exc.code == 'PT-KEV-NOTFOUND':
        emit(args, command, 'unavailable', _record(args.action, reason=exc.message), [], exc.message)
        return NO_RESULTS
    hint = ' (use --accept-shrink to replace the catalog in use anyway)' if exc.code == 'PT-KEV-SHRINK' else ''
    raise CliError(exc.exit_code, f'{exc}{hint}')


# --- actions --------------------------------------------------------------------------------------------------

def _over_limit(freshness: str, age: int | None, limit: int) -> str | None:
    """The warning when a catalog is older than ``--max-age-days`` allows (a future release time cannot be measured)."""
    if freshness == 'future':
        return f'The release time is in the future, so the age cannot be held to the limit of {limit} days.'
    if age is not None and age > limit:
        return f'The catalog is {age} days old, older than the limit of {limit} days.'
    return None


def _stored(item: KevCatalogMeta) -> dict:
    return {'snapshot_id': item.snapshot_id, 'catalog_version': item.catalog_version,
            'date_released': item.date_released, 'entry_count': item.entry_count, 'retrieved_at': item.retrieved_at,
            'source': item.source}


def _status(args, cancel, service: KevService) -> int:
    state = service.store.status()
    meta = state.current
    freshness, age = freshness_of(meta.date_released, service.now()) if meta else ('unknown', None)
    banner = banner_text(freshness, age)
    over = _over_limit(freshness, age, args.max_age_days) if meta and args.max_age_days is not None else None
    warnings = [*state.notes, *(w for w in (state.warning, banner, over) if w)]
    result = _record('status', directory=str(service.store.root), catalog=meta and meta.model_dump(mode='json'),
                     freshness=freshness, age_days=age, banner=banner, max_age_days=args.max_age_days,
                     notes=list(state.notes), snapshots=state.snapshots, bytes=state.bytes,
                     stored=[_stored(item) for item in service.store.list_snapshots()[:MAX_STORED_LISTED]])
    if meta is None:
        emit(args, args.command_label, 'unavailable', result, warnings, NO_CATALOG)
        return NO_RESULTS
    text = '\n'.join([status_line(meta, freshness, age),
                      f'Stored catalogs: {state.snapshots} ({_kib(state.bytes)}) in {service.store.root}'])
    emit(args, args.command_label, 'partial' if over else 'complete', result, warnings, text)
    return RUNTIME if over else OK


def _plan(args, cancel, service: KevService) -> int:
    plan = plan_for(args.source)
    lines = consent_lines(plan)
    command = f'patchtrace kev fetch --source {plan.source} --consent-hosts {plan.host}'
    emit(args, args.command_label, 'complete',
         _record('plan', network='none', plan=plan.model_dump(mode='json'), consent_hosts=plan.host,
                 request=list(lines)), [], '\n'.join([*lines, '', f'To allow this request, run: {command}']))
    return OK


def _installed(args, service: KevService, installed: Installed, older: str, **extra) -> int:
    meta, in_use, outcome = installed.meta, installed.in_use, installed.result.outcome
    warnings = [older] if outcome == 'kept-newer' else []
    freshness, age = freshness_of(meta.date_released, service.now())
    text = {'installed': f'Installed the KEV catalog now in use.\n{status_line(meta, freshness, age)}\n'
                         f'SHA-256 {meta.raw_sha256}',
            'unchanged': f'KEV catalog {meta.catalog_version} is already the catalog in use; nothing changed.',
            'kept-newer': f'Stored KEV catalog {meta.catalog_version}; the catalog in use stays '
                          f'{in_use.catalog_version}.'}[outcome]
    emit(args, args.command_label, 'partial' if warnings else 'complete',
         _record(args.action, outcome=outcome, catalog=meta.model_dump(mode='json'), in_use=_digest(in_use), **extra),
         warnings, text)
    return OK


def _fetch(args, cancel, service: KevService) -> int:
    installed = service.fetch(args.source, args.consent_hosts, accept_shrink=args.accept_shrink, cancel=cancel,
                              announce=_announce)
    older = mirror_older_text(installed.meta.catalog_version, installed.in_use.catalog_version)
    return _installed(args, service, installed, older, plan_sha=plan_for(args.source).plan_sha)


def _import(args, cancel, service: KevService) -> int:
    installed = service.import_file(args.file, accept_shrink=args.accept_shrink)
    older = (f'The imported catalog ({installed.meta.catalog_version}) is older than the one in use '
             f'({installed.in_use.catalog_version}); the newer one was kept.')
    return _installed(args, service, installed, older)


def _escape(text: str) -> str:
    return _MARKDOWN_SPECIAL.sub(r'\\\1', text)


def _markdown(catalog: KevCatalog | None, rows: list[KevLookup], cells: list) -> str:
    """The Markdown report block of a lookup. Every value that did not come from a fixed vocabulary or a checked date
    is escaped, so hostile text typed or published cannot become markup."""
    if catalog is None:
        provenance = 'No KEV catalog is loaded.'
    else:
        meta = catalog.meta
        where = https_host(meta.final_url) if meta.final_url else 'a local file'
        entries = '1 entry' if meta.entry_count == 1 else f'{meta.entry_count} entries'
        provenance = (f'Catalog {_escape(meta.catalog_version)}, released {meta.date_released[:10]} '
                      f'{meta.date_released[11:19]} UTC, {entries}, retrieved {meta.retrieved_at[:10]} from {where}, '
                      f'SHA-256 {meta.raw_sha256}, CC0 1.0.')
    lines = ['### Exploitation context (CISA KEV)', '', provenance, '',
             '| CVE | KEV | Added to KEV | CISA due date | Known ransomware campaign use | '
             'Forensic triage required by CISA |', '|---|---|---|---|---|---|']
    for row, cell in zip(rows, cells, strict=True):
        entry = row.entry
        values = [_escape(row.cve_id), cell.text, entry.date_added if entry else _NO_ENTRY,
                  entry.due_date if entry else _NO_ENTRY,
                  _RANSOMWARE.get(entry.ransomware_use, _NO_ENTRY) if entry else _NO_ENTRY,
                  _TRIAGE.get(entry.forensic_triage, _NO_ENTRY) if entry else _NO_ENTRY]
        lines.append('| ' + ' | '.join(values) + ' |')
    lines += ['', 'KEV lists a CVE as a known exploited vulnerability. It does not identify builds, KBs, files or '
                  f'functions. {NOT_LISTED_NEGATION}']
    return '\n'.join(lines)


def _table(rows: list[KevLookup], cells: list) -> list[str]:
    lines = []
    for row, cell in zip(rows, cells, strict=True):
        extra = f'  (added {row.entry.date_added}, CISA due date {row.entry.due_date})' if row.entry else ''
        lines.append(f'{row.cve_id}  {cell.text}{extra}')
    return lines


def _catalog_for(args, service: KevService) -> tuple[KevCatalog | None, list[str]]:
    """The catalog to answer from (``--catalog FILE``, else the one in use) and the notes of a repaired store."""
    if args.catalog is not None:
        return service.read_catalog(args.catalog), []
    loaded = service.store.load_current()
    return (loaded.catalog, list(loaded.notes)) if loaded else (None, [])


def _counts(rows: list[KevLookup]) -> dict:
    listed = [row for row in rows if row.status == 'listed']
    return {'listed': len(listed), 'listed_ransomware_known': sum(row.entry.ransomware_use == 'known' for row in listed),
            'not_listed': sum(row.status == 'not-listed' for row in rows),
            'unavailable': sum(row.status == 'unavailable' for row in rows),
            'invalid': sum(row.status == 'invalid-id' for row in rows)}


def _summary(catalog: KevCatalog | None, counts: dict, age: str) -> str | None:
    """One sentence over the IDs the catalog answered (invalid IDs are not counted): numbers only, no score word."""
    answered = counts['listed'] + counts['not_listed']
    if catalog is None or not answered:
        return None
    return (f'{counts["listed"]} of {answered} CVEs are listed in CISA KEV (catalog {catalog.meta.catalog_version}, '
            f'{age}). {NOT_LISTED_NEGATION}')


def _lookup(args, cancel, service: KevService) -> int:
    ids = _requested(args)
    now = service.now()
    catalog, notes = _catalog_for(args, service)
    rows = list(lookup(catalog, ids, now))
    provider = KevColumnProvider(catalog, now)
    cells = [provider.cell(cve) for cve in ids]
    freshness, age = provider.freshness, provider.age_days
    banner = banner_text(freshness, age)
    counts = _counts(rows)
    summary = _summary(catalog, counts, age_phrase(freshness, age))
    markdown = _markdown(catalog, rows, cells) if args.md else None
    if markdown is not None:
        text = markdown
    else:
        head = status_line(catalog.meta, freshness, age) if catalog else NO_CATALOG
        body = ([detail_text(rows[0], catalog.meta)] if catalog and len(rows) == 1
                else [*_table(rows, cells), *([summary] if summary else [])])
        text = '\n'.join([head, *body, FOOTER])
    result = _record('lookup', catalog=catalog and catalog.meta.model_dump(mode='json'), freshness=freshness,
                     age_days=age, banner=banner, counts=counts, summary=summary,
                     rows=[{'cve_id': row.cve_id, 'label': cell.text, 'lookup': row.model_dump(mode='json')}
                           for row, cell in zip(rows, cells, strict=True)],
                     **({'markdown': markdown} if markdown is not None else {}))
    warnings = [*notes, *([banner] if banner else [])]
    if catalog is None:
        emit(args, args.command_label, 'unavailable', result, warnings, text)
        return NO_RESULTS
    emit(args, args.command_label, 'partial' if freshness in ('stale', 'future') else 'complete', result, warnings,
         text)
    return OK


def _diff(args, cancel, service: KevService) -> int:
    comparison = service.diff(args.from_id, args.to_id)
    lines = changes_lines(comparison.delta, comparison.new, comparison.old.meta.catalog_version)
    emit(args, args.command_label, 'complete',
         _record('diff', **{'from': _digest(comparison.old.meta), 'to': _digest(comparison.new.meta)},
                 delta=comparison.delta.model_dump(mode='json'), lines=list(lines)), [], '\n'.join(lines))
    return OK


def _prune(args, cancel, service: KevService) -> int:
    done = service.store.prune(args.keep, yes=args.yes)
    kept = len(service.store.list_snapshots())
    count = len(done.removed)
    emit(args, args.command_label, 'complete',
         _record('prune', removed=list(done.removed), removed_files=done.removed_files, freed_bytes=done.freed_bytes,
                 kept=kept), [],
         f'Removed {count} stored catalog{"" if count == 1 else "s"} ({done.removed_files} files, '
         f'{_kib(done.freed_bytes)}); {kept} kept.')
    return OK


ACTIONS = {'status': _status, 'plan': _plan, 'fetch': _fetch, 'import': _import, 'lookup': _lookup, 'diff': _diff,
           'prune': _prune}


def run(args, cancel) -> int:
    try:
        return ACTIONS[args.action](args, cancel, KevService(getattr(args, 'kev_dir', None) or default_kev_dir()))
    except KevError as exc:
        return _failed(args, exc)
