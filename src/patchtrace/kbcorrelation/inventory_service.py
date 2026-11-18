"""PW-01 service operations shared by CLI and desktop. Offline unless fetch is consented.

Each call owns its workspace connection. CSV/HTML parsing, persistence and exact
network policy remain in their dedicated modules; no target is executed here.
"""
from __future__ import annotations

import json
import os
import stat
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError

from .cli_index import open_existing
from .ids import KbSyntaxError, normalise_kb_edge
from .inventory_contracts import MAX_BYTES, InventoryContext
from .inventory_store import (
    add_inventory,
    add_support,
    get_inventory,
    get_support,
    inventory_count,
    list_inventories,
    list_support,
    read_source,
    support_count,
)
from .products import clean_text
from .sources.cvrf import SourceError, load_json
from .sources.inventory_fetch import InventoryPlan, build_plan, fetch_source, parse_plan, render_plan
from .sources.support_links import extract_links
from .store import KbcStoreError

HTML_BYTES = 4 * 1024 * 1024
PLAN_BYTES = 64 * 1024


def context_for(kb, **values) -> InventoryContext:
    """Normalize only the KB token; all other context remains explicit and strict."""
    try:
        return InventoryContext(kb=normalise_kb_edge(kb), **values)
    except (KbSyntaxError, ValidationError, TypeError):
        raise SourceError('PT-KBC-INPUT', 'inventory context is invalid; check KB, architecture, dialect and scope') from None


def _check(cancel):
    if cancel is not None and cancel.is_set():
        raise SourceError('PT-KBC-CANCEL', 'inventory operation was cancelled')


def read_file(path, cap, *, cancel=None):
    """Read an explicitly chosen regular file, bounded before and during allocation."""
    _check(cancel)
    path = Path(path).expanduser()
    fd = None
    try:
        before = path.lstat()
        reparse = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)
        if not stat.S_ISREG(before.st_mode) or getattr(before, 'st_file_attributes', 0) & reparse:
            raise SourceError('PT-KBC-INPUT', 'choose a regular file, not a link, device or directory')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or getattr(opened, 'st_file_attributes', 0) & reparse):
            raise SourceError('PT-KBC-INPUT', 'the selected file changed while it was opened')
        if opened.st_size > cap:
            raise SourceError('PT-KBC-LIMIT', 'the selected file exceeds this operation byte limit')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            chunks, size = [], 0
            while True:
                _check(cancel)
                chunk = stream.read(min(65_536, cap + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > cap:
                    raise SourceError('PT-KBC-LIMIT', 'the selected file exceeds this operation byte limit')
        _check(cancel)
        return b''.join(chunks)
    except OSError:
        raise SourceError('PT-KBC-INPUT', 'the selected file cannot be read') from None
    finally:
        if fd is not None:
            os.close(fd)


def _out(result, text, *, partial=False, empty=False, warnings=()):
    from .service import Outcome

    return Outcome(3 if partial else 4 if empty else 0, 'partial' if partial else 'unavailable' if empty else 'complete',
                   {'contract': 'kbcorrelation/1', **result}, text, list(warnings))


def _summary(record):
    parsed = record.parsed
    return {'import_id': record.import_id, 'source': record.source.model_dump(mode='json'),
            'asserted_source': record.asserted_source,
            'retrieval': record.retrieval.model_dump(mode='json') if record.retrieval else None,
            'context': parsed.context.model_dump(mode='json'), 'inventory_id': parsed.inventory_id,
            **{name: getattr(parsed, name) for name in ('accepted_count', 'rejected_count', 'duplicate_count',
                                                      'conflict_count', 'records_scanned', 'truncated', 'status',
                                                      'diagnostics_omitted')}}


def _import_out(record, added):
    p = record.parsed
    text = (f'{p.context.kb}: retained {p.accepted_count} rows; rejected {p.rejected_count}; '
            f'duplicates {p.duplicate_count}; conflicts {p.conflict_count}; '
            f'truncated {str(p.truncated).lower()}. Source: {record.source.authenticity}.\n'
            f'Inventory import: {record.import_id}\n'
            'Inspect entries with kb inventory show, then explicitly select an eligible row for an investigation.')
    return _out({'import_id': record.import_id, 'inventory': _summary(record), 'already_present': not added}, text,
                partial=p.status == 'partial', empty=not p.entries and p.status == 'complete')


def import_inventory(svc, path, context, *, asserted_source=None, cancel=None):
    raw = read_file(path, MAX_BYTES, cancel=cancel)
    # Validate before a missing workspace is created; persistence independently
    # replays the same bytes under its publication boundary.
    from .inventory_csv import parse_inventory

    parse_inventory(raw, context, cancel=cancel)
    with svc._open() as ws:
        record, added = add_inventory(ws, raw, context, now=svc._now(), asserted_source=asserted_source, cancel=cancel)
    return _import_out(record, added)


def _page(limit, offset, maximum):
    if type(limit) is not int or not 1 <= limit <= maximum or type(offset) is not int or not 0 <= offset <= 1_000_000:
        raise SourceError('PT-KBC-INPUT', f'page limit must be 1..{maximum} and offset 0..1000000')


def _support_summary(record):
    return {'import_id': record.import_id, 'source': record.source.model_dump(mode='json'),
            'page_url': record.page_url, 'extraction_sha256': record.extraction_sha256,
            'retrieval': record.retrieval.model_dump(mode='json') if record.retrieval else None}


def inventories(svc, *, kind='file-inventory', limit=20, offset=0, cancel=None):
    _page(limit, offset, 100)
    if kind not in ('file-inventory', 'support-page'):
        raise SourceError('PT-KBC-INPUT', 'choose file-inventory or support-page')
    _check(cancel)
    ws = open_existing(svc.root)
    records, total = [], 0
    if ws is not None:
        try:
            count = inventory_count if kind == 'file-inventory' else support_count
            listing = list_inventories if kind == 'file-inventory' else list_support
            summary = _summary if kind == 'file-inventory' else _support_summary
            total = count(ws)
            # Keep only one full cached model resident at a time. List results
            # contain summaries; show is the explicit raw/replay verification.
            for index in range(offset, min(offset + limit, total)):
                _check(cancel)
                found = listing(ws, limit=1, offset=index, verify=False, cancel=cancel)
                if found:
                    records.append(summary(found[0]))
        finally:
            ws.close()
    label = 'inventories' if kind == 'file-inventory' else 'support pages'
    lines = [f'{row["import_id"]}  {row["source"]["authenticity"]}' for row in records]
    return _out({'inventories': records, 'total': total, 'offset': offset, 'limit': limit, 'kind': kind},
                f'{total} saved {label}; showing {len(records)}.\n' + '\n'.join(lines), empty=not records)


def inventory_details(svc, import_id, *, name='', architecture=None, state=None, limit=200, offset=0, cancel=None):
    _page(limit, offset, 500)
    if type(name) is not str or len(name) > 128 or clean_text(name, 129) != name:
        raise SourceError('PT-KBC-INPUT', 'filename filter must be at most 128 plain-text characters')
    if architecture not in (None, 'amd64', 'arm64', 'x86', 'unknown') or state not in (
            None, 'metadata-only', 'unknown', 'conflicted', 'descriptive-only'):
        raise SourceError('PT-KBC-INPUT', 'inventory architecture or state filter is invalid')
    _check(cancel)
    with svc._open(create=False) as ws:
        record = get_inventory(ws, import_id, verify=True, cancel=cancel)
        if record is None:
            support = get_support(ws, import_id, verify=True, cancel=cancel)
            if support is None:
                raise SourceError('PT-KBC-INPUT', 'there is no source with that exact import ID')
            raw = read_source(ws, support, cancel=cancel)
            links = extract_links(raw, page_url=support.page_url, cancel=cancel)
            return _support_out(support, links, False)
    entries = [entry for entry in record.parsed.entries
               if name.casefold() in (entry.basename or entry.original_filename).casefold()
               and (architecture is None or entry.architecture == architecture)
               and (state is None or entry.state == state)]
    shown = entries[offset:offset + limit]
    detail = {**_summary(record), **record.parsed.model_dump(mode='json', exclude={'entries'})}
    result = {'import_id': import_id, 'inventory': detail,
              'entries': [entry.model_dump(mode='json') for entry in shown], 'filtered_count': len(entries),
              'offset': offset, 'limit': limit, 'entries_truncated': offset + len(shown) < len(entries)}
    lines = [f'{entry.entry_id}  {clean_text(entry.original_filename, 128)}  '
             f'{clean_text(entry.original_version, 128)}  {entry.architecture}  {entry.state}  '
             f'record {entry.reference.logical_record}, lines {entry.reference.line_start}-{entry.reference.line_end}'
             for entry in shown]
    return _out(result, _import_out(record, False).text + '\n' + '\n'.join(lines),
                partial=record.parsed.status == 'partial', empty=not shown and record.parsed.status == 'complete')


def _support_out(record, extraction, added):
    accepted = sum(link.accepted for link in extraction.links)
    result = {'import_id': record.import_id, 'source': record.source.model_dump(mode='json'),
              'extraction': extraction.as_dict(), 'already_present': not added,
              'retrieval': record.retrieval.model_dump(mode='json') if record.retrieval else None}
    lines = [f'{"candidate" if link.accepted else "rejected"}  {link.url or "invalid URL"}  '
             f'{link.reason or "explicit selection required"}' for link in extraction.links]
    return _out(result, f'{accepted} file-information candidate(s); no link followed. '
                f'Source: {record.source.authenticity}.\n' + '\n'.join(lines),
                partial=extraction.truncated, empty=not accepted and not extraction.truncated)


def support_links(svc, path, *, page_url, cancel=None):
    raw = read_file(path, HTML_BYTES, cancel=cancel)
    extraction = extract_links(raw, page_url=page_url, cancel=cancel)
    with svc._open() as ws:
        record, added = add_support(ws, raw, page_url, now=svc._now(), cancel=cancel)
    return _support_out(record, extraction, added)


def inventory_plan(_svc, url, *, kind='file-inventory', redirects=()):
    plan = build_plan(url, kind=kind, redirects=redirects)
    preview = render_plan(plan)
    return _out({'plan': plan.as_dict(), 'preview': preview}, preview)


def _plan_input(value, cancel):
    if isinstance(value, InventoryPlan):
        return parse_plan(value.to_json())
    raw = read_file(value, PLAN_BYTES, cancel=cancel)
    payload = load_json(raw)
    if isinstance(payload, dict) and payload.get('contract') == 'enrichment-cli/1':
        if payload.get('command') != 'kb inventory plan' or not isinstance(payload.get('result'), dict):
            raise SourceError('PT-KBC-INPUT', 'the plan file is not an inventory plan preview')
        payload = payload['result'].get('plan')
    return parse_plan(json.dumps(payload))


def fetch_inventory(svc, plan, *, context=None, consent_hosts=(), consent_plan=None, offline=False, cancel=None,
                    opener=None):
    parsed = _plan_input(plan, cancel)
    if parsed.kind == 'file-inventory' and not isinstance(context, InventoryContext):
        raise SourceError('PT-KBC-INPUT', 'a file-inventory fetch requires explicit KB parsing context')
    try:
        fetched = fetch_source(parsed, consent_hosts=consent_hosts, consent_plan=consent_plan, offline=offline,
                               cancel=cancel, opener=opener,
                               now=lambda: datetime.fromisoformat(svc._now().replace('Z', '+00:00')))
    except SourceError as exc:
        if exc.code != 'PT-KBC-CONSENT' or not exc.details or 'proposed_plan' not in exc.details:
            raise
        from .service import Outcome

        return Outcome(2, 'failed', {'contract': 'kbcorrelation/1', **exc.details},
                       exc.message + '\n' + exc.details['preview'], error=f'{exc.code}: {exc.message}')
    _check(cancel)
    if fetched.kind == 'file-inventory':
        with svc._open() as ws:
            record, added = add_inventory(ws, fetched.raw, context, now=svc._now(), retrieval=fetched, cancel=cancel)
        return _import_out(record, added)
    extraction = extract_links(fetched.raw, page_url=fetched.final_url, cancel=cancel)
    with svc._open() as ws:
        record, added = add_support(ws, fetched.raw, fetched.final_url, now=svc._now(), retrieval=fetched, cancel=cancel)
    return _support_out(record, extraction, added)


def select_inventory(svc, *args, **kwargs):
    from .inventory_selection import select

    try:
        return select(svc, *args, **kwargs)
    except ValidationError:
        raise KbcStoreError('PT-KBC-INPUT', 'inventory selection identifiers are invalid') from None
