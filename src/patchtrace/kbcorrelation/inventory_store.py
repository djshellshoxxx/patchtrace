"""PW-01 immutable imports over the existing workspace transaction and raw store.

Raw source identity is kind plus exact bytes; import identity additionally binds
parser context and provenance. Local URL assertions never become fetched origin.
The additive tables leave the advisory schema and user_version unchanged. Fault
seams are ``inventory_after_object``, ``inventory_before_commit`` and the same
names prefixed with ``support``. A failed write may leave an orphan raw object.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, field_validator, model_validator

from ..hostile_text import replace_hostile
from ..persistence import strict_json
from .contracts import Record, Sha256, SourceDoc, Timestamp, domain_id, https_host
from .inventory_contracts import (
    DEFAULT_LIMITS,
    MAX_BYTES,
    MAX_PAGE_ENTRIES,
    CsvInventory,
    CsvInventoryPage,
    InventoryContext,
    InventoryLimits,
    InventoryPageLimits,
    InventoryRetention,
)
from .sources.cvrf import SourceError
from .store import KbcStoreError, WorkspaceStore

if TYPE_CHECKING:
    from .sources.inventory_fetch import FetchedSource

SCHEMA_VERSION = 1
MAX_SUPPORT_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_PAGE_RECORDS = 100
MAX_PAGE_BYTES = 64 * 1024 * 1024
INVENTORY_TABLE = 'kb_inventory_imports'
SUPPORT_TABLE = 'kb_support_imports'
_TABLES = (INVENTORY_TABLE, SUPPORT_TABLE)
_SHA = re.compile(r'[0-9a-f]{64}')
Url = Annotated[str, Field(min_length=1, max_length=2048)]


def _asserted_url(value: str | None) -> str | None:
    if value is not None:
        if type(value) is not str or not 1 <= len(value) <= 2048:
            raise ValueError('an asserted source must be a bounded URL string')
        if https_host(value) is None or '\\' in value or replace_hostile(value) != value:
            raise ValueError('an asserted source must be inert HTTPS text without userinfo, fragments or controls')
    return value


class RetrievalProvenance(Record):
    """The exact bounded fetch receipt; it asserts TLS transport, not authorship."""
    kind: Literal['file-inventory', 'support-page']
    original_url: Url
    final_url: Url
    redirect_chain: tuple[Url, ...] = Field(min_length=1, max_length=5)
    sha256: Sha256
    size: int = Field(ge=0, le=MAX_BYTES)
    retrieved_at: Timestamp
    plan_sha: Sha256

    @model_validator(mode='after')
    def _consistent(self):
        from .sources.inventory_fetch import build_plan
        if self.redirect_chain[0] != self.original_url or self.redirect_chain[-1] != self.final_url:
            raise ValueError('receipt endpoints disagree with the exact request chain')
        if self.kind == 'support-page' and self.size > MAX_SUPPORT_BYTES:
            raise ValueError('support-page receipt exceeds its byte budget')
        try:
            plan = build_plan(self.original_url, kind=self.kind, redirects=self.redirect_chain[1:])
        except SourceError as exc:
            raise ValueError('receipt has an invalid request plan') from exc
        if plan.plan_sha != self.plan_sha:
            raise ValueError('receipt digest does not bind the exact request plan')
        return self


def _source_identity(source: SourceDoc, retrieval: RetrievalProvenance | None) -> dict:
    # A local import time is bookkeeping. A fetch receipt's time identifies the
    # actual acquisition event and remains in the provenance binding.
    return {'source': source.model_dump(mode='json', exclude={'retrieved_at'}),
            'retrieval': retrieval.model_dump(mode='json') if retrieval is not None else None}


def _inventory_id(source: SourceDoc, parsed: CsvInventory, asserted: str | None,
                  retrieval: RetrievalProvenance | None) -> str:
    return domain_id('kbc.inventory-import', 1,
                     {'inventory_id': parsed.inventory_id, 'asserted_source': asserted,
                      **_source_identity(source, retrieval)})


def _support_id(source: SourceDoc, page_url: str, extraction_sha256: str,
                retrieval: RetrievalProvenance | None) -> str:
    return domain_id('kbc.support-import', 1,
                     {'page_url': page_url, 'extraction_sha256': extraction_sha256,
                      **_source_identity(source, retrieval)})


def _source_consistent(source: SourceDoc, kind: str, dialect: str,
                       retrieval: RetrievalProvenance | None) -> None:
    if (source.kind != kind or source.dialect != dialect or source.parser_version != 1
            or source.release_id is not None or source.current_release_date is not None
            or source.object_path != f'objects/{source.sha256[:2]}/{source.sha256}.gz'):
        raise ValueError('source does not match this import contract')
    if retrieval is None:
        if source.origin != 'local-import' or source.lineage != 'analyst':
            raise ValueError('an import without a receipt must retain local provenance')
    else:
        expected_kind = 'file-inventory' if kind == 'kb-file-csv' else 'support-page'
        if (source.origin != 'https-fetch' or source.authenticity != 'tls-allowlisted-host'
                or source.lineage != 'microsoft-support' or source.uri != retrieval.original_url
                or source.retrieved_at != retrieval.retrieved_at or retrieval.kind != expected_kind
                or source.sha256 != retrieval.sha256 or source.size != retrieval.size):
            raise ValueError('source and exact retrieval receipt disagree')


class InventoryImport(Record):
    contract: Literal['kb-inventory-import/1'] = 'kb-inventory-import/1'
    import_id: Sha256
    source: SourceDoc
    parsed: Annotated[CsvInventory | CsvInventoryPage, Field(discriminator='contract')]
    asserted_source: Url | None = None
    retrieval: RetrievalProvenance | None = None

    _assertion = field_validator('asserted_source')(_asserted_url)

    @model_validator(mode='after')
    def _consistent(self):
        _source_consistent(self.source, 'kb-file-csv', 'csv-file-inventory/1', self.retrieval)
        if self.source.sha256 != self.parsed.raw_sha256 or self.source.size != self.parsed.raw_size:
            raise ValueError('parsed inventory does not describe the source bytes')
        if self.import_id != _inventory_id(self.source, self.parsed, self.asserted_source, self.retrieval):
            raise ValueError('import identity does not bind its inventory and provenance')
        return self


class SupportImport(Record):
    """Saved support HTML with an explicit base URL and replayable link digest."""
    contract: Literal['kb-support-import/1'] = 'kb-support-import/1'
    parser_version: Literal[1] = 1
    import_id: Sha256
    source: SourceDoc
    page_url: Url
    extraction_sha256: Sha256
    retrieval: RetrievalProvenance | None = None

    @field_validator('parser_version', mode='before')
    @classmethod
    def _version(cls, value):
        if type(value) is not int:
            raise ValueError('support parser version must be an integer')
        return value

    @model_validator(mode='after')
    def _consistent(self):
        from .sources.inventory_fetch import build_plan
        _source_consistent(self.source, 'kb-support-html', 'support-html/1', self.retrieval)
        if self.source.size > MAX_SUPPORT_BYTES:
            raise ValueError('support HTML exceeds its byte budget')
        try:
            build_plan(self.page_url, kind='support-page')
        except SourceError as exc:
            raise ValueError('support import needs an approved explicit page URL') from exc
        if self.retrieval is not None and self.page_url != self.retrieval.final_url:
            raise ValueError('fetched HTML must resolve links against its final page URL')
        if self.import_id != _support_id(self.source, self.page_url, self.extraction_sha256, self.retrieval):
            raise ValueError('support identity does not bind its page, parser and provenance')
        return self


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _check_cancel(cancel) -> None:
    if cancel is not None:
        if not callable(getattr(cancel, 'is_set', None)):
            raise KbcStoreError('PT-KBC-INPUT', 'the cancellation token must expose is_set()')
        if cancel.is_set():
            raise KbcStoreError('PT-KBC-CANCEL', 'the import operation was cancelled')


def _query(ws: WorkspaceStore, sql: str, params: tuple = ()) -> sqlite3.Cursor:
    try:
        return ws.db.execute(sql, params)
    except sqlite3.Error as exc:
        raise KbcStoreError('PT-KBC-STORAGE', 'the inventory tables cannot be read or written') from exc


def _rows(ws: WorkspaceStore, sql: str, params: tuple = ()):
    try:
        yield from _query(ws, sql, params)
    except (sqlite3.Error, UnicodeError) as exc:
        raise KbcStoreError('PT-KBC-VERIFY', 'stored import fields have invalid database text encoding') from exc


def _exists(ws: WorkspaceStore, table: str) -> bool:
    found = _query(ws, 'SELECT type FROM sqlite_master WHERE name=? COLLATE NOCASE', (table,)).fetchone()
    if found is not None and found[0] != 'table':
        raise KbcStoreError('PT-KBC-VERIFY', 'an inventory table has an unexpected database object type')
    return found is not None


def _create_table(ws: WorkspaceStore, table: str) -> None:
    # Only called inside WorkspaceStore._transaction. SQLite rolls DDL back too.
    _query(ws, f'CREATE TABLE IF NOT EXISTS {table} (schema_version INTEGER NOT NULL CHECK(schema_version=1), '
           'import_id TEXT PRIMARY KEY, sha256 TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), '
           'body TEXT NOT NULL, body_sha256 TEXT NOT NULL)')
    for operation in ('UPDATE', 'DELETE'):
        _query(ws, f'CREATE TRIGGER IF NOT EXISTS {table}_{operation.lower()} BEFORE {operation} ON {table} '
               "BEGIN SELECT RAISE(ABORT, 'append-only'); END")


def _read_record[T: (InventoryImport, SupportImport)](
        ws: WorkspaceStore, table: str, import_id: str, model: type[T]) -> T | None:
    if not _exists(ws, table):
        return None
    row = next(_rows(ws, "SELECT CASE WHEN typeof(schema_version)='integer' THEN schema_version END,"
                     "CASE WHEN typeof(import_id)='text' AND length(CAST(import_id AS BLOB))=64 THEN import_id END,"
                     "CASE WHEN typeof(sha256)='text' AND length(CAST(sha256 AS BLOB))=64 THEN sha256 END,"
                     "CASE WHEN typeof(size)='integer' THEN size END,"
                     "CASE WHEN typeof(body_sha256)='text' AND length(CAST(body_sha256 AS BLOB))=64 "
                     'THEN body_sha256 END,'
                     f'CASE WHEN length(CAST(body AS BLOB))<=? THEN body ELSE NULL END FROM {table} '
                     'WHERE import_id=?', (MAX_RECORD_BYTES, import_id)), None)
    if row is None:
        return None
    version, stored_id, raw_sha, size, body_sha, body = row
    if type(version) is not int or version != SCHEMA_VERSION:
        raise KbcStoreError('PT-KBC-VERIFY', 'the inventory record schema version is unsupported')
    try:
        if type(body) is not str or _sha(body.encode('utf-8')) != body_sha:
            raise ValueError('stored record digest mismatch')
        strict_json(body)
        record = model.model_validate_json(body)
        if (record.import_id != stored_id or stored_id != import_id or record.source.sha256 != raw_sha
                or type(size) is not int or record.source.size != size):
            raise ValueError('stored record columns disagree')
    except (ValueError, TypeError, RecursionError) as exc:
        raise KbcStoreError('PT-KBC-VERIFY', 'the stored import record is damaged or inconsistent') from exc
    return record


def _read_raw(ws: WorkspaceStore, source: SourceDoc) -> bytes:
    limit = MAX_BYTES if source.kind == 'kb-file-csv' else MAX_SUPPORT_BYTES
    return ws.read_object(source.sha256, maximum=limit, expected_size=source.size)


def _write_raw(ws: WorkspaceStore, source: SourceDoc, raw: bytes) -> None:
    tables = ['docs', *(table for table in _TABLES if _exists(ws, table))]
    referenced = any(_query(ws, f'SELECT 1 FROM {table} WHERE sha256=? LIMIT 1', (source.sha256,))
                     .fetchone() is not None for table in tables)
    # A missing object already referenced by a different context is damaged
    # state; a new import must not silently repair that earlier claim. Check and
    # reuse through the same held parent/leaf boundary as new-object publication.
    ws.write_object(source.sha256, raw, require_existing=referenced)


def _receipt(raw: bytes, kind: str, retrieval: FetchedSource | None) -> RetrievalProvenance | None:
    if retrieval is None:
        return None
    from .sources.inventory_fetch import FetchedSource
    if type(retrieval) is not FetchedSource:
        raise KbcStoreError('PT-KBC-INPUT', 'retrieval must be the result of the exact approved fetch operation')
    try:
        if type(retrieval.raw) is not bytes or retrieval.raw != raw:
            raise ValueError('fetch result and supplied bytes disagree')
        receipt = RetrievalProvenance(kind=retrieval.kind, original_url=retrieval.original_url,
                                      final_url=retrieval.final_url, redirect_chain=retrieval.redirect_chain,
                                      sha256=retrieval.sha256, size=len(retrieval.raw),
                                      retrieved_at=retrieval.retrieved_at, plan_sha=retrieval.plan_sha)
        if receipt.kind != kind or receipt.sha256 != _sha(raw):
            raise ValueError('fetch result and supplied bytes disagree')
        return receipt
    except (ValueError, TypeError) as exc:
        raise KbcStoreError('PT-KBC-VERIFY', 'the fetch result is inconsistent with its receipt or raw bytes') from exc


def _source(raw: bytes, kind: str, dialect: str, now: str,
            retrieval: RetrievalProvenance | None) -> SourceDoc:
    sha = _sha(raw)
    fetched = retrieval is not None
    return SourceDoc(doc_id=domain_id('kbc.source', 1, {'kind': kind, 'sha256': sha}), kind=kind,
                     sha256=sha, size=len(raw), origin='https-fetch' if fetched else 'local-import',
                     uri=retrieval.original_url if fetched else None,
                     retrieved_at=retrieval.retrieved_at if fetched else now, dialect=dialect, parser_version=1,
                     authenticity='tls-allowlisted-host' if fetched else 'unverified-local-file',
                     lineage='microsoft-support' if fetched else 'analyst',
                     object_path=f'objects/{sha[:2]}/{sha}.gz')


def _extraction_digest(raw: bytes, page_url: str, cancel) -> str:
    from .sources.support_links import extract_links
    extraction = extract_links(raw, page_url=page_url, cancel=cancel)
    return _sha(json.dumps(extraction.as_dict(), sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('utf-8'))


def _verify(ws: WorkspaceStore, record: InventoryImport | SupportImport, cancel) -> None:
    _check_cancel(cancel)
    raw = _read_raw(ws, record.source)
    try:
        if isinstance(record, InventoryImport):
            from .inventory_csv import parse_inventory, parse_inventory_page
            if isinstance(record.parsed, CsvInventoryPage):
                expected = parse_inventory_page(raw, record.parsed.context, record.parsed.retention,
                                                limits=record.parsed.limits, cancel=cancel)
            else:
                expected = parse_inventory(raw, record.parsed.context, limits=record.parsed.limits, cancel=cancel)
            same = expected == record.parsed
        else:
            same = _extraction_digest(raw, record.page_url, cancel) == record.extraction_sha256
    except SourceError as exc:
        if exc.code == 'PT-KBC-CANCEL':
            raise KbcStoreError(exc.code, 'import verification was cancelled') from exc
        raise KbcStoreError('PT-KBC-VERIFY', 'the raw import cannot be replayed with its captured parser') from exc
    _check_cancel(cancel)
    if not same:
        raise KbcStoreError('PT-KBC-VERIFY', 'the stored parsed record disagrees with deterministic raw replay')


def _budget(ws: WorkspaceStore, source: SourceDoc, body_size: int) -> None:
    # Count shared raw bytes once, including advisory references. Import metadata
    # also consumes the workspace budget so repeated contexts cannot grow it free.
    tables = [table for table in _TABLES if _exists(ws, table)]
    for table in ('docs', *tables):
        invalid = _query(ws, f"SELECT 1 FROM {table} WHERE typeof(size)!='integer' OR size<0 OR "
                         "typeof(sha256)!='text' OR length(sha256)!=64 OR sha256 GLOB '*[^0-9a-f]*' LIMIT 1")
        if invalid.fetchone() is not None:
            raise KbcStoreError('PT-KBC-VERIFY', 'a stored raw reference has invalid budget metadata')
    for table in tables:
        if _query(ws, f"SELECT 1 FROM {table} WHERE typeof(body)!='text' OR length(CAST(body AS BLOB))>? LIMIT 1",
                  (MAX_RECORD_BYTES,)).fetchone() is not None:
            raise KbcStoreError('PT-KBC-VERIFY', 'an existing import record exceeds its storage bounds')
    raw_queries = ['SELECT sha256,size FROM docs', *(f'SELECT sha256,size FROM {table}' for table in tables)]
    raw_queries.append('SELECT ? AS sha256,? AS size')
    raw_used = _query(ws, 'SELECT COALESCE(SUM(size),0) FROM (SELECT sha256,MAX(size) AS size FROM ('
                      + ' UNION ALL '.join(raw_queries) + ') GROUP BY sha256)',
                      (source.sha256, source.size)).fetchone()[0]
    metadata_used = sum(_query(ws, f'SELECT COALESCE(SUM(length(CAST(body AS BLOB))),0) FROM {table}')
                        .fetchone()[0] for table in tables)
    if raw_used + metadata_used + body_size > ws.limits.workspace_objects_bytes:
        raise KbcStoreError('PT-KBC-LIMIT', 'the workspace raw-object and import-record budget is exhausted')


def _add[T: (InventoryImport, SupportImport)](
        ws: WorkspaceStore, raw: bytes, record: T, table: str,
        model: type[T], prefix: str, cancel) -> tuple[T, bool]:
    _check_cancel(cancel)
    previous = _read_record(ws, table, record.import_id, model)
    if previous is not None:
        _verify(ws, previous, cancel)
        return previous, False
    body = record.model_dump_json()
    body_bytes = body.encode('utf-8')
    if len(body_bytes) > MAX_RECORD_BYTES:
        raise KbcStoreError('PT-KBC-LIMIT', 'the serialized import record exceeds its byte budget')
    _budget(ws, record.source, len(body_bytes))
    _check_cancel(cancel)
    _write_raw(ws, record.source, raw)
    ws.fault(f'{prefix}_after_object')
    _check_cancel(cancel)

    def work(_db):
        _create_table(ws, table)
        previous = _read_record(ws, table, record.import_id, model)
        if previous is not None:
            _verify(ws, previous, cancel)
            return previous, False
        _budget(ws, record.source, len(body_bytes))
        _query(ws, f'INSERT INTO {table} VALUES (?,?,?,?,?,?)',
               (SCHEMA_VERSION, record.import_id, record.source.sha256, record.source.size, body, _sha(body_bytes)))
        ws.fault(f'{prefix}_before_commit')
        _check_cancel(cancel)
        return record, True

    return ws._transaction(work)


def add_inventory(ws: WorkspaceStore, raw: bytes, context: InventoryContext, *, now: str,
                  asserted_source: str | None = None, retrieval: FetchedSource | None = None,
                  limits: InventoryLimits = DEFAULT_LIMITS, cancel=None) -> tuple[InventoryImport, bool]:
    """Parse and append a CSV claim; return the first immutable record and whether it was added."""
    ws._writable()
    _check_cancel(cancel)
    try:
        _asserted_url(asserted_source)
    except ValueError as exc:
        raise KbcStoreError('PT-KBC-INPUT', 'the asserted inventory source URL is invalid') from exc
    from .inventory_csv import parse_inventory
    parsed = parse_inventory(raw, context, limits=limits, cancel=cancel)
    receipt = _receipt(raw, 'file-inventory', retrieval)
    try:
        source = _source(raw, 'kb-file-csv', 'csv-file-inventory/1', now, receipt)
        record = InventoryImport(import_id=_inventory_id(source, parsed, asserted_source, receipt), source=source,
                                 parsed=parsed, asserted_source=asserted_source, retrieval=receipt)
    except (ValueError, TypeError) as exc:
        raise KbcStoreError('PT-KBC-INPUT', 'the inventory import context or provenance is invalid') from exc
    return _add(ws, raw, record, INVENTORY_TABLE, InventoryImport, 'inventory', cancel)


def retain_inventory(ws: WorkspaceStore, import_id: str, retention: InventoryRetention, *,
                     cancel=None) -> tuple[InventoryImport, bool]:
    """Append a page from verified retained bytes without changing source provenance or investigations."""
    from .inventory_csv import parse_inventory_page

    ws._writable()
    _check_cancel(cancel)
    parent = get_inventory(ws, import_id, verify=True, cancel=cancel)
    if parent is None:
        raise KbcStoreError('PT-KBC-INPUT', 'there is no inventory with that exact import ID')
    raw = _read_raw(ws, parent.source)
    limits = InventoryPageLimits.model_validate(parent.parsed.limits.model_dump() | {
        'max_entries': min(parent.parsed.limits.max_entries, MAX_PAGE_ENTRIES),
    })
    parsed = parse_inventory_page(raw, parent.parsed.context, retention, limits=limits, cancel=cancel)
    record = InventoryImport(import_id=_inventory_id(parent.source, parsed, parent.asserted_source, parent.retrieval),
                             source=parent.source, parsed=parsed, asserted_source=parent.asserted_source,
                             retrieval=parent.retrieval)
    return _add(ws, raw, record, INVENTORY_TABLE, InventoryImport, 'inventory', cancel)


def add_support(ws: WorkspaceStore, raw: bytes, page_url: str, *, now: str,
                retrieval: FetchedSource | None = None, cancel=None) -> tuple[SupportImport, bool]:
    """Retain exact saved HTML and its explicit resolution URL without following links."""
    ws._writable()
    _check_cancel(cancel)
    if type(raw) is not bytes:
        raise KbcStoreError('PT-KBC-INPUT', 'support HTML must be supplied as exact bytes')
    if len(raw) > MAX_SUPPORT_BYTES:
        raise KbcStoreError('PT-KBC-LIMIT', 'support HTML exceeds its byte budget')
    digest = _extraction_digest(raw, page_url, cancel)
    receipt = _receipt(raw, 'support-page', retrieval)
    try:
        source = _source(raw, 'kb-support-html', 'support-html/1', now, receipt)
        record = SupportImport(import_id=_support_id(source, page_url, digest, receipt), source=source,
                               page_url=page_url, extraction_sha256=digest, retrieval=receipt)
    except (ValueError, TypeError) as exc:
        raise KbcStoreError('PT-KBC-INPUT', 'the support import URL or provenance is invalid') from exc
    return _add(ws, raw, record, SUPPORT_TABLE, SupportImport, 'support', cancel)


def _get[T: (InventoryImport, SupportImport)](
        ws: WorkspaceStore, import_id: str, table: str, model: type[T],
        verify: bool, cancel) -> T | None:
    _check_cancel(cancel)
    if type(import_id) is not str or _SHA.fullmatch(import_id) is None or type(verify) is not bool:
        raise KbcStoreError('PT-KBC-INPUT', 'an import lookup requires a SHA-256 identifier and boolean verify')
    record = _read_record(ws, table, import_id, model)
    if record is not None and verify:
        _verify(ws, record, cancel)
    _check_cancel(cancel)
    return record


def get_inventory(ws: WorkspaceStore, import_id: str, verify: bool = True, *,
                  cancel=None) -> InventoryImport | None:
    return _get(ws, import_id, INVENTORY_TABLE, InventoryImport, verify, cancel)


def get_support(ws: WorkspaceStore, import_id: str, verify: bool = True, *, cancel=None) -> SupportImport | None:
    return _get(ws, import_id, SUPPORT_TABLE, SupportImport, verify, cancel)


def read_source(ws: WorkspaceStore, record: InventoryImport | SupportImport, *, cancel=None) -> bytes:
    """Re-read exact source bytes under the bounded regular-object guard."""
    _check_cancel(cancel)
    raw = _read_raw(ws, record.source)
    _check_cancel(cancel)
    return raw


def _list[T: (InventoryImport, SupportImport)](
        ws: WorkspaceStore, table: str, model: type[T], limit: int, offset: int,
        verify: bool, cancel) -> tuple[T, ...]:
    _check_cancel(cancel)
    if (type(limit) is not int or not 1 <= limit <= MAX_PAGE_RECORDS or type(offset) is not int
            or not 0 <= offset <= 2**31 - 1 or type(verify) is not bool):
        raise KbcStoreError('PT-KBC-INPUT', 'inventory pagination requires bounded integer limits and offsets')
    if not _exists(ws, table):
        return ()
    # Fetch only identifiers and sizes first: a forged giant row never crosses
    # the SQLite/Python boundary as a JSON string.
    rows = list(_rows(ws, "SELECT CASE WHEN typeof(import_id)='text' AND length(CAST(import_id AS BLOB))=64 "
                      'THEN import_id END,'
                      f'length(CAST(body AS BLOB)) FROM {table} '
                      'ORDER BY import_id LIMIT ? OFFSET ?', (limit, offset)))
    if any(type(import_id) is not str or _SHA.fullmatch(import_id) is None
           or type(size) is not int or size > MAX_RECORD_BYTES for import_id, size in rows):
        raise KbcStoreError('PT-KBC-VERIFY', 'a stored import record exceeds its byte budget')
    if sum(size for _, size in rows) > MAX_PAGE_BYTES:
        raise KbcStoreError('PT-KBC-LIMIT', 'the inventory page exceeds its byte budget; request fewer records')
    records = []
    for import_id, _size in rows:
        record = _get(ws, import_id, table, model, verify, cancel)
        if record is None:
            raise KbcStoreError('PT-KBC-VERIFY', 'an immutable import disappeared during pagination')
        records.append(record)
    return tuple(records)


def list_inventories(ws: WorkspaceStore, *, limit: int = 100, offset: int = 0,
                     verify: bool = False, cancel=None) -> tuple[InventoryImport, ...]:
    """A stable ID-ordered page. Records are strict-validated even when raw replay is disabled."""
    return _list(ws, INVENTORY_TABLE, InventoryImport, limit, offset, verify, cancel)


def list_support(ws: WorkspaceStore, *, limit: int = 100, offset: int = 0,
                  verify: bool = False, cancel=None) -> tuple[SupportImport, ...]:
    return _list(ws, SUPPORT_TABLE, SupportImport, limit, offset, verify, cancel)


def inventory_count(ws: WorkspaceStore) -> int:
    return _query(ws, f'SELECT COUNT(*) FROM {INVENTORY_TABLE}').fetchone()[0] if _exists(ws, INVENTORY_TABLE) else 0


def support_count(ws: WorkspaceStore) -> int:
    return _query(ws, f'SELECT COUNT(*) FROM {SUPPORT_TABLE}').fetchone()[0] if _exists(ws, SUPPORT_TABLE) else 0


def referenced_raw_hashes(ws: WorkspaceStore) -> tuple[str, ...]:
    """Additional raw references for WorkspaceStore's non-destructive orphan report."""
    hashes = set()
    for table in _TABLES:
        if _exists(ws, table):
            for (sha,) in _rows(ws, "SELECT DISTINCT CASE WHEN typeof(sha256)='text' "
                               f'AND length(CAST(sha256 AS BLOB))=64 THEN sha256 END FROM {table}'):
                if type(sha) is not str or _SHA.fullmatch(sha) is None:
                    raise KbcStoreError('PT-KBC-VERIFY', 'an import raw reference is damaged')
                hashes.add(sha)
    return tuple(sorted(hashes))
