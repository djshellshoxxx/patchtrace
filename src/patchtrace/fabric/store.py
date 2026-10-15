"""Enrichment-backed anchor store: `AnchorSink` and `AnchorReader` over the rows of kind `anchor-batch`
(FAB-integration-plan.md s7 "Store as built").

One row holds what one (producer, batch) published, so replacing a batch is replacing a row. The behaviour of the ports
is `MemoryAnchorStore`'s: this store keeps that reference loaded with the verified, merged rows of the project and
persists what a publish or retraction changes, so publish checks, replacement, merge, `find` and `resolve` are the same
code and cannot drift. The older and newer hashes come from the saved project on every call, so the orientation check
cannot be skipped.

Reading never fails a batch for one anchor: an anchor that does not validate (written by a newer version), fails
`verify_anchor`, holds a witness of another batch or was made for the other orientation of the pair is skipped and
counted; a row that cannot be read at all is listed unreadable. Stale batches (an origin table that moved since they
were stored, or a guard stored moved) are listed with their flag and their anchors are still returned. Reading deletes
nothing and creates nothing.

Writing validates the whole call (the reference checks, then the row cap) before the first write; rows are then written
one transaction each, so a crash between two rows leaves a state that repeating the call completes.

Thread ownership: like every enrichment store, a store uses the project connection and must be used on the thread that
owns it.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..enrichment.contracts import EnrichmentError
from ..enrichment.identity import domain_id
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from .contracts import (
    PROJECT_ID,
    SHA256_RE,
    Anchor,
    AnchorPage,
    AnchorQuery,
    Batch,
    Producer,
    PublishReport,
    Resolution,
    Sha256,
)
from .ids import anchors_digest, check_orientation, verify_anchor
from .limits import DEFAULT_LIMITS, FabricError, FabricLimits
from .memory import MemoryAnchorStore
from .origins import DefaultOriginRegistry
from .ports import OriginRegistry

KIND = 'anchor-batch'
CONTRACT = 'fabric-batch/1'
GUARD_RUN = 'fabric'  # a batch describes the project's two images, not one Ghidriff run
BATCH_DOMAIN = 'fabric-batch'
MAX_BODY_BYTES = 24 * 1024 * 1024  # the enrichment row limit is 32 MiB
_L = DEFAULT_LIMITS
_ROW_ID = re.compile(r'fabric:([a-z0-9]+):(.+)')


# --- the persisted contract ---------------------------------------------------------------------------------------

class StrictModel(BaseModel):
    """The base of the persisted fabric rows: no extra fields, nothing coerced, frozen."""
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class BatchHead(StrictModel):
    """What identifies a stored batch. A reader validates this strictly and the anchors one by one."""
    contract: Literal['fabric-batch/1'] = CONTRACT
    producer: Producer
    batch: Batch
    origins_digest: Sha256


class FabricBatch(BatchHead):
    """Body of an `anchor-batch` row: the anchors of one (producer, batch), each holding only that batch's witnesses.
    `origins_digest` names the origin table the witnesses' tags were checked against."""
    anchors: tuple[Anchor, ...] = Field(min_length=1, max_length=_L.f01_anchors_per_publish)

    @model_validator(mode='after')
    def _canonical_and_own(self):
        anchor_ids = [anchor.anchor_id for anchor in self.anchors]
        if anchor_ids != sorted(set(anchor_ids)):
            raise ValueError('anchors must be sorted and unique by anchor_id')
        if any((w.producer, w.batch) != (self.producer, self.batch) for a in self.anchors for w in a.witnesses):
            raise ValueError('every witness belongs to the producer and batch of its row')
        return self


@dataclass(frozen=True, slots=True)
class BatchStatus:
    """One stored batch as this reader sees it: the anchors it took, the ones it skipped (unknown to it, damaged, held
    for another batch or made for the other orientation), whether the batch is stale and whether the row was read."""
    row_id: str
    producer: str
    batch: str
    anchors: int
    skipped: int
    stale: bool
    readable: bool


def row_id(producer: str, batch: str) -> str:
    return f'fabric:{producer}:{batch}'


def batch_digest(producer: str, batch: str, origins_digest: str, anchors: Iterable[Anchor]) -> str:
    """The `input_digest` of a row's guard."""
    return domain_id(BATCH_DOMAIN, 1, {'producer': producer, 'batch': batch, 'origins_digest': origins_digest,
                                       'anchors_digest': anchors_digest(anchors)})


# --- the project and the rows -------------------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ProjectFacts:
    id: str
    revision: int
    pair: tuple[str, str]  # (older, newer) SHA-256


def storage_error(reason: str, message: str) -> FabricError:
    return FabricError('PT-FAB-STORAGE', message, reason=reason)


def _read_only_error() -> FabricError:
    return FabricError('PT-FAB-STALE', 'The project data was written by a newer PatchTrace and is read only',
                       reason='read-only-store')


def _from_enrichment(exc: EnrichmentError) -> FabricError:
    if exc.code == 'PT-ENRICH-LIMIT':
        return FabricError('PT-FAB-LIMIT', 'The project cannot hold more enrichment data', reason='project-bytes')
    if exc.code == 'PT-ENRICH-STALE':
        return _read_only_error()
    return storage_error('enrichment', 'The enrichment store refused the anchor rows')


@contextmanager
def as_fabric_errors() -> Iterator[None]:
    try:
        yield
    except EnrichmentError as exc:
        raise _from_enrichment(exc) from exc
    except sqlite3.Error as exc:
        raise storage_error('sqlite', 'The project database could not be used') from exc


def _has_table(db: sqlite3.Connection) -> bool:
    found = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone()
    return found is not None


def _saved_project(db: sqlite3.Connection) -> ProjectFacts | None:
    """The project id, revision and (older, newer) hashes of the saved snapshot; None when it names no project."""
    row = db.execute("SELECT json_extract(payload, '$.id'), json_extract(payload, '$.revision'), "
                     "json_extract(payload, '$.artifacts') FROM current_snapshot WHERE singleton=1").fetchone()
    if not isinstance(row[0], str):
        return None
    if not PROJECT_ID.fullmatch(row[0]):
        raise storage_error('project-id', 'The project id cannot be used as a project key')
    try:
        sides = {artifact['side']: artifact['sha256'] for artifact in json.loads(row[2])}
        pair = (sides['older'], sides['newer'])
    except (TypeError, ValueError, KeyError):
        raise storage_error('project-pair', 'The project does not name one older and one newer artifact') from None
    if not all(isinstance(sha, str) and SHA256_RE.fullmatch(sha) for sha in pair):
        raise storage_error('project-pair', 'The project does not name one older and one newer artifact')
    return ProjectFacts(row[0], row[1] if isinstance(row[1], int) else 0, pair)


def _row_meta(db: sqlite3.Connection) -> tuple:
    """What decides whether a loaded view is still the stored state, without reading a single body."""
    if not _has_table(db):
        return ()
    return tuple(db.execute('SELECT id, body_sha256, stale, project_id FROM enrichment_entries WHERE kind=? '
                            'ORDER BY id', (KIND,)).fetchall())


def _check_key(project_key: object) -> str:
    if not isinstance(project_key, str) or not PROJECT_ID.fullmatch(project_key):
        raise FabricError('PT-FAB-INPUT', 'The project key is not a project id', reason='project-key')
    return project_key


class ProjectAccess:
    """The project database of an enrichment store as the fabric uses it, shared by the batch store and the pin store:
    the checks that it is open and used on its own thread, the saved project (a snapshot can be megabytes, so it is
    parsed again only when its hash moved) and the check that a key names this project."""

    def __init__(self, enrichment: EnrichmentStore):
        self.enrichment = enrichment
        self._facts: tuple[str | None, ProjectFacts | None] | None = None  # (snapshot hash, what it says)

    def db(self) -> sqlite3.Connection:
        store = self.enrichment.store
        if store.closed:
            raise storage_error('project-closed', 'The project is closed')
        try:
            store.connection.execute('SELECT 1').fetchone()
        except sqlite3.ProgrammingError:
            raise storage_error('wrong-thread', 'Anchors are used only on the thread that owns the project') from None
        return store.connection

    def open(self, project_key: str) -> tuple[sqlite3.Connection, ProjectFacts | None]:
        """The connection and the saved project (None when it was never saved) for a key that names this project."""
        key = _check_key(project_key)
        db = self.db()
        with as_fabric_errors():
            row = db.execute('SELECT sha256 FROM current_snapshot WHERE singleton=1').fetchone()
            snapshot = None if row is None else row[0]
            if self._facts is None or self._facts[0] != snapshot:
                self._facts = (snapshot, None if snapshot is None else _saved_project(db))
            project = self._facts[1]
        if project is not None and key != project.id:
            raise FabricError('PT-FAB-INPUT', 'The key names another project than this database holds',
                              reason='foreign-project')
        return db, project


# --- reading a row ------------------------------------------------------------------------------------------------

def _head(entry: Entry, project_id: str) -> BatchHead | None:
    """The validated identity of a readable row, else None: wrong project, not a batch body, a contract or fields this
    version does not know, or a body that is not the one its row id names."""
    body = entry.body
    if entry.guard.project_id != project_id or not isinstance(body, dict) or not isinstance(body.get('anchors'), list):
        return None
    try:
        head = BatchHead.model_validate({name: value for name, value in body.items() if name != 'anchors'})
    except ValidationError:
        return None
    return head if entry.id == row_id(head.producer, head.batch) else None


def _anchor(raw: object, head: BatchHead, pair: tuple[str, str]) -> Anchor | None:
    """One stored anchor, or None: it must validate in JSON mode, certify its own ids, hold only the witnesses of its
    batch and agree with the orientation of the project's pair."""
    try:
        anchor = Anchor.model_validate_json(json.dumps(raw))
        verify_anchor(anchor)
        check_orientation(anchor, *pair)
    except (ValueError, FabricError):  # a ValidationError is a ValueError
        return None
    own = all((w.producer, w.batch) == (head.producer, head.batch) for w in anchor.witnesses)
    return anchor if own else None


def _unreadable(entry_id: str) -> BatchStatus:
    found = _ROW_ID.fullmatch(entry_id)
    producer, batch = found.groups() if found else ('', entry_id)
    return BatchStatus(entry_id, producer, batch, anchors=0, skipped=0, stale=False, readable=False)


# --- writing a row ------------------------------------------------------------------------------------------------

def _rows_of(batch: Iterable[Anchor]) -> dict[tuple[str, str], tuple[Anchor, ...]]:
    """A call cut into one anchor list per (producer, batch): each anchor with only that batch's witnesses, equal
    anchors joined, in `anchor_id` order."""
    cut: dict[tuple[str, str], dict[str, Anchor]] = {}
    for anchor in batch:
        for key in {(w.producer, w.batch) for w in anchor.witnesses}:
            rows = cut.setdefault(key, {})
            mine = {w.witness_id: w for w in anchor.witnesses if (w.producer, w.batch) == key}
            if anchor.anchor_id in rows:
                mine |= {w.witness_id: w for w in rows[anchor.anchor_id].witnesses}
            rows[anchor.anchor_id] = anchor.model_copy(update={'witnesses': tuple(mine[i] for i in sorted(mine))})
    return {key: tuple(rows[i] for i in sorted(rows)) for key, rows in sorted(cut.items())}


class _Engine(MemoryAnchorStore):
    """The reference store, loaded with the verified rows of one project instead of filled by `publish`."""

    def __init__(self, project: ProjectFacts | None, anchors: Mapping[str, Anchor], registry: OriginRegistry,
                 limits: FabricLimits):
        super().__init__(registry, limits)
        if project is not None:
            self.bind_pair(project.id, *project.pair)
            if anchors:
                self._projects[project.id] = anchors  # the state `publish` would have built from these rows


@dataclass(frozen=True, slots=True)
class _View:
    signature: tuple
    engine: _Engine
    batches: tuple[BatchStatus, ...]


class EnrichmentAnchorStore:
    """`AnchorSink` and `AnchorReader` over one project's `anchor-batch` rows. It answers for the project of its
    database only (another key is `PT-FAB-INPUT` reason `foreign-project`); `registry` and `limits` are the reference's.
    `digest` is the cache-key input of consumers and `batches` lists the stored batches with their flags."""

    def __init__(self, enrichment: EnrichmentStore, registry: OriginRegistry | None = None,
                 limits: FabricLimits = DEFAULT_LIMITS):
        self._enrichment = enrichment
        self._access = ProjectAccess(enrichment)
        self._registry = DefaultOriginRegistry() if registry is None else registry
        self._origins_digest = self._registry.digest()
        self._limits = limits
        self._view: _View | None = None

    # --- AnchorSink ---------------------------------------------------------------------------------------------

    def publish(self, project_key: str, anchors: Iterable[Anchor]) -> PublishReport:
        project, view = self._current(project_key)
        if project is None:
            raise storage_error('project-unsaved', 'The project has no saved snapshot to hold anchors')
        batch = tuple(anchors) if isinstance(anchors, Iterable) else anchors
        report = view.engine.publish(project_key, batch)
        self._view = None  # the reference now holds what is not stored yet: read the rows again
        prepared = [self._prepare(project, key, rows) for key, rows in _rows_of(batch).items()]
        for entry_id, guard, body in prepared:
            with as_fabric_errors():
                self._enrichment.publish(KIND, guard, guard, project.revision, 'complete', body, entry_id)
        return report

    def retract(self, project_key: str, producer: str, batch: str) -> PublishReport:
        project, view = self._current(project_key)
        report = view.engine.retract(project_key, producer, batch)
        if project is None:
            return report
        self._view = None
        db = self._access.db()
        with as_fabric_errors():
            if _has_table(db):
                self._enrichment.ensure()
                if self._enrichment.read_only:
                    raise _read_only_error()
                with db:
                    db.execute('DELETE FROM enrichment_entries WHERE id=? AND kind=?', (row_id(producer, batch), KIND))
        return report

    def _prepare(self, project: ProjectFacts, key: tuple[str, str], anchors: tuple[Anchor, ...]
                 ) -> tuple[str, Guard, dict]:
        producer, batch = key
        if len(anchors) > _L.f01_anchors_per_publish:
            raise FabricError('PT-FAB-LIMIT', 'A batch holds more anchors than a row may', reason='publish-size')
        body = FabricBatch(producer=producer, batch=batch, origins_digest=self._origins_digest,
                           anchors=anchors).model_dump(mode='json')
        text = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
        if len(text.encode('utf-8')) > MAX_BODY_BYTES:
            raise FabricError('PT-FAB-LIMIT', 'A batch is larger than a stored row may be', reason='row-size')
        guard = Guard(project.id, GUARD_RUN, '', batch_digest(producer, batch, self._origins_digest, anchors))
        return row_id(producer, batch), guard, body

    # --- AnchorReader -------------------------------------------------------------------------------------------

    def get(self, project_key: str, anchor_id: str) -> Anchor | None:
        return self._current(project_key)[1].engine.get(project_key, anchor_id)

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        return self._current(project_key)[1].engine.find(project_key, query)

    def resolve(self, project_key: str, kind: str, value: str | None, side: str | None) -> Resolution:
        return self._current(project_key)[1].engine.resolve(project_key, kind, value, side)

    # --- beyond the ports ---------------------------------------------------------------------------------------

    def digest(self, project_key: str) -> str:
        """Order-independent digest of every anchor and witness this reader holds for the project."""
        return self._current(project_key)[1].engine.digest(project_key)

    def batches(self, project_key: str) -> tuple[BatchStatus, ...]:
        """Every stored batch, by row id, with its flags: stale batches and unreadable rows are listed, never hidden."""
        return self._current(project_key)[1].batches

    # --- loading ------------------------------------------------------------------------------------------------

    def _current(self, project_key: str) -> tuple[ProjectFacts | None, _View]:
        """The saved project and a view of its rows that is still the stored state (loaded again when it is not)."""
        db, project = self._access.open(project_key)
        with as_fabric_errors():
            identity = None if project is None else (project.id, project.pair)  # not the revision: every save moves it
            signature = (identity, _row_meta(db))
            if self._view is None or self._view.signature != signature:
                self._view = self._load(project, signature)
        return project, self._view

    def _load(self, project: ProjectFacts | None, signature: tuple) -> _View:
        merged: dict[str, Anchor] = {}
        statuses: list[BatchStatus] = []
        if project is not None:
            corrupt: list[str] = []
            entries = self._enrichment.entries(KIND, on_corrupt=corrupt.append)
            statuses = [_unreadable(entry_id) for entry_id in corrupt]
            statuses += [self._read(entry, project, merged) for entry in sorted(entries, key=lambda e: e.id)]
        engine = _Engine(project, merged, self._registry, self._limits)
        return _View(signature, engine, tuple(sorted(statuses, key=lambda status: status.row_id)))

    def _read(self, entry: Entry, project: ProjectFacts, merged: dict[str, Anchor]) -> BatchStatus:
        head = _head(entry, project.id)
        if head is None:
            return _unreadable(entry.id)
        taken = skipped = 0
        for raw in entry.body['anchors']:
            anchor = _anchor(raw, head, project.pair)
            if anchor is not None and self._merge(merged, anchor):
                taken += 1
            else:
                skipped += 1
        stale = entry.stale or head.origins_digest != self._origins_digest
        return BatchStatus(entry.id, head.producer, head.batch, taken, skipped, stale, readable=True)

    def _merge(self, merged: dict[str, Anchor], anchor: Anchor) -> bool:
        """Join the witnesses of equal anchors from different batches; False when that would pass F-03."""
        known = merged.get(anchor.anchor_id)
        witnesses = {w.witness_id: w for w in (known.witnesses if known else ())}
        witnesses |= {w.witness_id: w for w in anchor.witnesses}
        if len(witnesses) > self._limits.f03_witnesses_per_anchor:
            return False
        merged[anchor.anchor_id] = anchor if known is None else known.model_copy(
            update={'witnesses': tuple(witnesses[i] for i in sorted(witnesses))})
        return True
