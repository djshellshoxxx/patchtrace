"""Bounded owner-thread stored-source capture for Search and Strings.

Consumers receive values only. Existing admission owns evidence selection;
this adapter bounds its input and sidecar I/O without changing legacy readers.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from ...enrichment.identity import canonical_json
from ...enrichment.storage import KINDS, Entry, Guard
from ...owned_publication import DirectoryAnchor, directory_anchor
from ...owned_publication import read_bytes as read_owned_bytes
from ...persistence import strict_json
from .admission import AdmittedToolEvidence, latest_admitted
from .common import (
    EVIDENCE_KIND,
    RUN_KIND,
    ToolError,
    ToolEvidenceSet,
    ToolRun,
    cache_key,
    config_digest,
    evidence_entry_id,
)
from .store import ToolStore

SNAPSHOT_ROWS = 1000
SNAPSHOT_BYTES = 16 * 1024 * 1024
SIDECAR_BYTES = 64 * 1024 * 1024
EVIDENCE_ROWS = {'strings': 200_000, 'capabilities': 20_000, 'environment': 512}
ENGINES = ('floss', 'capa', 'diec')
SIDES = ('older', 'newer')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_FIELDS = (('id', 512), ('kind', 64), ('project_id', 128), ('run_id', 256),
           ('raw_sha256', 256), ('input_digest', 256), ('status', 64), ('created', 64), ('body_sha256', 64))


@dataclass(frozen=True, slots=True)
class CapturedRows:
    rows: tuple[tuple[str, tuple[Entry, ...]], ...]
    errors: tuple[str, ...] = ()

    def entries(self, kind, current=None, on_corrupt=None):
        if kind in self.errors:
            raise ValueError('stored source rows failed bounded integrity capture')
        found = next((rows for taken, rows in self.rows if taken == kind), ())
        return [replace(entry, stale=entry.stale or (current is not None and entry.guard != current))
                for entry in found]


def _evidence_shape(body: dict) -> None:
    if body.keys() - ToolEvidenceSet.model_fields.keys():
        raise ValueError('stored evidence contains unknown fields')
    for name, limit in EVIDENCE_ROWS.items():
        items = body.get(name, [])
        if not isinstance(items, list) or len(items) > limit:
            raise ValueError('stored evidence exceeds its row budget')


def _capture(db, kinds, max_rows, max_bytes):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone() is None:
        return CapturedRows(())
    columns = ','.join(f"CASE WHEN typeof({name})='text' AND length(CAST({name} AS BLOB))<={cap} "
                       f'THEN {name} END' for name, cap in _FIELDS)
    numbers = ("CASE WHEN typeof(project_revision)='integer' AND project_revision>=0 THEN project_revision END,"
               "CASE WHEN typeof(stale)='integer' AND stale IN (0,1) THEN stale END,"
               "CASE WHEN typeof(body)='text' THEN length(CAST(body AS BLOB)) END")
    marks = ','.join('?' for _ in kinds)
    metadata = db.execute(f'SELECT rowid,{columns},{numbers} FROM enrichment_entries '
                          f'WHERE kind IN ({marks}) LIMIT ?', (*kinds, max_rows + 1)).fetchall()
    if len(metadata) > max_rows:
        return CapturedRows((), kinds)
    sizes = [row[-1] for row in metadata]
    if any(type(size) is not int or size < 0 for size in sizes) or sum(sizes) > max_bytes:
        return CapturedRows((), kinds)
    rows, bad = {kind: [] for kind in kinds}, set()
    for number, ident, kind, project_id, run_id, raw_sha, digest, status, created, sha, revision, stale, size in metadata:
        if (any(value is None for value in (ident, kind, project_id, run_id, raw_sha, digest, status,
                                            created, sha, revision, stale)) or not _HASH.fullmatch(sha)):
            bad.update((kind,) if kind in rows else kinds)
            continue
        # The savepoint holds a consistent SQLite read snapshot. Recheck size
        # and hash before returning the body; no unbounded body projection runs.
        got = db.execute("SELECT CASE WHEN typeof(body)='text' AND length(CAST(body AS BLOB))=? THEN body END "
                         'FROM enrichment_entries WHERE rowid=? AND id=? AND body_sha256=?',
                         (size, number, ident, sha)).fetchone()
        try:
            text = None if got is None else got[0]
            if not isinstance(text, str) or hashlib.sha256(text.encode('utf-8')).hexdigest() != sha:
                raise ValueError('stored source body changed')
            body = strict_json(text)
            if type(body) is not dict:
                raise ValueError('stored source body must be an object')
            if kind == EVIDENCE_KIND and body.get('kind') != 'sidecar':
                _evidence_shape(body)
            rows[kind].append(Entry(ident, kind, Guard(project_id, run_id, raw_sha, digest), revision,
                                    status, bool(stale), created, body, text, sha))
        except (ValueError, RecursionError):
            bad.add(kind)
    return CapturedRows(tuple((kind, tuple(sorted(sorted(found, key=lambda row: row.id),
                                                  key=lambda row: row.created, reverse=True)))
                              for kind, found in rows.items()), tuple(sorted(bad)))


def capture_rows(service, kinds, *, max_rows=None, max_bytes=None) -> CapturedRows:
    """Capture a bounded read snapshot without committing the owner's writes."""
    max_rows = SNAPSHOT_ROWS if max_rows is None else max_rows
    max_bytes = SNAPSHOT_BYTES if max_bytes is None else max_bytes
    if (not isinstance(kinds, (tuple, list)) or not 0 < len(kinds) <= 8
            or any(type(kind) is not str or kind not in KINDS for kind in kinds)
            or len(set(kinds)) != len(kinds) or type(max_rows) is not int or not 0 < max_rows <= SNAPSHOT_ROWS
            or type(max_bytes) is not int or not 0 < max_bytes <= SNAPSHOT_BYTES):
        raise ValueError('stored capture requires bounded kinds, rows and bytes')
    db = service.store.connection
    db.execute('SAVEPOINT patchtrace_stored_source_capture')
    try:
        return _capture(db, tuple(kinds), max_rows, max_bytes)
    finally:
        db.execute('RELEASE patchtrace_stored_source_capture')


@dataclass
class ReadBudget:
    remaining: int = SIDECAR_BYTES
    root: Path | None = None
    touched: bool = field(default=False, init=False)
    exhausted: bool = field(default=False, init=False)
    anchor: DirectoryAnchor | None = field(default=None, init=False)

    def __post_init__(self):
        if type(self.remaining) is not int or not 0 <= self.remaining <= SIDECAR_BYTES:
            raise ValueError('invalid stored sidecar byte budget')
        if self.root is not None:
            self.root = Path(os.path.abspath(self.root))
            self.anchor = directory_anchor(self.root)

    def read(self, path: Path, maximum: int, sha: str) -> bytes:
        self.touched = True
        if (type(maximum) is not int or not 0 < maximum <= SIDECAR_BYTES
                or not isinstance(sha, str) or not _HASH.fullmatch(sha)):
            raise ValueError('invalid stored source sidecar identity')
        cap = min(maximum, self.remaining)
        if cap <= 0:
            self.exhausted = True
            raise ValueError('stored source sidecar byte budget exhausted')
        self.remaining -= cap  # failures cannot spend the same allowance again

        def check(data):
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError('stored source sidecar failed its digest')

        data = read_owned_bytes(path, maximum=cap, validate=check, anchor=self.anchor)
        self.remaining += cap - len(data)
        return data


class StoredTools(ToolStore):
    """Existing current admission over bounded rows and held sidecar reads."""

    def __init__(self, *args, artifacts, budget: ReadBudget, **kwargs):
        super().__init__(*args, **kwargs)
        self.artifacts, self.budget = artifacts, budget

    def _load(self, body):
        sha, size = body.get('sidecar_sha256'), body.get('size')
        if type(size) is int and size > min(SIDECAR_BYTES, self.budget.remaining):
            self.budget.exhausted = True
            raise ToolError('PT-TOOL-LIMIT', 'stored tool sidecar exceeds the capture byte budget')
        fields = {'contract', 'kind', 'run_id', 'engine', 'side', 'artifact_sha256', 'cache_key',
                  'config_digest', 'sidecar', 'sidecar_sha256', 'size', 'counts'}
        if (body.keys() != fields or not isinstance(sha, str) or not _HASH.fullmatch(sha)
                or type(size) is not int or not 0 < size <= min(SIDECAR_BYTES, self.budget.remaining)
                or body.get('sidecar') != f'intel-tools/{sha}.json'):
            raise ValueError('invalid stored tool sidecar identity')
        data = self.budget.read(self.project_dir / body['sidecar'], size, sha)
        if len(data) != size:
            raise ValueError('stored tool sidecar has changed size')
        value = strict_json(data)
        if type(value) is not dict:
            raise ValueError('stored tool evidence must be an object')
        _evidence_shape(value)
        evidence = ToolEvidenceSet.model_validate_json(data)
        header = ('contract', 'run_id', 'engine', 'side', 'artifact_sha256', 'cache_key', 'config_digest', 'counts')
        if canonical_json({key: body[key] for key in header}) != canonical_json(
                {key: getattr(evidence, key) for key in header}):
            raise ValueError('stored sidecar header differs from its evidence')
        return evidence

    @staticmethod
    def _producer(run: ToolRun):
        if (not run.manifest.supported or run.config_digest != config_digest(run.manifest, run.options)
                or run.cache_key != cache_key(run.input_artifact_hash, run.manifest, run.options)
                or run.raw_sidecar is not None and (run.stdout_digest is None
                    or run.raw_sidecar != f'intel-tools/raw/{run.engine}-{run.stdout_digest}.json')):
            raise ToolError('PT-TOOL-STALE', 'stored producer configuration or raw identity changed')

    def admitted(self, engine, side):
        found = latest_admitted(self, engine=engine, side=side, artifact_sha256=self.artifacts.get(side))
        if found is None:
            return None
        self._producer(found.run)
        self._producer(found.evidence_run)
        if (found.evidence_run.cache_hit or found.run.manifest.identity() != found.evidence_run.manifest.identity()
                or found.run.options != found.evidence_run.options):
            raise ToolError('PT-TOOL-STALE', 'stored cache origin is not its compatible producing run')
        identities = {found.run.run_id, found.evidence_run.run_id, evidence_entry_id(found.evidence)}
        if any(entry.project_revision > self.revision for kind in (RUN_KIND, EVIDENCE_KIND)
               for entry in self.enrichment.entries(kind) if entry.id in identities):
            raise ToolError('PT-TOOL-STALE', 'stored tool row is from a future project revision')
        return found

    def latest(self, engine, side):
        found = self.admitted(engine, side)
        return None if found is None else (found.run, found.evidence)


@dataclass(frozen=True, slots=True)
class ToolSources:
    found: tuple[tuple[tuple[str, str], AdmittedToolEvidence], ...] = ()
    failures: tuple[tuple[str, str, str], ...] = ()
    captured_engines: tuple[str, ...] = ENGINES
    capture_error: str | None = None

    def require_capture(self) -> None:
        if self.capture_error is not None:
            raise ToolError('PT-TOOL-OUTPUT', f'stored source capture is unavailable ({self.capture_error})')

    def admitted(self, engine: str, side: str) -> AdmittedToolEvidence | None:
        if engine not in ENGINES or side not in SIDES:
            raise ToolError('PT-TOOL-OUTPUT', 'unknown stored tool source')
        if engine not in self.captured_engines:
            raise ToolError('PT-TOOL-OUTPUT', 'this tool source was not captured')
        reason = next((reason for failed_engine, failed_side, reason in self.failures
                       if (failed_engine, failed_side) == (engine, side)), None)
        if reason is not None:
            raise ToolError('PT-TOOL-OUTPUT', f'stored {engine} evidence for {side} is unavailable ({reason})')
        return next((value for where, value in self.found if where == (engine, side)), None)

    def latest(self, engine: str, side: str):
        found = self.admitted(engine, side)
        return None if found is None else (found.run, found.evidence)


def capture_tool_sources(service, *, engines=ENGINES) -> ToolSources:
    """Owner-thread I/O only here; returned latest/admitted methods use values only."""
    if (not isinstance(engines, (tuple, list)) or len(engines) > len(ENGINES)
            or any(type(engine) is not str or engine not in ENGINES for engine in engines)
            or len(set(engines)) != len(engines)):
        raise ValueError('engines must be a bounded unique selection of stored tools')
    engines = tuple(engines)
    if not engines or getattr(service, 'store', None) is None:
        return ToolSources(captured_engines=engines)
    found, failures = [], []
    try:
        project = service.project
        rows = capture_rows(service, (RUN_KIND, EVIDENCE_KIND))
        budget = ReadBudget(remaining=SIDECAR_BYTES, root=Path(service.root))
        store = StoredTools(rows, Path(service.root), project.id, project.revision,
            artifacts={artifact.side: artifact.sha256 for artifact in project.artifacts},
            budget=budget)
    except Exception as exc:  # fault boundary: unusable persisted input is never missing output
        reason = str(getattr(exc, 'code', '') or type(exc).__name__)[:40]
        return ToolSources(failures=tuple((engine, side, reason) for engine in engines for side in SIDES),
                           captured_engines=engines, capture_error=reason)
    for engine in engines:
        for side in SIDES:
            try:
                item = store.admitted(engine, side)
            except Exception as exc:  # preserve independently admitted opposite-side output
                failures.append((engine, side, str(getattr(exc, 'code', '') or type(exc).__name__)[:40]))
            else:
                if item is not None:
                    found.append(((engine, side), item))
    capture_error = 'stored rows failed bounded integrity capture' if rows.errors else (
        'stored sidecar byte budget exhausted' if budget.exhausted else None)
    return ToolSources(tuple(found), tuple(failures), engines, capture_error)
