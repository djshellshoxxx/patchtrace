"""Bounded owner-thread capture of stored tool sources for read-only consumers.

The returned values hold no service, store, connection or open artifact handle.
Search and Strings share the same evidence admission; no tool or target executes.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from ...enrichment.identity import canonical_json
from ...enrichment.storage import Entry, Guard
from ...ingestion import safe_path
from ...owned_publication import read_bytes as read_owned_bytes
from ...persistence import strict_json
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
from .normalize import validate_set
from .store import ToolStore

SNAPSHOT_ROWS = 1000
SNAPSHOT_BYTES = 16 * 1024 * 1024
SIDECAR_BYTES = 64 * 1024 * 1024
EVIDENCE_ROWS = {'strings': 200_000, 'capabilities': 20_000, 'environment': 512}
ENGINES = ('floss', 'capa', 'diec')
SIDES = ('older', 'newer')
_HASH = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True, slots=True)
class CapturedRows:
    rows: tuple[tuple[str, tuple[Entry, ...]], ...]
    errors: tuple[str, ...] = ()

    def entries(self, kind, current=None, on_corrupt=None):
        if kind in self.errors:
            raise ValueError('stored source rows failed bounded integrity capture')
        found = next((rows for taken, rows in self.rows if taken == kind), ())
        return [replace(entry, stale=entry.stale or (current is not None and entry.guard != current)) for entry in found]



def capture_rows(service, kinds, *, max_rows: int = SNAPSHOT_ROWS, max_bytes: int = SNAPSHOT_BYTES) -> CapturedRows:
    """Bound metadata and bodies independently; no unbounded fetchall precedes admission."""
    db = service.store.connection
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone() is None:
        return CapturedRows(())
    # Bound text metadata too: a malformed id or guard is not allowed to allocate an arbitrary payload.
    fields = [('id', 512), ('kind', 64), ('project_id', 128), ('run_id', 256),
              ('raw_sha256', 256), ('input_digest', 256), ('status', 64), ('created', 64), ('body_sha256', 64)]
    columns = ','.join(f'CASE WHEN typeof({name})=\'text\' AND length(CAST({name} AS BLOB))<={cap} '
                       f'THEN {name} END' for name, cap in fields)
    marks = ','.join('?' for _ in kinds)
    metadata = db.execute(f'SELECT rowid,{columns},project_revision,stale,length(CAST(body AS BLOB)) '
                          f'FROM enrichment_entries WHERE kind IN ({marks}) LIMIT ?',
                          (*kinds, max_rows + 1)).fetchall()
    if len(metadata) > max_rows:
        return CapturedRows((), kinds)
    sizes = [row[-1] for row in metadata]
    if any(type(size) is not int or size < 0 for size in sizes) or sum(sizes) > max_bytes:
        return CapturedRows((), kinds)
    rows = {kind: [] for kind in kinds}
    bad = set()
    for number, ident, kind, project_id, run_id, raw_sha, input_digest, status, created, sha, revision, stale, size in metadata:
        if (any(value is None for value in (ident, kind, project_id, run_id, raw_sha, input_digest, status, created, sha))
                or project_id != service.project.id or not _HASH.fullmatch(sha)
                or type(revision) is not int or revision < 0 or stale not in (0, 1)):
            bad.add(kind)
            continue
        # Re-check size in SQLite before returning bytes to Python. A raced replacement cannot evade the first bound.
        got = db.execute('SELECT CASE WHEN typeof(body)=\'text\' AND length(CAST(body AS BLOB))=? THEN body END '
                         'FROM enrichment_entries WHERE rowid=? AND id=? AND body_sha256=?',
                         (size, number, ident, sha)).fetchone()
        try:
            text = None if got is None else got[0]
            if not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != sha:
                raise ValueError('stored source body changed')
            body = strict_json(text)
            if not isinstance(body, dict):
                raise ValueError('stored source body is not an object')
            if kind == RUN_KIND:
                if len(body) > len(ToolRun.model_fields) or body.keys() - ToolRun.model_fields.keys():
                    raise ValueError('stored tool run contains unknown fields')
                ToolRun.model_validate_json(text)
            rows[kind].append(Entry(ident, kind, Guard(project_id, run_id, raw_sha, input_digest),
                                   revision, status, bool(stale), created, body, text, sha))
        except (ValueError, RecursionError):
            bad.add(kind)
    return CapturedRows(tuple((kind, tuple(sorted(sorted(found, key=lambda entry: entry.id),
                                                   key=lambda entry: entry.created, reverse=True)))
                               for kind, found in rows.items()), tuple(sorted(bad)))



@dataclass
class ReadBudget:
    remaining: int = SIDECAR_BYTES
    touched: bool = False

    def read(self, path: Path, maximum: int, sha: str) -> bytes:
        self.touched = True
        cap = min(maximum, self.remaining)
        if cap <= 0:
            raise ValueError('stored source sidecar byte budget exhausted')

        def check(data):
            if hashlib.sha256(data).hexdigest() != sha:
                raise ValueError('stored source sidecar failed its digest')

        data = read_owned_bytes(path, maximum=cap, validate=check)
        self.remaining -= len(data)
        return data



class StoredTools(ToolStore):
    """Current tool models over bounded immutable rows and verified sidecars, without fallback on corrupt output."""

    def __init__(self, *args, artifacts, budget, **kwargs):
        super().__init__(*args, **kwargs)
        self.artifacts, self.budget = artifacts, budget

    def _guard(self, entry, *, kind, identity, artifact, key, status):
        if (entry.kind != kind or entry.id != identity or entry.guard != self.guard(artifact, key)
                or entry.status != status or entry.stale or entry.project_revision > self.revision):
            raise ValueError('stored tool row does not bind its declared content')

    def runs(self, engine=None, side=None):
        out = []
        for entry in self.enrichment.entries(RUN_KIND):
            run = ToolRun.model_validate_json(entry.body_json or json.dumps(entry.body))
            if (engine is not None and run.engine != engine) or (side is not None and run.side != side):
                continue
            self._guard(entry, kind=RUN_KIND, identity=run.run_id, artifact=run.input_artifact_hash,
                        key=run.cache_key, status=run.status)
            if (run.config_digest != config_digest(run.manifest, run.options)
                    or run.cache_key != cache_key(run.input_artifact_hash, run.manifest, run.options)):
                raise ValueError('stored tool run has changed producer configuration')
            if run.status in ('ok', 'none-found') and not run.manifest.supported:
                raise ValueError('stored produced run has no supported producer')
            if run.raw_sidecar is not None and (
                    run.stdout_digest is None
                    or run.raw_sidecar != f'intel-tools/raw/{run.engine}-{run.stdout_digest}.json'):
                raise ValueError('stored tool raw provenance differs from its stdout digest')
            out.append(run)
        return out

    def _load(self, body):
        pointer = None
        if body.get('kind') == 'sidecar':
            pointer = body
            sha, size = body.get('sidecar_sha256'), body.get('size')
            if (body.keys() != {'contract', 'kind', 'run_id', 'engine', 'side', 'artifact_sha256', 'cache_key',
                               'config_digest', 'sidecar', 'sidecar_sha256', 'size', 'counts'}
                    or not isinstance(sha, str) or not _HASH.fullmatch(sha) or type(size) is not int
                    or not 0 < size <= min(SIDECAR_BYTES, self.budget.remaining) or body.get('sidecar') != f'intel-tools/{sha}.json'):
                raise ValueError('invalid stored tool sidecar identity')
            data = self.budget.read(safe_path(self.project_dir, body['sidecar']), size, sha)
            if len(data) != size:
                raise ValueError('stored tool sidecar has changed size')
            body = strict_json(data)
        if (not isinstance(body, dict) or len(body) > len(ToolEvidenceSet.model_fields)
                or body.keys() - ToolEvidenceSet.model_fields.keys()):
            raise ValueError('stored tool evidence must contain known object fields')
        for field, limit in EVIDENCE_ROWS.items():
            rows = body.get(field, [])
            if not isinstance(rows, list) or len(rows) > limit:
                raise ValueError('stored tool evidence exceeds its row budget')
        evidence = ToolEvidenceSet.model_validate_json(json.dumps(body, allow_nan=False))
        if pointer is not None:
            fields = ('contract', 'run_id', 'engine', 'side', 'artifact_sha256', 'cache_key', 'config_digest', 'counts')
            if canonical_json({field: pointer[field] for field in fields}) != canonical_json(
                    {field: getattr(evidence, field) for field in fields}):
                raise ValueError('stored tool sidecar header differs from its evidence')
        return evidence

    def latest(self, engine, side):
        runs = self.runs(engine, side)
        run = next((run for run in runs if run.side == side and run.status in ('ok', 'none-found')), None)
        if run is None:
            return None
        if self.artifacts.get(side) != run.input_artifact_hash:
            raise ValueError('stored tool run describes another artifact')
        for entry in self.enrichment.entries(EVIDENCE_KIND):
            body = entry.body
            selected = (body.get('cache_key') == run.cache_key or entry.guard.input_digest == run.cache_key) \
                if run.cache_hit else body.get('run_id') == run.run_id
            if not selected:
                continue
            evidence = validate_set(self._load(body), artifact_sha256=run.input_artifact_hash,
                                    cache_key=run.cache_key, engine=engine)
            self._guard(entry, kind=EVIDENCE_KIND, identity=evidence_entry_id(evidence),
                        artifact=evidence.artifact_sha256, key=evidence.cache_key, status='ok')
            count = evidence.evidence_count()
            if (evidence.side != side or evidence.config_digest != run.config_digest
                    or run.evidence_count != count or run.status != ('ok' if count else 'none-found')):
                raise ValueError('stored tool evidence does not bind its run')
            producer = next((item for item in runs if item.run_id == evidence.run_id), None)
            if (producer is None or producer.cache_hit or producer.status != run.status
                    or producer.evidence_count != count or producer.side != side
                    or producer.input_artifact_hash != run.input_artifact_hash
                    or producer.config_digest != run.config_digest or producer.cache_key != run.cache_key
                    or producer.manifest.identity() != run.manifest.identity() or producer.options != run.options
                    or (not run.cache_hit and producer.run_id != run.run_id)):
                raise ValueError('stored tool evidence has no compatible producing run')
            return run, evidence
        raise ToolError('PT-TOOL-STALE', 'no stored evidence for the newest produced run')



@dataclass(frozen=True, slots=True)
class ToolSources:
    found: tuple[tuple[tuple[str, str], tuple[Any, Any]], ...] = ()
    failures: tuple[tuple[str, str, str], ...] = ()
    captured_engines: tuple[str, ...] = ENGINES

    def latest(self, engine: str, side: str):
        if engine not in ENGINES or side not in SIDES:
            raise ToolError('PT-TOOL-OUTPUT', 'unknown stored tool source')
        if engine not in self.captured_engines:
            raise ToolError('PT-TOOL-OUTPUT', 'this tool source was not captured')
        reason = next((reason for failed_engine, failed_side, reason in self.failures
                       if (failed_engine, failed_side) == (engine, side)), None)
        if reason is not None:
            raise ToolError('PT-TOOL-OUTPUT', f'stored {engine} evidence for {side} is unavailable ({reason})')
        return next((pair for where, pair in self.found if where == (engine, side)), None)


def capture_tool_sources(service, *, engines=ENGINES) -> ToolSources:
    """Owner thread only: capture selected engines, keeping missing and unreadable evidence distinct.

    ``latest`` afterwards reads only validated independent values, on any thread.
    A consumer chooses fallback policy for missing output; unreadable output raises.
    """
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
        rows = capture_rows(service, (RUN_KIND, EVIDENCE_KIND), max_rows=SNAPSHOT_ROWS, max_bytes=SNAPSHOT_BYTES)
        store = StoredTools(rows, Path(service.root), project.id, project.revision,
                            artifacts={artifact.side: artifact.sha256 for artifact in project.artifacts},
                            budget=ReadBudget(SIDECAR_BYTES))
    except Exception as exc:
        reason = str(getattr(exc, 'code', '') or type(exc).__name__)[:40]
        return ToolSources(failures=tuple((engine, side, reason) for engine in engines for side in SIDES),
                           captured_engines=engines)
    for engine in engines:
        for side in SIDES:
            try:
                item = store.latest(engine, side)
            except Exception as exc:
                failures.append((engine, side, str(getattr(exc, 'code', '') or type(exc).__name__)[:40]))
            else:
                if item is not None:
                    found.append(((engine, side), item))
    return ToolSources(tuple(found), tuple(failures), engines)
