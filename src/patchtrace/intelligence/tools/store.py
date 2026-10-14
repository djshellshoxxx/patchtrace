"""Persistence of tool runs and evidence (SPEC-29 tools T2 "Persistence") through the public enrichment storage API.

Two reserved kinds, neither derived (retention never deletes them): `tool-run` (body `ToolRun`, id `run_id`, one
row per attempt, never rewritten) and `tool-evidence` (body `ToolEvidenceSet`, id = content identity; inline when its
canonical JSON is <= 1 MiB, else a pointer to `<project>/intel-tools/<sha256>.json`). Raw tool stdout is kept as
`<project>/intel-tools/raw/<engine>-<sha256>.json` (atomic, content addressed) before parsing. The guard is
`(project_id, 'intel-tools', artifact_sha256, cache_key)`. All SQLite access must happen on the thread that owns the
`EnrichmentStore`; workers only produce immutable values.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from ...enrichment.contracts import EnrichmentError
from ...enrichment.identity import canonical_json
from ...enrichment.storage import EnrichmentStore, Guard
from .common import (
    EVIDENCE_KIND,
    GUARD_RUN_ID,
    RUN_KIND,
    ToolError,
    ToolEvidenceSet,
    ToolRun,
    evidence_entry_id,
)
from .normalize import validate_set

INLINE_LIMIT = 1024 * 1024
DIRECTORY = 'intel-tools'


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(dir=path.parent, prefix='.tmp-', suffix='.part')
    try:
        with os.fdopen(handle, 'wb') as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def write_raw(project_dir: Path, engine: str, raw: bytes) -> str:
    """Content-addressed raw stdout; returns the project-relative POSIX path. Thread-safe (filesystem only)."""
    digest = hashlib.sha256(raw).hexdigest()
    relative = f'{DIRECTORY}/raw/{engine}-{digest}.json'
    target = Path(project_dir) / relative
    if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
        _atomic_write(target, raw)
    return relative


class ToolStore:
    def __init__(self, enrichment: EnrichmentStore, project_dir: Path, project_id: str, revision: int):
        self.enrichment = enrichment
        self.project_dir = Path(project_dir)
        self.project_id = project_id
        self.revision = revision

    def guard(self, artifact_sha256: str, key: str) -> Guard:
        return Guard(self.project_id, GUARD_RUN_ID, artifact_sha256, key)

    # ---- writes -------------------------------------------------------------------------------------------------

    def publish_run(self, run: ToolRun) -> None:
        guard = self.guard(run.input_artifact_hash, run.cache_key)
        self._publish(RUN_KIND, guard, run.status, run.model_dump(mode='json'), run.run_id)

    def publish_evidence(self, evidence: ToolEvidenceSet) -> str:
        """Store the set (inline or as a sidecar pointer); returns the row id. Equal content reuses its row."""
        guard = self.guard(evidence.artifact_sha256, evidence.cache_key)
        entry_id = evidence_entry_id(evidence)
        body = evidence.model_dump(mode='json')
        text = canonical_json(body)
        if len(text) > INLINE_LIMIT:
            digest = hashlib.sha256(text).hexdigest()
            relative = f'{DIRECTORY}/{digest}.json'
            _atomic_write(self.project_dir / relative, text)
            body = {'contract': evidence.contract, 'kind': 'sidecar', 'run_id': evidence.run_id,
                    'engine': evidence.engine, 'side': evidence.side, 'artifact_sha256': evidence.artifact_sha256,
                    'cache_key': evidence.cache_key, 'config_digest': evidence.config_digest, 'sidecar': relative,
                    'sidecar_sha256': digest, 'size': len(text), 'counts': evidence.counts}
        self._publish(EVIDENCE_KIND, guard, 'ok', body, entry_id)
        return entry_id

    def _publish(self, kind: str, guard: Guard, status: str, body: dict, entry_id: str) -> None:
        try:
            self.enrichment.publish(kind, guard, guard, self.revision, status, json.loads(canonical_json(body)),
                                    entry_id)
        except EnrichmentError as exc:
            raise ToolError('PT-TOOL-STORE', f'result not stored ({exc.code})') from None

    # ---- reads --------------------------------------------------------------------------------------------------

    def runs(self, engine: str | None = None) -> list[ToolRun]:
        """Valid run rows, newest first; a row that no longer validates is skipped."""
        out = []
        for entry in self.enrichment.entries(RUN_KIND, on_corrupt=lambda _id: None):
            if entry.guard.run_id != GUARD_RUN_ID:
                continue
            try:
                run = ToolRun.model_validate_json(json.dumps(entry.body))
            except ValidationError:
                continue
            if engine is None or run.engine == engine:
                out.append(run)
        return out

    def _load(self, body: dict) -> ToolEvidenceSet:
        if body.get('kind') == 'sidecar':
            relative = body.get('sidecar')
            path = (self.project_dir / str(relative)).resolve()
            root = (self.project_dir / DIRECTORY).resolve()
            if not isinstance(relative, str) or root not in path.parents or not path.is_file():
                raise ToolError('PT-TOOL-STALE', 'the evidence sidecar is missing')
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != body.get('sidecar_sha256'):
                raise ToolError('PT-TOOL-STALE', 'the evidence sidecar failed its SHA-256 check')
            body = json.loads(data)
        try:
            return ToolEvidenceSet.model_validate_json(json.dumps(body))
        except ValidationError:
            raise ToolError('PT-TOOL-OUTPUT', 'stored evidence does not match the tool-evidence/1 contract') from None

    def evidence_for(self, run_id: str) -> ToolEvidenceSet:
        for entry in self.enrichment.entries(EVIDENCE_KIND, on_corrupt=lambda _id: None):
            if entry.body.get('run_id') == run_id and entry.guard.run_id == GUARD_RUN_ID:
                return self._load(entry.body)
        raise ToolError('PT-TOOL-STALE', 'no stored evidence for this run')

    def find_cached(self, artifact_sha256: str, key: str, engine: str) -> ToolEvidenceSet | None:
        """T7: a hit is re-validated (contract, binding, sidecar hash); a failing hit is a stale miss, never served."""
        for entry in self.enrichment.entries(EVIDENCE_KIND, on_corrupt=lambda _id: None):
            if entry.guard.run_id != GUARD_RUN_ID or entry.body.get('cache_key') != key:
                continue
            try:
                return validate_set(self._load(entry.body), artifact_sha256=artifact_sha256, cache_key=key,
                                    engine=engine)
            except ToolError:
                continue
        return None

    def latest(self, engine: str, side: str) -> tuple[ToolRun, ToolEvidenceSet | None] | None:
        """Newest produced (ok / none-found) run of one engine and side with its evidence when it has any."""
        for run in self.runs(engine):
            if run.side != side or run.status not in ('ok', 'none-found'):
                continue
            try:
                evidence = (self.find_cached(run.input_artifact_hash, run.cache_key, engine) if run.cache_hit
                            else self.evidence_for(run.run_id))
            except ToolError:
                continue
            if evidence is not None:
                return run, evidence
        return None
