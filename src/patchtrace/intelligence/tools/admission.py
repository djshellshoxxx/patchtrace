"""Opt-in current-project admission of stored tool evidence (SPEC-36 T14).

Search and Strings need Entry ownership/staleness, which ToolStore.latest does
not return. Read on the store owner thread; return values only, with the admitted
originating run for cache-hit raw provenance. No writes or tool execution.
Existing ToolStore readers and normalized-sidecar I/O behavior stay unchanged.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from ...enrichment.contracts import EnrichmentError
from ...enrichment.storage import Entry
from ...persistence import strict_json
from .common import EVIDENCE_KIND, RUN_KIND, ToolError, ToolEvidenceSet, ToolRun, evidence_entry_id, produced
from .normalize import validate_set
from .store import ToolStore


@dataclass(frozen=True, slots=True)
class AdmittedToolEvidence:
    run: ToolRun
    evidence: ToolEvidenceSet
    evidence_run: ToolRun


def _body(entry: Entry) -> tuple[dict, str]:
    # entries() preserves the original hash-checked JSON. Do not reserialize its
    # parsed dictionary before strict admission: that would erase duplicate keys.
    text = entry.body_json if entry.body_json is not None else json.dumps(entry.body)
    body = strict_json(text)
    if type(body) is not dict:
        raise ValueError('a stored tool record must be an object')
    return body, text


def _row(entry: Entry, store: ToolStore, artifact: str, key: str, *, kind: str, identity: str, status: str):
    if (entry.kind != kind or entry.id != identity or entry.status != status or entry.stale
            or entry.guard != store.guard(artifact, key)):
        raise ToolError('PT-TOOL-STALE', 'stored tool row ownership, status or identity is not current')


def _run(entry: Entry, run: ToolRun, store: ToolStore, engine: str, side: str, artifact: str):
    _row(entry, store, artifact, run.cache_key, kind=RUN_KIND, identity=run.run_id, status=run.status)
    if (not produced(run) or run.engine != engine or run.side != side
            or run.input_artifact_hash != artifact):
        raise ToolError('PT-TOOL-ARTIFACT', 'stored tool run does not describe the current artifact and side')


def _binding(run: ToolRun, evidence: ToolEvidenceSet, *, direct: bool):
    validate_set(evidence, artifact_sha256=run.input_artifact_hash, cache_key=run.cache_key, engine=run.engine)
    count = evidence.evidence_count()
    if (evidence.side != run.side or evidence.config_digest != run.config_digest
            or direct and evidence.run_id != run.run_id
            or run.evidence_count != count or run.status != ('ok' if count else 'none-found')):
        raise ToolError('PT-TOOL-STALE', 'stored tool evidence does not match the selected run')


def _evidence(store: ToolStore, run: ToolRun) -> ToolEvidenceSet:
    for entry in store.enrichment.entries(EVIDENCE_KIND):
        body, text = _body(entry)
        match = ((body.get('engine'), body.get('side'), body.get('cache_key'))
                 == (run.engine, run.side, run.cache_key) if run.cache_hit else body.get('run_id') == run.run_id)
        if not match:
            continue
        # Admit ownership before a selected pointer may read a sidecar. Its
        # content-derived row identity is checked once the evidence is loaded.
        _row(entry, store, run.input_artifact_hash, run.cache_key,
             kind=EVIDENCE_KIND, identity=entry.id, status='ok')
        if body.get('kind') == 'sidecar':
            evidence = store._load(body)  # reuse the existing normalized-sidecar loader, without changing it
            fields = ('contract', 'run_id', 'engine', 'side', 'artifact_sha256', 'cache_key', 'config_digest')
            if any(body.get(field) != getattr(evidence, field) for field in fields):
                raise ToolError('PT-TOOL-STALE', 'stored tool sidecar identity disagrees with its evidence')
        else:
            evidence = ToolEvidenceSet.model_validate_json(text)
        if entry.id != evidence_entry_id(evidence):
            raise ToolError('PT-TOOL-STALE', 'stored tool evidence row has a different content identity')
        _binding(run, evidence, direct=not run.cache_hit)
        return evidence
    raise ToolError('PT-TOOL-STALE', 'the selected tool run has no stored evidence')


def latest_admitted(store: ToolStore, *, engine: str, side: str,
                    artifact_sha256: str) -> AdmittedToolEvidence | None:
    """Newest produced matching run, its evidence and admitted evidence owner.

None means no produced run exists. Bad selected records raise ToolError instead
of silently selecting an older attempt. Ordinary unsuccessful attempts retain
the existing newest-produced selection behavior. Cache hits may retain the
original evidence run ID and have no raw sidecar of their own.
"""
    if (engine not in ('capa', 'floss', 'diec') or side not in ('older', 'newer')
            or type(artifact_sha256) is not str or len(artifact_sha256) != 64
            or any(char not in '0123456789abcdef' for char in artifact_sha256)):
        raise ToolError('PT-TOOL-INPUT', 'stored tool admission needs an engine, side and artifact SHA-256')
    try:
        entries = store.enrichment.entries(RUN_KIND)
        selected = None
        for entry in entries:
            body, text = _body(entry)
            if body.get('engine') not in ('capa', 'floss', 'diec') or body.get('side') not in ('older', 'newer'):
                raise ToolError('PT-TOOL-OUTPUT', 'stored tool attempt cannot be classified safely')
            if (body['engine'], body['side']) != (engine, side):
                continue
            run = ToolRun.model_validate_json(text)
            if entry.status != run.status:
                raise ToolError('PT-TOOL-STALE', 'stored tool attempt status disagrees with its body')
            if produced(run):
                _run(entry, run, store, engine, side, artifact_sha256)
                selected = run
                break
        if selected is None:
            return None
        evidence = _evidence(store, selected)
        if not selected.cache_hit:
            return AdmittedToolEvidence(selected, evidence, selected)
        origins = [entry for entry in entries if entry.id == evidence.run_id]
        if len(origins) != 1 or evidence.run_id == selected.run_id:
            raise ToolError('PT-TOOL-STALE', 'cached tool evidence has no unique originating run')
        entry = origins[0]
        _value, text = _body(entry)
        origin = ToolRun.model_validate_json(text)
        _run(entry, origin, store, engine, side, artifact_sha256)
        _binding(origin, evidence, direct=True)
        return AdmittedToolEvidence(selected, evidence, origin)
    except ToolError:
        raise
    except (EnrichmentError, sqlite3.Error, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        raise ToolError('PT-TOOL-OUTPUT', 'stored tool records could not be admitted safely') from None
