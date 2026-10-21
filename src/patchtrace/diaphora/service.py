"""Façade for the Diaphora CLI/GUI: inspect, import into the project's enrichment store, read back. No Qt."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from pydantic import ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from .address_map import ImageMap
from .contracts import KIND, DiaphoraError, DiaphoraMatchSet
from .provenance import bind, load_manifest
from .result_import import import_result


def image_map(artifact, root: Path, cancel: threading.Event) -> ImageMap:
    """Image base and size from the verified project copy; unreadable PEs map nothing (`ambiguous`)."""
    from ..artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    from ..pe_overview import inspect_pe
    try:
        with VerifiedArtifactReader.open_artifact(artifact, root, cancel.is_set) as reader:
            overview = inspect_pe(reader, cancel=cancel.is_set)
    except ArtifactBytesError:
        return ImageMap(None, None)
    if overview.status != 'ok' and overview.image_base is None:
        return ImageMap(None, None)
    return ImageMap(overview.image_base, overview.size_of_image)


def import_into_project(service, result: Path, *, manifest: Path | None, user_attest_pair: bool,
                        cancel: threading.Event) -> tuple[Entry, DiaphoraMatchSet]:
    """Bind, parse and publish one result as the project's `diaphora-matches` row (re-import upserts the same id)."""
    project = service.project
    run = next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)
    if run is None:
        raise DiaphoraError('PT-DIAPHORA-INPUT', 'project has no completed analysis run to attach Diaphora matches to')
    sides = {a.side: a for a in project.artifacts}
    older, newer = sides['older'], sides['newer']
    parsed = load_manifest(manifest) if manifest is not None else None
    # The manifest hash is re-checked against the private snapshot that is parsed (see import_result).
    trust = bind(parsed, user_attest_pair, parsed.result_sha256 if parsed else '0' * 64, older.sha256, newer.sha256)
    match_set = import_result(
        result, older_sha256=older.sha256, newer_sha256=newer.sha256, trust=trust,
        older_map=image_map(older, service.root, cancel), newer_map=image_map(newer, service.root, cancel),
        expected_result_sha256=parsed.result_sha256 if parsed else None, cancel=cancel)
    store = EnrichmentStore(service.store)
    guard = Guard(project.id, run.id, run.raw_sha256, match_set.result_sha256)
    try:
        entry = store.publish(KIND, guard, guard, project.revision, 'complete', match_set.model_dump(mode='json'),
                              match_set.entry_id)
    except EnrichmentError as exc:
        raise DiaphoraError('PT-DIAPHORA-STORAGE', str(exc)) from None
    return entry, match_set


def stored_sets(service) -> list[tuple[Entry, DiaphoraMatchSet]]:
    """Valid stored sets for the current pair, newest first. A row failing validation is skipped, never fatal."""
    project = service.project
    run = next((r for r in reversed(project.runs) if r.status == 'completed' and r.raw_sha256), None)
    store = EnrichmentStore(service.store)
    out = []
    pair = {a.side: a.sha256 for a in project.artifacts}
    for entry in store.entries(KIND, None, on_corrupt=lambda _id: None):
        try:
            match_set = DiaphoraMatchSet.model_validate_json(json.dumps(entry.body))
        except ValidationError:
            continue
        if (match_set.older_sha256, match_set.newer_sha256) != (pair.get('older'), pair.get('newer')):
            continue
        if run is not None and entry.guard.run_id != run.id:
            continue    # attached to another analysis run
        out.append((entry, match_set))
    return out
