"""Persistence of build fingerprints as the additive enrichment kind `build-env` (DIE plan s7).

One row per (artifact, PE facts version, DiE cache key); the body is the `BuildFingerprint` inline, at most 64 KiB, no
sidecar. Deltas are never stored. Rows are written on the GUI thread only. A reader that does not know the kind never
queries it, so old clients keep working and the row survives their saves and retention (it is not a derived kind).
"""
from __future__ import annotations

import json

from pydantic import ValidationError

from ..enrichment.storage import EnrichmentError, EnrichmentStore, Guard
from .contracts import BuildEnvError, BuildFingerprint

KIND = 'build-env'
MAX_BODY = 64 * 1024


class BuildEnvStore:
    def __init__(self, enrichment: EnrichmentStore, project_id: str, revision: int):
        self.enrichment = enrichment
        self.project_id = project_id
        self.revision = revision

    def guard(self, fingerprint: BuildFingerprint) -> Guard:
        return Guard(self.project_id, KIND, fingerprint.artifact_sha256, fingerprint.entry_id())

    def publish(self, fingerprint: BuildFingerprint) -> str:
        """Store (or replace) the row of this fingerprint's identity; returns the row id."""
        body = fingerprint.model_dump(mode='json')  # entropy values are floats: canonical_json would refuse them
        if len(json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()) > MAX_BODY:
            raise BuildEnvError('PT-BUILD-LIMIT', 'the build fingerprint exceeds 64 KiB')
        guard = self.guard(fingerprint)
        try:
            self.enrichment.publish(KIND, guard, guard, self.revision, 'complete', body, fingerprint.entry_id())
        except EnrichmentError as exc:
            raise BuildEnvError('PT-BUILD-STORE', f'build environment not stored ({exc.code})') from None
        return fingerprint.entry_id()

    def fingerprints(self, artifact_sha256: str | None = None) -> list[BuildFingerprint]:
        """Valid rows of this project, newest first; a row that no longer validates is skipped, never served."""
        out = []
        for entry in self.enrichment.entries(KIND, on_corrupt=lambda _id: None):
            if entry.guard.project_id != self.project_id or entry.guard.run_id != KIND:
                continue
            try:
                fingerprint = BuildFingerprint.model_validate_json(json.dumps(entry.body))
            except ValidationError:
                continue
            if fingerprint.entry_id() == entry.id and artifact_sha256 in (None, fingerprint.artifact_sha256):
                out.append(fingerprint)
        return out

    def latest(self, artifact_sha256: str, side: str) -> BuildFingerprint | None:
        return next((fp for fp in self.fingerprints(artifact_sha256) if fp.side == side), None)
