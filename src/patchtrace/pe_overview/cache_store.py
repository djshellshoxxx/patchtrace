"""Owner-thread storage bridge for offline PE metadata (SPEC-51 D2-5).

Workers receive frozen metadata values, never the SQLite connection. Cache faults
are nonfatal optimization failures: live inspection and previous rows survive.
OS trust results are deliberately absent from the persisted record.
"""
from __future__ import annotations

import logging
import sys
from collections.abc import Iterable
from itertools import islice

from ..enrichment.storage import EnrichmentStore, Guard
from ..models import Artifact
from .cache import KIND, OVERVIEW_VERSION, cache_key, limits_digest
from .cache_codec import MAX_CACHE_BYTES, canonical, decode_metadata
from .metadata import DEFAULT_LIMITS, PeMetadata

CONTRACT = 'pe-metadata-cache/1'
_LOG = logging.getLogger(__name__)


def trust_fingerprint() -> str:
    return f'win32:{sys.getwindowsversion().build}' if sys.platform == 'win32' else 'portable'


def _pair(artifacts: Iterable[Artifact]) -> tuple[tuple[str, str], ...]:
    records = tuple(islice(artifacts, 3))
    if len(records) != 2 or {artifact.side for artifact in records} != {'newer', 'older'}:
        raise ValueError('PE metadata cache requires an oriented artifact pair')
    return tuple(sorted((artifact.side, artifact.sha256) for artifact in records))


class MetadataCacheStore:
    def __init__(self, enrichment: EnrichmentStore, project_id: str, revision: int,
                 fingerprint: str | None = None):
        if not isinstance(project_id, str) or not project_id or type(revision) is not int or revision < 0:
            raise ValueError('PE metadata cache requires a current project identity and revision')
        self.enrichment, self.project_id, self.revision = enrichment, project_id, revision
        self.fingerprint = trust_fingerprint() if fingerprint is None else fingerprint

    def key(self, artifact_sha256: str) -> str:
        return cache_key(artifact_sha256, DEFAULT_LIMITS, 'offline', self.fingerprint)

    def _guard(self, artifact_sha256: str) -> Guard:
        return Guard(self.project_id, KIND, artifact_sha256, self.key(artifact_sha256))

    def _body(self, artifact_sha256: str, metadata: PeMetadata) -> dict:
        return {'contract': CONTRACT, 'overview_version': OVERVIEW_VERSION,
                'artifact_sha256': artifact_sha256, 'key': self.key(artifact_sha256),
                'limits_digest': limits_digest(DEFAULT_LIMITS), 'trust_fingerprint': self.fingerprint,
                'consent': {'trust_mode': 'offline', 'network_used': False}, 'result': metadata.to_dict()}

    def load(self, artifact_sha256: str) -> PeMetadata | None:
        guard = self._guard(artifact_sha256)
        entry = self.enrichment.entry(KIND, f'{KIND}:{guard.input_digest}', max_bytes=MAX_CACHE_BYTES)
        if (entry is None or entry.guard != guard or entry.stale or entry.status != 'complete'
                or entry.project_revision > self.revision):
            return None
        try:
            metadata = decode_metadata(entry.body.get('result'))
            if canonical(entry.body) != canonical(self._body(artifact_sha256, metadata)):
                return None
        except (TypeError, ValueError, AttributeError):
            return None
        return metadata

    def publish(self, artifact_sha256: str, metadata: PeMetadata) -> bool:
        guard = self._guard(artifact_sha256)
        entry_id = f'{KIND}:{guard.input_digest}'
        metadata = decode_metadata(metadata.to_dict())
        old = self.enrichment.entry(KIND, entry_id, max_bytes=MAX_CACHE_BYTES)
        if old is not None and (old.guard != guard or old.kind != KIND or old.project_revision > self.revision):
            return False  # a foreign owner is never overwritten by a cache publication
        if (old is not None and not old.stale and old.status == 'complete'
                and canonical(old.body) == canonical(self._body(artifact_sha256, metadata))):
            return True  # do not mutate an already matching cache row on every inspection
        body = self._body(artifact_sha256, metadata)
        if len(canonical(body).encode('utf-8')) > MAX_CACHE_BYTES:
            raise ValueError('PE metadata cache envelope exceeds its byte limit')
        self.enrichment.publish(KIND, guard, guard, self.revision, 'complete', body, entry_id,
                                protect_owner=True, allow_retention=False)
        return True


def snapshot_metadata_cache(service) -> dict[str, PeMetadata]:
    """Read only the current pair's exact rows, on the service's owner thread."""
    found: dict[str, PeMetadata] = {}
    try:
        pair = _pair(service.project.artifacts)
        store = MetadataCacheStore(EnrichmentStore(service.store), service.project.id, service.project.revision)
    except Exception:  # cache is optional; inspection still verifies and parses both files
        _LOG.debug('PE metadata cache snapshot unavailable', exc_info=True)
        return found
    for _side, digest in pair:
        try:
            metadata = store.load(digest)
        except Exception:
            _LOG.debug('PE metadata cache row unavailable', exc_info=True)
            continue
        if metadata is not None:
            found[digest] = metadata
    return found


def publish_metadata_cache(service, inspection) -> int:
    """Persist complete current results after the worker handoff; never cache cancellation."""
    try:
        if inspection.cancelled or inspection.project_id != service.project.id:
            return 0
        pair = _pair(service.project.artifacts)
        observed = tuple(sorted((side, info.artifact_sha256) for side, info in inspection.sides.items()))
        if pair != observed:
            return 0
        store = MetadataCacheStore(EnrichmentStore(service.store), service.project.id, service.project.revision)
    except Exception:
        _LOG.debug('PE metadata cache publication owner unavailable', exc_info=True)
        return 0
    published = 0
    for side, digest in pair:
        try:
            metadata = inspection.sides[side].metadata
            if metadata is None or metadata.status != 'ok':
                continue
            published += store.publish(digest, metadata)
        except Exception:  # preserve live results and prior rows when cache storage is unavailable
            _LOG.debug('PE metadata cache publication unavailable', exc_info=True)
    return published
