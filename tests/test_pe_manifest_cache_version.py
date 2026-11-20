"""A legacy metadata cache must not bypass the recovered manifest parser boundary."""
from __future__ import annotations

from dataclasses import replace

from pe_rsrc_builder import LANG_EN_US, RT_MANIFEST, rsrc_pe, tree

from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pe_overview import cache, cache_store
from patchtrace.pe_overview.authenticode import TrustResult
from patchtrace.pe_overview.cache import KIND
from patchtrace.pe_overview.cache_store import MetadataCacheStore, snapshot_metadata_cache
from patchtrace.pe_overview.manifest import AssemblyIdentity
from patchtrace.service import ProjectService

NORMAL = ('<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
          '<assemblyIdentity name="Authored.Normal"/></assembly>')
ENTITY = ('<!DOCTYPE assembly [<!ENTITY proof "AUTHORED_ENTITY_MARKER">]>'
          + NORMAL.replace('Authored.Normal', '&proof;'))


def inspect(service, **kwargs):
    return inspect_project_artifacts(
        service.project.id, service.project.artifacts, service.root,
        verify_trust=lambda path: TrustResult('unavailable', None, 'test'), **kwargs)


def test_reopening_version_two_cache_reparses_manifest_and_preserves_legacy_evidence(tmp_path, monkeypatch):
    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(rsrc_pe(tree({RT_MANIFEST: {1: {LANG_EN_US: (' ' + ENTITY).encode('utf-16-be')}}}))[0])
    newer.write_bytes(rsrc_pe(tree({RT_MANIFEST: {1: {LANG_EN_US: NORMAL.encode()}}}))[0])
    root = tmp_path / 'case'
    service = ProjectService.create(older, newer, 'legacy manifest cache', root)
    try:
        result = inspect(service)
        try:
            metadata = result.sides['older'].metadata
            assert metadata.status == 'partial'
            assert metadata.manifests[0].warnings == ('manifest_dtd_rejected',)
            # Exact facts returned by the old parser for these authored bytes.
            # Preserve the actual resource identity and digest, as a genuine v2 row did.
            legacy_manifest = replace(
                metadata.manifests[0], warnings=(),
                identity=AssemblyIdentity('AUTHORED_ENTITY_MARKER', None, None, None, None))
            legacy_metadata = replace(metadata, status='ok', warnings=(), manifests=(legacy_manifest,))
            digest = result.sides['older'].artifact_sha256
        finally:
            result.close()
        with monkeypatch.context() as legacy:
            legacy.setattr(cache, 'OVERVIEW_VERSION', 2)
            legacy.setattr(cache_store, 'OVERVIEW_VERSION', 2)
            storage = MetadataCacheStore(EnrichmentStore(service.store), service.project.id,
                                         service.project.revision)
            assert storage.publish(digest, legacy_metadata)
        original_rows = [(entry.id, entry.body_sha256) for entry in EnrichmentStore(service.store).entries(KIND)]
        assert len(original_rows) == 1
    finally:
        service.close()

    service = ProjectService.open(root)
    try:
        cached = snapshot_metadata_cache(service)
        assert digest not in cached
        result = inspect(service, metadata_cache=cached)
        try:
            metadata = result.sides['older'].metadata
            assert metadata.status == 'partial'
            assert metadata.manifests[0].identity is None
            assert metadata.manifests[0].warnings == ('manifest_dtd_rejected',)
            assert result.sides['newer'].metadata.manifests[0].identity.name == 'Authored.Normal'
        finally:
            result.close()
        assert [(entry.id, entry.body_sha256) for entry in EnrichmentStore(service.store).entries(KIND)] == original_rows
    finally:
        service.close()
