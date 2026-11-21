"""Independent authored controls for root's manifest/cache recovery; no network."""
import hashlib
import json
import os
import subprocess
import sys

import pytest
from pe_rsrc_builder import LANG_EN_US, RT_MANIFEST, rsrc_pe, tree

from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.pe_overview import cache, cache_store
from patchtrace.pe_overview.authenticode import TrustResult
from patchtrace.pe_overview.cache_store import MetadataCacheStore
from patchtrace.service import ProjectService

NORMAL = ('<assembly xmlns="urn:schemas-microsoft-com:asm.v1">'
          '<assemblyIdentity name="Peer.Normal"/></assembly>')


@pytest.mark.parametrize('fallback', [False, True])
def test_independent_doctype_variants_before_entity_processing(fallback):
    child = '''
import codecs,hashlib,json,sys
if sys.argv[1] == 'True': sys.modules['_elementtree'] = None
from patchtrace.pe_overview.manifest import observe_manifest
from patchtrace.pe_overview.resources import ResourceLeaf
normal = '<assembly xmlns="urn:schemas-microsoft-com:asm.v1"><assemblyIdentity name="Peer.Normal"/></assembly>'
declarations = [
 '<!DOCTYPE assembly>',
 '<!DOCTYPE assembly SYSTEM "file:///NO_SUCH_FILE">',
 '<!DOCTYPE assembly PUBLIC "peer" "https://example.invalid/unread">',
 '<!DOCTYPE assembly [<!ENTITY named "Peer.Expanded">]>',
 '<!DOCTYPE assembly [<!ENTITY % part "<!ENTITY named &quot;Peer.Expanded&quot;>">%part;]>',
]
count = 0
for prefix in (' ', '\\t', '\\r\\n', ' \\n\\t'):
 for declaration in declarations:
  for encoding in ('utf-8','utf-16-le','utf-16-be'):
   raw=(prefix+declaration+normal).encode(encoding)
   leaf=ResourceLeaf(24,'RT_MANIFEST',1,1033,0x2000,len(raw),0,0x400)
   observed=observe_manifest(leaf,raw)
   assert observed.identity is None
   assert observed.warnings in (('manifest_dtd_rejected',), ('manifest_xml_invalid',))
   assert observed.sha256 == hashlib.sha256(raw).hexdigest()
   count += 1
for encoding,bom in [('utf-8',b''),('utf-16-le',codecs.BOM_UTF16_LE),('utf-16-be',codecs.BOM_UTF16_BE)]:
 raw=bom+normal.encode(encoding)
 leaf=ResourceLeaf(24,'RT_MANIFEST',1,1033,0x2000,len(raw),0,0x400)
 observed=observe_manifest(leaf,raw)
 assert observed.identity.name == 'Peer.Normal' and not observed.warnings
 count += 1
print(json.dumps({'checked':count}))
'''
    result = subprocess.run([sys.executable, '-c', child, str(fallback)], capture_output=True,
                            text=True, timeout=15, env=os.environ.copy())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'checked': 63}


def test_current_key_cannot_admit_legacy_version_envelope(tmp_path):
    older, newer = tmp_path / 'a.exe', tmp_path / 'b.exe'
    data = rsrc_pe(tree({RT_MANIFEST: {1: {LANG_EN_US: NORMAL.encode()}}}))[0]
    older.write_bytes(data)
    newer.write_bytes(data)
    service = ProjectService.create(older, newer, 'independent envelope review', tmp_path / 'case')
    try:
        observed = inspect_project_artifacts(service.project.id, service.project.artifacts, service.root,
            verify_trust=lambda path: TrustResult('unavailable', None, 'authored'))
        try:
            metadata = observed.sides['older'].metadata
            digest = observed.sides['older'].artifact_sha256
        finally:
            observed.close()
        enrichment = EnrichmentStore(service.store)
        storage = MetadataCacheStore(enrichment, service.project.id, service.project.revision)
        guard = storage._guard(digest)
        body = storage._body(digest, metadata)
        body['overview_version'] = 2
        entry_id = f'{cache.KIND}:{guard.input_digest}'
        enrichment.publish(cache.KIND, guard, guard, service.project.revision, 'complete', body, entry_id)
        before = [(e.id, e.body_sha256) for e in enrichment.entries(cache.KIND)]
        assert storage.load(digest) is None
        assert [(e.id, e.body_sha256) for e in enrichment.entries(cache.KIND)] == before
        # A current, well-formed row still supplies a cache hit after recomputation.
        assert storage.publish(digest, metadata)
        assert storage.load(digest) == metadata
    finally:
        service.close()


def test_cache_keys_and_envelopes_have_one_consistent_current_version(monkeypatch):
    assert cache.OVERVIEW_VERSION == cache_store.OVERVIEW_VERSION == 3
    digest = hashlib.sha256(b'authored artifact').hexdigest()
    storage = MetadataCacheStore(None, 'not-read', 1, fingerprint='portable')
    current = storage.key(digest)
    with monkeypatch.context() as old:
        old.setattr(cache, 'OVERVIEW_VERSION', 2)
        legacy = storage.key(digest)
    assert current != legacy and storage.key(digest) == current
