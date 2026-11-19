"""SPEC-51: real storage, exact identity, cache corruption and worker ownership.

Fixtures are synthetic PE files. No target, OS trust operation or network runs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pe_meta_builder import meta_pe

from patchtrace import artifact_inspection
from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import DERIVED_KINDS, KINDS, EnrichmentStore
from patchtrace.pe_overview.authenticode import TrustResult
from patchtrace.pe_overview.cache import KIND, cache_key
from patchtrace.pe_overview.cache_codec import decode_metadata
from patchtrace.pe_overview.cache_store import (
    MetadataCacheStore,
    publish_metadata_cache,
    snapshot_metadata_cache,
)
from patchtrace.pe_overview.metadata import DEFAULT_LIMITS, PeMetadata
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older = tmp_path / 'older.exe'
    newer = tmp_path / 'newer.exe'
    older.write_bytes(meta_pe('1.0.0.0')[0])
    newer.write_bytes(meta_pe('1.0.1.0', 'requireAdministrator')[0])
    service = ProjectService.create(older, newer, 'metadata cache', tmp_path / 'case')
    yield service
    if not service.store.closed:
        service.close()


def inspect(service, **kwargs):
    return inspect_project_artifacts(service.project.id, service.project.artifacts, service.root,
                                     verify_trust=lambda path: TrustResult('unavailable', None, 'test'), **kwargs)


def cache_store(service, fingerprint='portable'):
    return MetadataCacheStore(EnrichmentStore(service.store), service.project.id,
                              service.project.revision, fingerprint)


def rows(service):
    return EnrichmentStore(service.store).entries(KIND)


def corrupt(service, entry, body):
    text = json.dumps(body, sort_keys=True)
    db = service.store.connection
    with db:
        db.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                   (text, hashlib.sha256(text.encode()).hexdigest(), entry.id))


def test_registered_kind_does_not_enter_pipeline_retention():
    assert KIND in KINDS and KIND not in DERIVED_KINDS


def test_real_inspection_round_trip_and_reopen_skips_metadata_parse(service, monkeypatch):
    result = inspect(service)
    try:
        assert all(info.metadata is not None and info.metadata.status == 'ok' for info in result.sides.values())
        assert publish_metadata_cache(service, result) == 2
        original = {side: info.metadata for side, info in result.sides.items()}
        saved = [(entry.id, entry.created, entry.body_sha256) for entry in rows(service)]
        root = service.root
    finally:
        result.close()
    service.close()
    reopened = ProjectService.open(root)
    try:
        cached = snapshot_metadata_cache(reopened)
        assert len(cached) == 2
        def unexpected(*args, **kwargs):
            pytest.fail('cache hit reparsed PE metadata')
        monkeypatch.setattr(artifact_inspection, 'inspect_metadata', unexpected)
        result = inspect(reopened, metadata_cache=cached)
        try:
            assert {side: info.metadata for side, info in result.sides.items()} == original
            assert publish_metadata_cache(reopened, result) == 2
            assert [(entry.id, entry.created, entry.body_sha256) for entry in rows(reopened)] == saved
            assert reopened.store.connection.execute('PRAGMA user_version').fetchone()[0] == 1
        finally:
            result.close()
    finally:
        reopened.close()


def test_snapshot_does_not_enumerate_unrelated_rows(service, monkeypatch):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
        monkeypatch.setattr(EnrichmentStore, 'entries', lambda *args, **kwargs: pytest.fail('unbounded cache scan'))
        assert len(snapshot_metadata_cache(service)) == 2
    finally:
        result.close()


def test_worker_cache_never_bypasses_artifact_hash_verification(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    cached = snapshot_metadata_cache(service)
    older = next(a for a in service.project.artifacts if a.side == 'older')
    path = service.root / older.relative_path
    path.chmod(0o600)
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    result = inspect(service, metadata_cache=cached)
    try:
        assert result.sides['older'].overview is None
        assert result.sides['older'].metadata is None
        assert result.sides['older'].error_code is not None
        assert result.sides['newer'].metadata is not None
    finally:
        result.close()


def test_trust_is_recomputed_and_never_restored_from_metadata(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    calls = []
    result = inspect_project_artifacts(
        service.project.id, service.project.artifacts, service.root,
        verify_trust=lambda path: (calls.append(path) or TrustResult('untrusted', None, 'current check')),
        metadata_cache=snapshot_metadata_cache(service))
    try:
        assert len(calls) == 2
        assert all(info.trust.status == 'untrusted' for info in result.sides.values())
        assert all(sig.chain == 'not_evaluated' for entry in rows(service)
                   for sig in decode_metadata(entry.body['result']).signatures)
    finally:
        result.close()


@pytest.mark.parametrize('mutation', ['version', 'key', 'artifact', 'consent', 'extra', 'missing',
                                      'status', 'trust', 'hostile', 'bool-integer', 'primary-index', 'partial-warnings'])
def test_bad_envelopes_or_metadata_are_cache_misses(service, mutation):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    entry = rows(service)[0]
    body = copy.deepcopy(entry.body)
    if mutation == 'version':
        body['overview_version'] = 1
    elif mutation == 'key':
        body['key'] = '0' * 64
    elif mutation == 'artifact':
        body['artifact_sha256'] = '0' * 64
    elif mutation == 'consent':
        body['consent']['network_used'] = True
    elif mutation == 'extra':
        body['result']['extra'] = 'ignored fields are forbidden'
    elif mutation == 'missing':
        del body['result']['warnings']
    elif mutation == 'status':
        body['result']['status'] = 'cancelled'
    elif mutation == 'partial-warnings':
        body['result']['warnings'] = [{'code': 'internal_error_resources', 'message': 'partial parse'}]
    elif mutation == 'trust':
        body['result']['signatures'][0]['chain'] = 'trusted_no_revocation_check'
    elif mutation == 'hostile':
        body['result']['signatures'][0]['signers'][0]['issuer_dn'] = 'inert\u202eforged'
    elif mutation == 'bool-integer':
        body['result']['signatures'][0]['index'] = True
    elif mutation == 'primary-index':
        body['result']['version']['primary_index'] = 99999
    corrupt(service, entry, body)
    cached = snapshot_metadata_cache(service)
    assert entry.guard.raw_sha256 not in cached and len(cached) == 1
    result = inspect(service, metadata_cache=cached)
    try:
        assert all(info.metadata is not None for info in result.sides.values())
    finally:
        result.close()


def test_corrupt_integrity_isolated_to_one_row(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    entry = rows(service)[0]
    db = service.store.connection
    with db:
        db.execute("UPDATE enrichment_entries SET body_sha256=? WHERE id=?", ('0' * 64, entry.id))
    assert len(snapshot_metadata_cache(service)) == 1


def test_foreign_owner_row_is_not_reused_or_overwritten(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
        entry = rows(service)[0]
        db = service.store.connection
        with db:
            db.execute('UPDATE enrichment_entries SET project_id=? WHERE id=?', ('foreign-project', entry.id))
        assert entry.guard.raw_sha256 not in snapshot_metadata_cache(service)
        assert publish_metadata_cache(service, result) == 1
        assert db.execute('SELECT project_id FROM enrichment_entries WHERE id=?', (entry.id,)).fetchone()[0] == (
            'foreign-project')
    finally:
        result.close()


def test_foreign_kind_collision_is_never_overwritten(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
        entry = rows(service)[0]
        db = service.store.connection
        with db:
            db.execute("UPDATE enrichment_entries SET kind='ranking' WHERE id=?", (entry.id,))
        assert publish_metadata_cache(service, result) == 1
        row = db.execute('SELECT kind,body_sha256 FROM enrichment_entries WHERE id=?', (entry.id,)).fetchone()
        assert row == ('ranking', entry.body_sha256)
    finally:
        result.close()


def test_platform_trust_fingerprints_do_not_mix(service):
    result = inspect(service)
    try:
        old = next(a for a in service.project.artifacts if a.side == 'older')
        assert cache_store(service, 'portable').publish(old.sha256, result.sides['older'].metadata)
        assert cache_store(service, 'win32:22631').load(old.sha256) is None
    finally:
        result.close()


def test_partial_and_cancelled_results_do_not_replace_previous_rows(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
        before = [entry.body_sha256 for entry in rows(service)]
        result.sides['older'] = replace(result.sides['older'], metadata=PeMetadata('partial'))
        result.sides['newer'] = replace(result.sides['newer'], metadata=PeMetadata('cancelled'))
        assert publish_metadata_cache(service, result) == 0
        result.cancelled = True
        assert publish_metadata_cache(service, result) == 0
        assert [entry.body_sha256 for entry in rows(service)] == before
    finally:
        result.close()


def test_project_change_refuses_worker_publication(service):
    result = inspect(service)
    try:
        result.project_id = 'superseded'
        assert publish_metadata_cache(service, result) == 0
        result.project_id = service.project.id
        result.sides['older'] = replace(result.sides['older'], artifact_sha256='0' * 64)
        assert publish_metadata_cache(service, result) == 0
        assert rows(service) == []
    finally:
        result.close()


def test_storage_failure_keeps_live_metadata(service, monkeypatch):
    result = inspect(service)
    try:
        original = {side: info.metadata for side, info in result.sides.items()}
        def fail(*args, **kwargs):
            raise OSError('storage refused')
        monkeypatch.setattr(EnrichmentStore, 'publish', fail)
        assert publish_metadata_cache(service, result) == 0
        assert {side: info.metadata for side, info in result.sides.items()} == original
    finally:
        result.close()


@pytest.mark.parametrize('cancel_on_read', [1, 2], ids=['first-side', 'last-side'])
def test_cancel_during_metadata_read_does_not_publish(service, monkeypatch, cancel_on_read):
    event = threading.Event()
    real = artifact_inspection.inspect_metadata
    calls = []
    def stop_after_read(*args, **kwargs):
        found = real(*args, **kwargs)
        calls.append(1)
        if len(calls) == cancel_on_read:
            event.set()
        return found
    monkeypatch.setattr(artifact_inspection, 'inspect_metadata', stop_after_read)
    result = inspect(service, cancel=event.is_set)
    try:
        assert result.cancelled
        assert publish_metadata_cache(service, result) == 0
        assert rows(service) == []
    finally:
        result.close()


def test_exact_entry_refuses_duplicate_json_even_with_matching_hash(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    entry = rows(service)[0]
    text = '{"result": {}, "result": {}}'
    with service.store.connection:
        service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                         (text, hashlib.sha256(text.encode()).hexdigest(), entry.id))
    with pytest.raises(EnrichmentError, match='strict JSON'):
        EnrichmentStore(service.store).entry(KIND, entry.id)


def test_exact_entry_enforces_read_budget(service):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    entry = rows(service)[0]
    with pytest.raises(EnrichmentError, match='byte limit'):
        EnrichmentStore(service.store).entry(KIND, entry.id, max_bytes=16)
    assert EnrichmentStore(service.store).entry(KIND, 'missing') is None


@pytest.mark.parametrize('digest', ['', 'a' * 63, 'A' * 64, 'x' * 64, 42])
def test_cache_key_refuses_invalid_artifact_identity(digest):
    with pytest.raises(ValueError):
        cache_key(digest, DEFAULT_LIMITS, 'offline', 'portable')


_JSON = st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=100),
                     lambda children: st.lists(children, max_size=8) | st.dictionaries(
                         st.text(max_size=20), children, max_size=8), max_leaves=40)


@settings(max_examples=100, deadline=None)
@given(_JSON)
def test_hostile_metadata_values_either_validate_exactly_or_fail_closed(value):
    try:
        found = decode_metadata(value)
    except (TypeError, ValueError):
        return
    assert found.status == 'ok'
    assert json.loads(json.dumps(found.to_dict())) == value


def test_exact_entry_never_materializes_a_row_that_grows_past_budget(service, monkeypatch):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
    finally:
        result.close()
    entry = rows(service)[0]
    real = service.store.connection
    limit = len(entry.body_json.encode()) + 16
    observed = []

    class ObservedCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            row = self.cursor.fetchone()
            observed.append(None if row is None else len(row[10].encode()))
            return row

    class ChangingConnection:
        def __getattr__(self, name):
            return getattr(real, name)

        def execute(self, sql, values=()):
            if sql.startswith('SELECT id,kind,project_id'):
                with real:
                    real.execute('UPDATE enrichment_entries SET body=? WHERE id=?', ('x' * (limit + 1), entry.id))
                return ObservedCursor(real.execute(sql, values))
            return real.execute(sql, values)

    monkeypatch.setattr(service.store, 'connection', ChangingConnection())
    with pytest.raises(EnrichmentError):
        EnrichmentStore(service.store).entry(KIND, entry.id, max_bytes=limit)
    assert observed == [None]  # no oversized body crossed the SQLite/Python boundary


@pytest.mark.parametrize('claimed,computed', [
    ('not-a-hex-digest', 'not-a-hex-digest'), ('aa', 'aa'),
    ('0' * 64, '0' * 62), ('AB' * 32, 'AB' * 32), ('0' * 63, '0' * 64),
])
def test_cache_refuses_impossible_digest_encodings(service, claimed, computed):
    result = inspect(service)
    try:
        metadata = result.sides['older'].metadata
        sig = replace(metadata.signatures[0], digest_algorithm='sha256', weak_digest=False,
                      digest_claimed_hex=claimed, digest_computed_hex=computed,
                      digest_match=claimed == computed)
        with pytest.raises(ValueError):
            decode_metadata(replace(metadata, signatures=(sig,)).to_dict())
    finally:
        result.close()


@pytest.mark.parametrize('mutation', ['no-signers', 'no-certificates', 'no-matching-cert', 'not-found', 'not-rsa'])
def test_cache_refuses_signature_math_without_required_proof_fields(tmp_path, mutation):
    from test_pe_rsa import signatures
    sig, = signatures(tmp_path)
    assert sig.signature_math == 'ok_chain_not_evaluated'
    if mutation == 'no-signers':
        sig = replace(sig, signers=())
    elif mutation == 'no-certificates':
        sig = replace(sig, certificates=())
    elif mutation == 'no-matching-cert':
        sig = replace(sig, certificates=(replace(sig.certificates[0], serial_hex='ff'),))
    elif mutation == 'not-found':
        sig = replace(sig, signers=(replace(sig.signers[0], signer_cert_found=False),))
    elif mutation == 'not-rsa':
        sig = replace(sig, signers=(replace(sig.signers[0], signature_alg_oid='1.2.3'),))
    with pytest.raises(ValueError):
        decode_metadata(PeMetadata('ok', signatures=(sig,)).to_dict())


@pytest.mark.parametrize('flip_section', [False, True])
def test_cache_preserves_real_signature_math_without_promoting_file_integrity(tmp_path, flip_section):
    from test_pe_rsa import signatures
    sig, = signatures(tmp_path, flip_section=flip_section)
    metadata = PeMetadata('ok', signatures=(sig,))
    assert decode_metadata(metadata.to_dict()) == metadata
    assert sig.digest_match is not flip_section


@pytest.mark.parametrize('stale,status', [(True, 'complete'), (False, 'failed'), (True, 'failed')])
def test_recomputed_metadata_renews_stale_or_failed_matching_row(service, stale, status):
    result = inspect(service)
    try:
        publish_metadata_cache(service, result)
        entry = rows(service)[0]
        with service.store.connection:
            service.store.connection.execute('UPDATE enrichment_entries SET stale=?,status=? WHERE id=?',
                                             (int(stale), status, entry.id))
        assert len(snapshot_metadata_cache(service)) == 1
        assert publish_metadata_cache(service, result) == 2
        assert len(snapshot_metadata_cache(service)) == 2
        assert all(not row.stale and row.status == 'complete' for row in rows(service))
    finally:
        result.close()


@pytest.mark.parametrize('claimed', ['', '00' * 31, '00' * 33])
def test_cache_preserves_malformed_length_claims_as_digest_mismatches(service, claimed):
    result = inspect(service)
    try:
        metadata = result.sides['older'].metadata
        sig = replace(metadata.signatures[0], digest_claimed_hex=claimed, digest_match=False)
        value = replace(metadata, signatures=(sig,))
        assert decode_metadata(value.to_dict()) == value
        assert value.signatures[0].digest_match is False
    finally:
        result.close()
