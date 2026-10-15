"""`build-env` rows (DIE D4): round trip, guard, corrupt-row isolation and the old-reader invariant. The kind is not in
`KINDS` on this branch (the integrator adds it), so the tests add it the way the integrator will."""
from __future__ import annotations

import json

import pytest
from test_buildenv_support import pair_fingerprints
from test_intel_tools_pe import PAIRS

from patchtrace.buildenv import store as bstore
from patchtrace.buildenv.contracts import BuildEnvError
from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'KINDS', storage.KINDS | {bstore.KIND})
    older, newer = PAIRS['diec-toolchain']()
    (tmp_path / 'o.exe').write_bytes(older)
    (tmp_path / 'n.exe').write_bytes(newer)
    service = ProjectService.create(tmp_path / 'o.exe', tmp_path / 'n.exe', 'case', tmp_path / 'case')
    enrichment = EnrichmentStore(service.store)
    enrichment.ensure()
    yield service, enrichment, pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    service.close()


def _store(service, enrichment):
    return bstore.BuildEnvStore(enrichment, service.project.id, service.project.revision)


def test_round_trip_returns_equal_fingerprints(case):
    service, enrichment, (older, newer) = case
    store = _store(service, enrichment)
    assert store.publish(older) == older.entry_id() and store.publish(newer) == newer.entry_id()
    assert store.latest(older.artifact_sha256, 'older') == older
    assert store.latest(newer.artifact_sha256, 'newer') == newer
    assert store.latest(newer.artifact_sha256, 'older') is None
    assert {fp.side for fp in store.fingerprints()} == {'older', 'newer'}


def test_republish_replaces_instead_of_duplicating(case):
    service, enrichment, (older, _newer) = case
    store = _store(service, enrichment)
    store.publish(older)
    store.publish(older)
    assert len(store.fingerprints(older.artifact_sha256)) == 1


def test_unknown_kind_is_refused_until_registered(case, monkeypatch):
    service, enrichment, (older, _newer) = case
    monkeypatch.setattr(storage, 'KINDS', storage.KINDS - {bstore.KIND})
    with pytest.raises(BuildEnvError) as raised:
        _store(service, enrichment).publish(older)
    assert raised.value.code == 'PT-BUILD-STORE'


def test_oversized_body_is_a_limit_error(case, monkeypatch):
    service, enrichment, (older, _newer) = case
    monkeypatch.setattr(bstore, 'MAX_BODY', 100)
    with pytest.raises(BuildEnvError) as raised:
        _store(service, enrichment).publish(older)
    assert raised.value.code == 'PT-BUILD-LIMIT'


def test_row_that_no_longer_validates_is_skipped(case):
    service, enrichment, (older, newer) = case
    store = _store(service, enrichment)
    store.publish(older)
    store.publish(newer)
    body = json.loads(json.dumps(newer.model_dump(mode='json')))
    body['facts'] = 'broken'
    guard = store.guard(newer)
    enrichment.publish(bstore.KIND, guard, guard, 1, 'complete', body, newer.entry_id())
    assert [fp.side for fp in store.fingerprints()] == ['older']


def test_row_of_another_project_is_ignored(case):
    service, enrichment, (older, _newer) = case
    _store(service, enrichment).publish(older)
    assert bstore.BuildEnvStore(enrichment, 'another-project', 1).fingerprints() == []


def test_old_reader_ignores_build_env_kind(case, monkeypatch):
    """A reader that predates the kind queries known kinds only: it never sees the rows, its retention keeps them and
    the project still saves; a reader that knows the kind reads both back."""
    service, enrichment, (older, newer) = case
    store = _store(service, enrichment)
    ids = {store.publish(older), store.publish(newer)}
    meta = service.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
    assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
    assert bstore.KIND not in storage.DERIVED_KINDS
    old_kinds = frozenset(storage.KINDS) - {bstore.KIND}
    monkeypatch.setattr(storage, 'KINDS', old_kinds)
    old = EnrichmentStore(service.store)
    for kind in sorted(old_kinds):
        assert all(e.kind == kind for e in old.entries(kind))
    old.apply_retention(store.guard(older), started='9999-01-01T00:00:00+00:00')
    old.prune_runs(keep=0)
    service.store.save(service.store.load())
    monkeypatch.setattr(storage, 'KINDS', old_kinds | {bstore.KIND})
    assert {e.id for e in EnrichmentStore(service.store).entries(bstore.KIND)} == ids
