"""SPEC-51 recovery: real consumer gaps and cache publication boundaries."""
from __future__ import annotations

import pytest
from pe_meta_builder import meta_pe

from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.pe_overview.authenticode import TrustResult
from patchtrace.pe_overview.metadata import PeMetadata
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'older.exe', tmp_path / 'newer.exe'
    older.write_bytes(meta_pe('1.0.0.0')[0])
    newer.write_bytes(meta_pe('1.0.1.0')[0])
    service = ProjectService.create(older, newer, 'metadata recovery', tmp_path / 'case')
    yield service
    service.close()


def inspect(service):
    return inspect_project_artifacts(
        service.project.id, service.project.artifacts, service.root,
        verify_trust=lambda _path: TrustResult('unavailable', None, 'synthetic fixture'))


def test_existing_inspection_delivers_metadata_before_reader_handoff(service):
    result = inspect(service)
    try:
        for side in ('older', 'newer'):
            metadata = getattr(result.sides[side], 'metadata', None)
            assert metadata is not None and metadata.status == 'ok'
            assert metadata.version.blocks[0].fixed.file_version[:2] == (1, 0)
    finally:
        result.close()


def test_missing_signing_metadata_is_unavailable_not_an_absent_version(qtbot):
    from patchtrace.ui_inspection import SigningTab
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result({'older': None, 'newer': PeMetadata('ok')})
    assert 'PT-PE-INPUT' in tab.status.full_text()


def stored(service, result):
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.pe_overview.cache import KIND
    from patchtrace.pe_overview.cache_store import publish_metadata_cache
    assert publish_metadata_cache(service, result) == 2
    return EnrichmentStore(service.store).entries(KIND)


@pytest.mark.parametrize('revision', ['future', 'negative', 'text'])
def test_cache_refuses_invalid_or_future_row_revision(service, revision):
    from patchtrace.pe_overview.cache_store import publish_metadata_cache, snapshot_metadata_cache
    result = inspect(service)
    try:
        entry = stored(service, result)[0]
        value = {'future': service.project.revision + 1, 'negative': -1, 'text': 'invalid'}[revision]
        db = service.store.connection
        with db:
            db.execute('UPDATE enrichment_entries SET project_revision=? WHERE id=?', (value, entry.id))
        before = db.execute('SELECT * FROM enrichment_entries WHERE id=?', (entry.id,)).fetchone()
        assert entry.guard.raw_sha256 not in snapshot_metadata_cache(service)
        assert publish_metadata_cache(service, result) == 1
        assert db.execute('SELECT * FROM enrichment_entries WHERE id=?', (entry.id,)).fetchone() == before
    finally:
        result.close()


@pytest.mark.parametrize('column,value', [
    ('kind', 'ranking'), ('project_id', 'another-project'), ('run_id', 'another-run'),
    ('raw_sha256', '0' * 64), ('input_digest', '1' * 64), ('project_revision', 'future'),
])
def test_cache_publication_refuses_changed_owner_at_write(service, monkeypatch, column, value):
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.pe_overview.cache_store import publish_metadata_cache
    result = inspect(service)
    try:
        entry = stored(service, result)[0]
        db = service.store.connection
        with db:
            db.execute("UPDATE enrichment_entries SET status='failed' WHERE id=?", (entry.id,))
        real_publish = EnrichmentStore.publish
        changed = []

        def replace_before_write(store, kind, guard, current, revision, status, body, entry_id, *args, **kwargs):
            if entry_id == entry.id:
                replacement = service.project.revision + 1 if value == 'future' else value
                with db:
                    db.execute(f'UPDATE enrichment_entries SET {column}=? WHERE id=?', (replacement, entry_id))
                changed.append(db.execute('SELECT * FROM enrichment_entries WHERE id=?', (entry_id,)).fetchone())
            return real_publish(store, kind, guard, current, revision, status, body, entry_id, *args, **kwargs)

        monkeypatch.setattr(EnrichmentStore, 'publish', replace_before_write)
        assert publish_metadata_cache(service, result) == 1
        assert len(changed) == 1
        assert db.execute('SELECT * FROM enrichment_entries WHERE id=?', (entry.id,)).fetchone() == changed[0]
    finally:
        result.close()


def test_cache_full_store_does_not_request_history_eviction(service, monkeypatch):
    from patchtrace.enrichment import storage
    from patchtrace.pe_overview.cache_store import publish_metadata_cache
    result = inspect(service)
    try:
        enrichment = storage.EnrichmentStore(service.store)
        guard = storage.Guard(service.project.id, 'run', 'raw', 'inputs')
        enrichment.publish('pipeline', guard, guard, service.project.revision, 'complete',
                           {'historical': 'retained derived result'}, 'retained-history')
        db = service.store.connection
        before = db.execute('SELECT * FROM enrichment_entries').fetchall()
        monkeypatch.setattr(storage, 'MAX_TOTAL', 1)
        evictions = []
        monkeypatch.setattr(storage.EnrichmentStore, 'make_room', lambda *args, **kwargs: evictions.append(True))
        assert publish_metadata_cache(service, result) == 0
        assert evictions == []
        assert db.execute('SELECT * FROM enrichment_entries').fetchall() == before
    finally:
        result.close()


def test_pair_snapshot_refuses_after_third_record():
    from patchtrace.pe_overview.cache_store import _pair

    class NeverEnds:
        def __iter__(self):
            from types import SimpleNamespace
            for side in ('older', 'newer', 'older'):
                yield SimpleNamespace(side=side, sha256='0' * 64)
            pytest.fail('pair admission consumed more than three records')

    with pytest.raises(ValueError, match='oriented artifact pair'):
        _pair(NeverEnds())


@pytest.mark.parametrize('column', ['project_id', 'created', 'raw_sha256'])
def test_exact_entry_bounds_guard_metadata_before_python_row_materialization(service, monkeypatch, column):
    from patchtrace.enrichment import storage
    from patchtrace.enrichment.contracts import EnrichmentError
    from patchtrace.pe_overview.cache import KIND
    result = inspect(service)
    try:
        entry = stored(service, result)[0]
    finally:
        result.close()
    real = service.store.connection
    monkeypatch.setattr(storage, 'MAX_ENTRY_METADATA_BYTES', 512, raising=False)
    with real:
        real.execute(f'UPDATE enrichment_entries SET {column}=? WHERE id=?', ('x' * 513, entry.id))
    returned = []

    class ObservedCursor:
        def __init__(self, cursor):
            self.cursor = cursor

        def fetchone(self):
            row = self.cursor.fetchone()
            returned.append(row is not None)
            return row

    class ObservedConnection:
        def __getattr__(self, name):
            return getattr(real, name)

        def execute(self, sql, values=()):
            cursor = real.execute(sql, values)
            return ObservedCursor(cursor) if sql.startswith('SELECT id,kind,project_id') else cursor

    monkeypatch.setattr(service.store, 'connection', ObservedConnection())
    with pytest.raises(EnrichmentError):
        storage.EnrichmentStore(service.store).entry(KIND, entry.id)
    assert returned == [False]
