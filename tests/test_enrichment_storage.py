"""SPEC-07 §10: additive enrichment tables keep v1 project compatibility."""
from __future__ import annotations

import sqlite3

import pytest

from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.service import ProjectService

G = Guard('p', 'r', 'a' * 64, 'b' * 64)


@pytest.fixture
def service(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    yield svc
    if not svc.store.closed:
        svc.close()


def guard_for(svc):
    run = next(r for r in svc.project.runs if r.raw_sha256)
    return Guard(svc.project.id, run.id, run.raw_sha256, 'c' * 64)


def test_first_use_backs_up_then_creates_tables(service):
    store = EnrichmentStore(service.store)
    store.ensure()
    backups = list((service.root / 'backups').glob('project-pre-enrichment-*.sqlite3'))
    assert len(backups) == 1
    copy = sqlite3.connect(backups[0])
    try:
        names = {r[0] for r in copy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        copy.close()
    assert 'enrichment_entries' not in names and 'current_snapshot' in names
    store.ensure()
    assert len(list((service.root / 'backups').iterdir())) == 1


def test_v1_open_save_backup_still_work_with_extension_tables(service, tmp_path):
    g = guard_for(service)
    EnrichmentStore(service.store).publish('ranking', g, g, service.project.revision, 'complete', {'x': 1}, 'e1')
    root = service.root
    service.close()
    reopened = ProjectService.open(root)
    try:
        assert reopened.store.connection.execute('PRAGMA user_version').fetchone()[0] == 1
        reopened.save()
        copy = reopened.backup(tmp_path / 'backup-copy')
        assert EnrichmentStore(reopened.store).current('ranking', g).body == {'x': 1}
    finally:
        reopened.close()
    restored = ProjectService.open(copy)
    try:
        assert EnrichmentStore(restored.store).current('ranking', g).body == {'x': 1}
    finally:
        restored.close()


def test_table_creation_failure_rolls_back(service, monkeypatch):
    store = EnrichmentStore(service.store)
    real = service.store.connection

    class Failing:
        def __getattr__(self, name):
            return getattr(real, name)

        def execute(self, sql, *args):
            if sql.startswith('CREATE INDEX'):
                raise sqlite3.OperationalError('simulated failure')
            return real.execute(sql, *args)

        def __enter__(self):
            return real.__enter__()

        def __exit__(self, *exc):
            return real.__exit__(*exc)

    monkeypatch.setattr(service.store, 'connection', Failing())
    with pytest.raises(sqlite3.OperationalError):
        store.ensure()
    monkeypatch.undo()
    names = {r[0] for r in real.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'enrichment_meta' not in names and 'enrichment_entries' not in names
    assert service.store.load().id == service.project.id


def test_late_result_is_stored_stale_not_current(service):
    store = EnrichmentStore(service.store)
    g = guard_for(service)
    moved = Guard(g.project_id, g.run_id, g.raw_sha256, 'd' * 64)
    entry = store.publish('signals', g, moved, 1, 'complete', {'v': 1}, 'late')
    assert entry.stale
    assert store.current('signals', g) is None
    assert store.entries('signals')[0].stale


def test_current_entry_becomes_stale_when_inputs_change(service):
    store = EnrichmentStore(service.store)
    g = guard_for(service)
    store.publish('ranking', g, g, 1, 'complete', {'v': 1}, 'r1')
    assert store.current('ranking', g) is not None
    rematched = Guard(g.project_id, g.run_id, g.raw_sha256, 'e' * 64)
    assert store.current('ranking', rematched) is None
    assert store.entries('ranking', rematched)[0].stale  # history retained


def test_newer_extension_version_is_read_only_and_preserved(service):
    store = EnrichmentStore(service.store)
    store.ensure()
    with service.store.connection:
        service.store.connection.execute("UPDATE enrichment_meta SET value='99' WHERE key='extension_version'")
    fresh = EnrichmentStore(service.store)
    fresh.ensure()
    assert fresh.read_only
    with pytest.raises(EnrichmentError, match='newer'):
        fresh.publish('ranking', G, G, 1, 'complete', {}, 'x')


def test_limits_kind_and_integrity(service, monkeypatch):
    from patchtrace.enrichment import storage
    store = EnrichmentStore(service.store)
    with pytest.raises(EnrichmentError, match='kind'):
        store.publish('bogus', G, G, 1, 'complete', {}, 'x')
    monkeypatch.setattr(storage, 'MAX_ROW', 10)
    with pytest.raises(EnrichmentError, match='32 MiB'):
        store.publish('ranking', G, G, 1, 'complete', {'big': 'x' * 100}, 'x')
    monkeypatch.setattr(storage, 'MAX_ROW', 10_000)
    monkeypatch.setattr(storage, 'MAX_TOTAL', 50)
    store.publish('ranking', G, G, 1, 'complete', {'a': 'x' * 20}, 'one')
    with pytest.raises(EnrichmentError, match='128 MiB'):
        store.publish('ranking', G, G, 1, 'complete', {'a': 'y' * 20}, 'two')
    with service.store.connection:
        service.store.connection.execute("UPDATE enrichment_entries SET body='{\"a\":\"tampered\"}'")
    with pytest.raises(EnrichmentError, match='integrity'):
        store.entries('ranking')
