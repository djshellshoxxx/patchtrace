"""SPEC-07h H2 (+H1): no prune deletes rows before a re-opened, integrity-checked backup exists.

Synthetic projects only (`synthetic_pe` / `ProjectService.sample`); real SQLite files on disk.
"""
from __future__ import annotations

import os
import shutil
import sqlite3

import pytest

from patchtrace import persistence, verified_backup
from patchtrace.enrichment import storage
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

FUTURE = '9999-01-01T00:00:00+00:00'


@pytest.fixture(autouse=True)
def _fresh_cache():
    verified_backup.forget_all()
    yield
    verified_backup.forget_all()


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    svc = ProjectService.create(older, newer, 'Comparison', tmp_path / 'project')
    yield svc
    if not svc.store.closed:
        svc.close()


def _save(service, name):
    candidate = service.project.model_copy(deep=True)
    candidate.name = name
    service.project = service.store.save(candidate)


def _backups(root, label):
    return sorted((root / 'backups').glob(f'project-pre-{label}-*.sqlite3'))


def _sequences(path_or_db):
    db = path_or_db if isinstance(path_or_db, sqlite3.Connection) else sqlite3.connect(path_or_db)
    try:
        return {row[0] for row in db.execute('SELECT sequence FROM history')}
    finally:
        if db is not path_or_db:
            db.close()


def _corrupt(path):
    data = bytearray(path.read_bytes())
    data[100:4096] = b'\xa5' * (4096 - 100)  # header kept, first b-tree page destroyed
    path.write_bytes(bytes(data))


# --- H2: history prune -------------------------------------------------------------------------

def test_history_prune_takes_verified_backup(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 4)
    for i in range(3):  # create + 3 saves = 4 rows: still within the bound
        _save(service, f'n{i}')
    assert _backups(service.root, 'history-prune') == []  # nothing pruned yet, nothing copied
    _save(service, 'first prune')
    backups = _backups(service.root, 'history-prune')
    assert len(backups) == 1 and not list((service.root / 'backups').glob('*.part'))
    copy = sqlite3.connect(f'{backups[0].as_uri()}?mode=ro', uri=True)
    try:
        assert copy.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        kept_in_backup = _sequences(copy)
    finally:
        copy.close()
    live = _sequences(service.store.connection)
    assert len(live) == 4 and live < kept_in_backup  # every deleted row is in the backup
    for i in range(6):
        _save(service, f'later {i}')
    assert len(_backups(service.root, 'history-prune')) == 1  # taken once, then reused
    assert len(service.store.history()) == 4


def test_history_kept_when_backup_impossible(service, monkeypatch, caplog):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    (service.root / 'backups').write_text('not a directory', encoding='utf-8')
    with caplog.at_level('WARNING'):
        for i in range(5):
            _save(service, f'n{i}')
    assert len(service.store.history()) == 6  # create + 5 saves, nothing deleted
    assert service.store.load().name == 'n4'  # the saves themselves succeeded
    assert 'history' in caplog.text.lower() and 'backup' in caplog.text.lower()


def test_history_backup_checked_on_reopened_file(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    monkeypatch.setattr(verified_backup, '_after_copy', _corrupt)
    for i in range(4):
        _save(service, f'n{i}')
    assert _backups(service.root, 'history-prune') == []
    assert not list((service.root / 'backups').glob('*.part'))
    assert len(service.store.history()) == 5  # prune aborted, rows kept


def test_corrupt_history_backup_not_trusted(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    (service.root / 'backups').mkdir()
    fake = service.root / 'backups' / 'project-pre-history-prune-20000101T000000000000Z.sqlite3'
    fake.write_bytes(b'SQLite format 3\x00' + b'\x00' * 200)
    for i in range(3):
        _save(service, f'n{i}')
    backups = _backups(service.root, 'history-prune')
    assert len(backups) == 2 and fake in backups
    assert len(service.store.history()) == 2


def test_foreign_project_backup_not_trusted(service, tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    other = ProjectService.create(tmp_path / 'o.dll', tmp_path / 'n.dll', 'Other', tmp_path / 'other')
    try:
        for i in range(3):
            _save(other, f'o{i}')
        foreign = _backups(other.root, 'history-prune')[0]
    finally:
        other.close()
    (service.root / 'backups').mkdir()
    shutil.copy2(foreign, service.root / 'backups' / foreign.name)
    verified_backup.forget_all()
    for i in range(3):
        _save(service, f'n{i}')
    assert len(_backups(service.root, 'history-prune')) == 2


def test_backup_swapped_during_verification_is_not_trusted(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    for i in range(3):
        _save(service, f'n{i}')
    (backup,) = _backups(service.root, 'history-prune')
    verified_backup.forget_all()
    real = verified_backup._verify

    def swap_after_check(path, *args, **kwargs):
        verdict = real(path, *args, **kwargs)
        stat = path.stat()
        _corrupt(path)  # same size, newer mtime: only a fingerprint taken before the check can tell
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 5_000_000_000))
        return verdict
    monkeypatch.setattr(verified_backup, '_verify', swap_after_check)
    assert verified_backup.find_verified_backup(service.root, 'history-prune') is None
    assert verified_backup.trusted_backup(service.root, 'history-prune') is None
    assert backup.exists()


def test_backup_reverified_once_per_file_version(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    for i in range(3):
        _save(service, f'n{i}')
    calls = []
    real = verified_backup._verify

    def spy(*args, **kwargs):
        calls.append(args[0])
        return real(*args, **kwargs)
    monkeypatch.setattr(verified_backup, '_verify', spy)
    for i in range(5):
        _save(service, f'more {i}')
    assert calls == []  # verified when written; the cached verdict covers this file version
    service.close()
    verified_backup.forget_all()  # a new process knows nothing
    with ProjectService.open(service.root) as reopened:
        _save(reopened, 'after reopen')
        _save(reopened, 'again')
    assert len(calls) == 1 and len(_backups(service.root, 'history-prune')) == 1


# --- H1 retention uses the same rule -------------------------------------------------------------

@pytest.fixture
def sample(tmp_path):
    svc = ProjectService.sample(tmp_path / 'case')
    yield svc
    if not svc.store.closed:
        svc.close()


CURRENT = Guard('p', 'r', 'a' * 64, 'b' * 64)


def _generations(store, count):
    for n in range(count):
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            store.publish(kind, CURRENT, CURRENT, 0, 'complete', {'pad': 'x' * 50}, f'{kind}:{rid}')
        store.publish('pipeline', CURRENT, CURRENT, 0, 'complete',
                      {'stage_ids': {'ranking': rid, 'wil': rid, 'signals': rid}, 'config_digest': 'cfg',
                       'default_profile': False}, f'pipeline:{rid}')


def _row_ids(svc):
    return {r[0] for r in svc.store.connection.execute('SELECT id FROM enrichment_entries')}


def test_retention_ignores_corrupt_backup(sample):
    store = EnrichmentStore(sample.store)
    _generations(store, 10)
    (sample.root / 'backups').mkdir(exist_ok=True)
    fake = sample.root / 'backups' / 'project-pre-retention-20000101T000000000000Z.sqlite3'
    fake.write_bytes(b'garbage, not a database')
    before = _row_ids(sample)
    assert store.apply_retention(CURRENT, started=FUTURE) > 0
    fresh = [p for p in _backups(sample.root, 'retention') if p != fake]
    assert len(fresh) == 1
    copy = sqlite3.connect(f'{fresh[0].as_uri()}?mode=ro', uri=True)
    try:
        assert copy.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        assert {r[0] for r in copy.execute('SELECT id FROM enrichment_entries')} == before
    finally:
        copy.close()


def test_retention_aborts_on_unverifiable_backup(sample, monkeypatch):
    store = EnrichmentStore(sample.store)
    _generations(store, 10)
    before = _row_ids(sample)
    monkeypatch.setattr(verified_backup, '_after_copy', _corrupt)
    assert store.apply_retention(CURRENT, started=FUTURE) == 0
    assert _row_ids(sample) == before and _backups(sample.root, 'retention') == []
    assert not sample.store.connection.in_transaction


def test_make_room_backup_failure_is_recoverable(sample, monkeypatch):
    store = EnrichmentStore(sample.store)
    _generations(store, 10)
    before = _row_ids(sample)
    monkeypatch.setattr(verified_backup, '_after_copy', _corrupt)
    with pytest.raises(EnrichmentError) as info:
        store.make_room(100, Guard('p', 'r', 'a' * 64, 'c' * 64))
    assert info.value.code == 'PT-ENRICH-LIMIT' and info.value.recoverable
    assert _row_ids(sample) == before


def test_worker_verification_reused_by_owner(sample, monkeypatch):
    store = EnrichmentStore(sample.store)
    _generations(store, 10)
    assert store.apply_retention(CURRENT, started=FUTURE) > 0  # writes the one retention backup
    verified_backup.forget_all()  # as after a restart
    storage.prepare_backups(sample.root)  # worker thread: re-verifies the existing backup
    calls = []
    real = verified_backup._verify
    monkeypatch.setattr(verified_backup, '_verify', lambda *a, **k: calls.append(a[0]) or real(*a, **k))
    _generations(store, 12)
    assert store.apply_retention(CURRENT, started=FUTURE) > 0
    assert calls == [] and len(_backups(sample.root, 'retention')) == 1
