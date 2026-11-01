"""Real SQLite backup/pruning regressions for issue #121; no target execution."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from patchtrace import persistence, verified_backup
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    verified_backup.forget_all()
    older, newer = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    with ProjectService.create(older, newer, 'Backup integrity', tmp_path / 'project') as svc:
        yield svc
    verified_backup.forget_all()


def _change_bytes_preserving_metadata(path):
    before = path.stat()
    with path.open('r+b') as stream:
        stream.seek(100)
        stream.write(b'\xa5' * (4096 - 100))  # Keep header/size; destroy the first SQLite b-tree page.
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = path.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)


def _save(service, name):
    candidate = service.project.model_copy(deep=True)
    candidate.name = name
    service.project = service.store.save(candidate)


def _sequences(service):
    return {row[0] for row in service.store.connection.execute('SELECT sequence FROM history')}


def test_cached_good_backup_does_not_trust_same_size_restored_mtime_corruption(service):
    backup = verified_backup.write_verified_backup(service.root, service.store.connection, 'history-prune')
    assert verified_backup.trusted_backup(service.root, 'history-prune',
                                          project_id=service.project.id, require_tables=('history',)) == backup
    _change_bytes_preserving_metadata(backup)
    assert verified_backup.trusted_backup(service.root, 'history-prune',
                                          project_id=service.project.id, require_tables=('history',)) is None
    assert verified_backup.find_verified_backup(service.root, 'history-prune',
                                                project_id=service.project.id, require_tables=('history',)) is None


def test_public_save_keeps_history_when_cached_backup_was_tampered(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 2)
    _save(service, 'first')
    _save(service, 'second')
    (backup,) = (service.root / 'backups').glob('project-pre-history-prune-*.sqlite3')
    prior = _sequences(service)
    assert len(prior) == 2
    _change_bytes_preserving_metadata(backup)
    # A real replacement copy is attempted but corrupted before verification.
    # Without any usable backup, the save must commit and deletion must stop.
    monkeypatch.setattr(verified_backup, '_after_copy', _change_bytes_preserving_metadata)
    _save(service, 'third')
    assert prior < _sequences(service)
    assert service.store.load().name == 'third'


def test_corruption_after_sqlite_check_cannot_enter_the_verdict_cache(service, monkeypatch):
    backup = verified_backup.write_verified_backup(service.root, service.store.connection, 'history-prune')
    verified_backup.forget_all()
    original_verify = verified_backup._verify

    def corrupt_after_check(path, *args, **kwargs):
        result = original_verify(path, *args, **kwargs)
        assert result[0] is None
        _change_bytes_preserving_metadata(path)
        return result

    monkeypatch.setattr(verified_backup, '_verify', corrupt_after_check)
    assert verified_backup.find_verified_backup(service.root, 'history-prune') is None
    assert verified_backup.trusted_backup(service.root, 'history-prune') is None
    assert backup.exists(), 'failed verification must preserve prior evidence'


def test_published_copy_changed_after_rename_is_not_returned_as_verified(service, monkeypatch):
    original_replace = Path.replace
    published = []

    def replace_then_corrupt(path, target):
        result = original_replace(path, target)
        if path.name.endswith('.sqlite3.part'):
            _change_bytes_preserving_metadata(Path(target))
            published.append(Path(target))
        return result

    monkeypatch.setattr(Path, 'replace', replace_then_corrupt)
    with pytest.raises(verified_backup.BackupError, match='changed during publication'):
        verified_backup.write_verified_backup(service.root, service.store.connection, 'history-prune')
    assert len(published) == 1 and published[0].exists()
    assert verified_backup.trusted_backup(service.root, 'history-prune') is None


def test_unreadable_byte_fingerprint_never_publishes_a_verified_copy(service, monkeypatch):
    monkeypatch.setattr(verified_backup, '_fingerprint', lambda _path: None)
    monkeypatch.setattr(verified_backup, '_verify', lambda *a, **k: pytest.fail('unreadable bytes reached SQLite'))
    with pytest.raises(verified_backup.BackupError, match='changed during verification'):
        verified_backup.write_verified_backup(service.root, service.store.connection, 'history-prune')
    assert not list((service.root / 'backups').glob('*.sqlite3'))


def test_edit_to_already_hashed_bytes_with_restored_mtime_is_not_trusted(service, monkeypatch):
    backup = verified_backup.write_verified_backup(service.root, service.store.connection, 'history-prune')
    original_sha256 = verified_backup.hashlib.sha256

    class MutatingHash:
        def __init__(self):
            self.digest = original_sha256()
            self.changed = False

        def update(self, block):
            self.digest.update(block)
            if not self.changed:
                _change_bytes_preserving_metadata(backup)
                self.changed = True

        def hexdigest(self):
            return self.digest.hexdigest()

    monkeypatch.setattr(verified_backup.hashlib, 'sha256', MutatingHash)
    assert verified_backup.trusted_backup(service.root, 'history-prune') is None
