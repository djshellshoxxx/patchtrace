"""Refuse ineligible cached backups without full byte reads; eligible trust still rehashes."""
from pathlib import Path

import pytest

from patchtrace import verified_backup as V
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    V.forget_all()
    with ProjectService.sample(tmp_path / 'project') as result:
        yield result
    V.forget_all()


@pytest.mark.parametrize('requirements', [
    {'project_id': 'another-project'},
    {'snapshot_sha': '0' * 64},
    {'require_tables': ('nonexistent-required-table',)},
])
def test_unacceptable_cached_facts_do_not_read_backup_bytes(service, monkeypatch, requirements):
    backup = V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    reads = []
    original = V._fingerprint

    def observed(path):
        reads.append(Path(path))
        return original(path)

    monkeypatch.setattr(V, '_fingerprint', observed)
    assert V.trusted_backup(service.root, 'history-prune', **requirements) is None
    assert reads == []
    assert V.trusted_backup(service.root, 'history-prune', project_id=service.project.id) == backup
    assert reads == [backup]


def test_failed_cached_check_is_not_rehashed_until_preparatory_verification(service, monkeypatch):
    backup = V.write_verified_backup(service.root, service.store.connection, 'history-prune')
    original_bytes = backup.read_bytes()
    backup.write_bytes(b'not a SQLite database')
    assert V.find_verified_backup(service.root, 'history-prune') is None
    reads = []
    original = V._fingerprint

    def observed(path):
        reads.append(Path(path))
        return original(path)

    monkeypatch.setattr(V, '_fingerprint', observed)
    assert V.trusted_backup(service.root, 'history-prune') is None
    assert reads == []
    # A changed, now-valid copy can be independently verified by the preparation path.
    backup.write_bytes(original_bytes)
    assert V.find_verified_backup(service.root, 'history-prune', project_id=service.project.id) == backup
    assert reads
    reads.clear()
    assert V.trusted_backup(service.root, 'history-prune', project_id=service.project.id) == backup
    assert reads == [backup]
