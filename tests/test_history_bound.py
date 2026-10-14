"""H2: bounded history table (SPEC-07h)."""
import sqlite3

import pytest

from patchtrace import persistence
from patchtrace.persistence import HISTORY_KEEP
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    svc = ProjectService.create(older, newer, 'Comparison', tmp_path / 'project')
    yield svc
    svc.close()


def _save_named(service, name, revision=None):
    candidate = service.project.model_copy(deep=True)
    candidate.name = name
    if revision is not None:
        candidate.revision = revision
    service.store.save(candidate)
    return candidate


def test_history_keeps_newest_rows_and_current(service):
    assert HISTORY_KEEP == 100
    for i in range(150):
        _save_named(service, f'name {i}')
    rows = service.store.history()
    assert len(rows) == 100
    assert [r['sequence'] for r in rows] == sorted(r['sequence'] for r in rows)
    current = service.store.connection.execute('SELECT sha256 FROM current_snapshot').fetchone()[0]
    assert rows[-1]['sha256'] == current


def test_revision_bump_snapshots_are_kept(service):
    _save_named(service, 'bump', revision=5)
    for i in range(150):
        _save_named(service, f'same {i}', revision=5)
    _save_named(service, 'final', revision=6)
    revisions = [r['revision'] for r in service.store.history()]
    assert revisions.count(5) >= 1
    assert len(revisions) <= 100 + 3


def test_byte_budget_prunes_oldest_but_never_current(service, monkeypatch):
    monkeypatch.setattr(persistence, 'HISTORY_MAX_BYTES', 2000)
    for i in range(10):
        _save_named(service, 'x' * 600 + str(i))
    rows = service.store.history()
    assert 1 <= len(rows) < 10
    current = service.store.connection.execute('SELECT sha256 FROM current_snapshot').fetchone()[0]
    assert rows[-1]['sha256'] == current


def test_duplicate_hash_save_adds_no_row(service):
    before = len(service.store.history())
    service.store.save(service.project)
    service.store.save(service.project)
    assert len(service.store.history()) == before


def test_prune_failure_rolls_back_whole_save(service, monkeypatch):
    for i in range(3):
        _save_named(service, f'n{i}')
    before = service.store.history()
    snapshot_before = service.store.connection.execute('SELECT payload FROM current_snapshot').fetchone()[0]
    monkeypatch.setattr(persistence, 'HISTORY_KEEP', 1)

    def boom(*_args, **_kwargs):
        raise sqlite3.OperationalError('prune failed')

    monkeypatch.setattr(persistence.ProjectStore, '_prune_history', boom)
    with pytest.raises(ValueError, match='prior snapshot retained'):
        _save_named(service, 'new')
    assert service.store.history() == before
    assert service.store.connection.execute('SELECT payload FROM current_snapshot').fetchone()[0] == snapshot_before
