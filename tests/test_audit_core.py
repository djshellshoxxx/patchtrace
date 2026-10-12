from __future__ import annotations

import sqlite3

import pytest

from patchtrace import persistence
from patchtrace.persistence import ProjectStore, strict_json


class _FailingHistoryDDL(sqlite3.Connection):
    def execute(self, sql, *args):
        if sql.startswith('CREATE TABLE history'):
            raise sqlite3.OperationalError('injected failure')
        return super().execute(sql, *args)


def test_failed_database_initialization_is_atomic_and_retryable(tmp_path, monkeypatch):
    real_connect = sqlite3.connect
    monkeypatch.setattr(persistence.sqlite3, 'connect',
                        lambda *a, **k: real_connect(*a, factory=_FailingHistoryDDL, **k))
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectStore(tmp_path, create=True)
    path = tmp_path / 'project.sqlite3'
    if path.exists():
        # If anything remains, it must not carry a committed version or partial tables.
        connection = real_connect(path)
        try:
            assert connection.execute('PRAGMA user_version').fetchone()[0] == 0
            assert connection.execute('SELECT count(*) FROM sqlite_master').fetchone()[0] == 0
        finally:
            connection.close()
    monkeypatch.setattr(persistence.sqlite3, 'connect', real_connect)
    store = ProjectStore(tmp_path, create=True)
    try:
        tables = {row[0] for row in store.connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {'current_snapshot', 'history'} <= tables
    finally:
        store.close()


def test_failed_initialization_does_not_delete_preexisting_database(tmp_path):
    (tmp_path / 'project.sqlite3').write_bytes(b'existing')
    with pytest.raises(ValueError, match='already exists'):
        ProjectStore(tmp_path, create=True)
    assert (tmp_path / 'project.sqlite3').read_bytes() == b'existing'


@pytest.mark.parametrize('text', ['{"a": 1e999}', '{"a": -1e400}', '[1E+999]'])
def test_strict_json_rejects_overflowing_floats(text):
    with pytest.raises(ValueError, match='PT-SCHEMA: invalid JSON number'):
        strict_json(text)


def test_strict_json_tags_oversized_integers():
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        strict_json('{"a": ' + '9' * 5000 + '}')
    assert strict_json('{"a": 1.5, "b": 7}') == {'a': 1.5, 'b': 7}


def _service(tmp_path):
    from patchtrace.sample import synthetic_pe
    from patchtrace.service import ProjectService
    older, newer = tmp_path / 'old.dll', tmp_path / 'new.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    return ProjectService.create(older, newer, 'audit', tmp_path / 'case')


def test_save_refuses_older_revision_or_foreign_project(tmp_path):
    from patchtrace.models import ComparisonProject
    with _service(tmp_path) as service:
        service.annotate(service.project.artifacts[0].id, 'note')
        bumped = service.project.model_copy(deep=True)
        bumped.revision = 3
        service._commit(bumped)
        older = service.project.model_copy(update={'revision': 2})
        with pytest.raises(ValueError, match='PT-STORAGE: snapshot belongs'):
            service.store.save(older)
        foreign = ComparisonProject(name='x', artifacts=service.project.artifacts, revision=5)
        with pytest.raises(ValueError, match='PT-STORAGE: snapshot belongs'):
            service.store.save(foreign)
        service.save()  # equal revision stays allowed
        assert service.store.load().revision == 3
        assert [row['revision'] for row in service.store.history()][-1] == 3


def test_public_annotate_cannot_forge_match_override(tmp_path):
    with _service(tmp_path) as service:
        before = len(service.project.annotations)
        with pytest.raises(ValueError, match='match-override'):
            service.annotate(service.project.artifacts[0].id, '{}', kind='match-override')
        assert len(service.store.load().annotations) == before


def test_backup_refreshes_service_after_interrupted_run_recovery(tmp_path):
    from patchtrace.models import AnalysisRun
    with _service(tmp_path) as service:
        candidate = service.project.model_copy(deep=True)
        candidate.runs.append(AnalysisRun(status='running'))
        service._commit(candidate)
        service.backup(tmp_path / 'backup')
        assert service.project.runs[-1].status == 'failed'
        assert service.project == service.store.load()


def test_backup_refuses_destination_appearing_as_empty_dir(tmp_path, monkeypatch):
    with _service(tmp_path) as service:
        destination = tmp_path / 'race'
        real = persistence.shutil.copytree
        def copy_then_race(*args, **kwargs):
            result = real(*args, **kwargs)
            destination.mkdir(exist_ok=True)
            return result
        monkeypatch.setattr(persistence.shutil, 'copytree', copy_then_race)
        with pytest.raises(OSError):
            service.backup(destination)
        assert list(destination.iterdir()) == []
        assert not list(tmp_path.glob('.patchtrace-backup-*'))


def test_failed_backup_cleanup_clears_readonly_bit(tmp_path):
    import os
    import stat
    calls = []
    target = tmp_path / 'ro'
    target.write_bytes(b'x')
    target.chmod(stat.S_IREAD)
    def remove(path):
        calls.append(path)
        if not os.stat(path).st_mode & stat.S_IWRITE:
            raise PermissionError(path)
        os.unlink(path)
    with pytest.raises(PermissionError):
        remove(str(target))
    persistence._clear_readonly_and_retry(remove, str(target), None)
    assert not target.exists()
