"""Real PE/project SQLite controls for operation reads and the first COMMIT."""
from __future__ import annotations

import hashlib
import os

import pytest
from held_input_support import Checkpoint, ReadStopped, authored_pair, deny_source_opens

from patchtrace import persistence
from patchtrace import service as core
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def test_real_project_creation_uses_both_held_inputs_and_reopens_without_them(tmp_path, monkeypatch):
    with authored_pair(tmp_path) as (paths, readers):
        expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
        deny_source_opens(monkeypatch, paths)
        root = tmp_path / 'project'
        with ProjectService.create(*paths, 'held', root, input_readers=readers) as project:
            assert [item.sha256 for item in project.project.artifacts] == expected
            assert project.project.revision == 0
        for lease in (readers.older, readers.newer):
            assert lease.opened == lease.closed == 1
            assert os.fstat(lease.fd).st_size == lease.captured[2]
        assert sum(count for kind, count in readers.checkpoint.counts if kind == 'held') == sum(
            lease.bytes_read for lease in (readers.older, readers.newer))
        assert sum(count for kind, count in readers.checkpoint.counts if kind == 'core') >= sum(
            lease.captured[2] for lease in (readers.older, readers.newer))
    # The source owner releases its handles before removal on Windows.
    for path in paths:
        path.unlink()
    with ProjectService.open(root, maintenance=False) as reopened:
        assert [item.sha256 for item in reopened.project.artifacts] == expected


@pytest.mark.parametrize('phase', ['before-store', 'newer-copy', 'save-verification'])
def test_operation_failure_cleans_only_new_owned_project_files(tmp_path, monkeypatch, phase):
    with authored_pair(tmp_path) as (paths, readers):
        root = tmp_path / 'project'
        root.mkdir()
        foreign = root / 'analyst.txt'
        foreign.write_bytes(b'keep me')
        if phase == 'before-store':
            readers.checkpoint.stop = lambda count, kind: True
        elif phase == 'newer-copy':
            readers.newer.on_read = lambda: (_ for _ in ()).throw(ReadStopped('newer copy stopped'))
        else:
            original = ProjectStore._verify_files

            def verify(store, project, **kwargs):
                readers.checkpoint.stop = lambda count, kind: count > 0
                return original(store, project, **kwargs)

            monkeypatch.setattr(ProjectStore, '_verify_files', verify)
        with pytest.raises(ReadStopped):
            ProjectService.create(*paths, 'interrupted', root, input_readers=readers)
        assert foreign.read_bytes() == b'keep me'
        assert not (root / 'project.sqlite3').exists()
        assert not list(root.rglob('*.bin')) and not list(root.rglob('.input-*'))
        assert all(not lease.active and lease.opened == lease.closed for lease in (readers.older, readers.newer))


@pytest.mark.parametrize('database', ['new', 'zero-byte', 'empty-current'])
def test_precommit_cancel_rolls_back_sqlite_and_preserves_retry_inputs(tmp_path, monkeypatch, database):
    with authored_pair(tmp_path) as (paths, readers):
        root = tmp_path / 'project'
        root.mkdir()
        db = root / 'project.sqlite3'
        if database == 'zero-byte':
            db.write_bytes(b'')
        elif database == 'empty-current':
            with ProjectStore(root, create=True):
                pass
        before = db.read_bytes() if db.exists() else None
        foreign = root / 'keep.txt'
        foreign.write_text('unchanged')
        original = ProjectStore.__init__
        traces, stores = [], []

        def init(store, *args, **kwargs):
            original(store, *args, **kwargs)
            stores.append(store)
            store.connection.set_trace_callback(traces.append)

        monkeypatch.setattr(ProjectStore, '__init__', init)

        def stop(count, kind):
            return (bool(stores) and stores[0].connection.in_transaction
                    and any(sql.startswith('INSERT INTO current_snapshot') for sql in traces))

        readers.checkpoint.stop = stop
        with pytest.raises(ReadStopped, match='authored operation stopped'):
            ProjectService.create(*paths, 'cancel before commit', root, input_readers=readers)
        assert any(sql.startswith('INSERT INTO current_snapshot') for sql in traces)
        assert 'ROLLBACK' in traces and 'COMMIT' not in traces
        assert foreign.read_text() == 'unchanged'
        if before is None:
            assert not db.exists()
        else:
            assert db.read_bytes() == before
        assert not list(root.rglob('*.bin'))
        readers.checkpoint.stop = lambda count, kind: False
        with ProjectService.create(*paths, 'healthy retry', root, input_readers=readers) as retried:
            assert retried.project.name == 'healthy retry'


def test_no_checkpoint_after_commit_can_enter_creation_rollback(tmp_path, monkeypatch):
    with authored_pair(tmp_path) as (paths, readers):
        original_save = ProjectStore.save
        original_rollback = core._rollback_creation
        rolled_back = []

        def save(store, project, **kwargs):
            result = original_save(store, project, **kwargs)
            assert not store.connection.in_transaction
            readers.checkpoint.stop = lambda count, kind: True
            return result

        def rollback(*args):
            rolled_back.append(True)
            return original_rollback(*args)

        monkeypatch.setattr(ProjectStore, 'save', save)
        monkeypatch.setattr(core, '_rollback_creation', rollback)
        root = tmp_path / 'project'
        with ProjectService.create(*paths, 'committed', root, input_readers=readers) as made:
            expected_id = made.project.id
        assert rolled_back == []
        with pytest.raises(ReadStopped):
            readers.checkpoint(0)  # A later outer observation does not undo the completed project.
        with ProjectService.open(root, maintenance=False) as reopened:
            assert reopened.project.id == expected_id


def test_checkpoint_runs_on_verified_cache_hits_without_rehashing(tmp_path):
    path = tmp_path / 'plain.sys'
    path.write_bytes(synthetic_pe(0))
    with ProjectService.create(path, path, 'cached', tmp_path / 'project') as project:
        checkpoint = Checkpoint()
        project.store.save(project.project, checkpoint=checkpoint)
        assert checkpoint.counts and all(count == 0 for _, count in checkpoint.counts)
        checkpoint.stop = lambda count, kind: True
        before = project.store.connection.execute('SELECT payload,sha256 FROM current_snapshot').fetchone()
        with pytest.raises(ReadStopped):
            project.store.save(project.project, checkpoint=checkpoint)
        assert project.store.connection.execute('SELECT payload,sha256 FROM current_snapshot').fetchone() == before


def test_checkpoint_does_not_skip_corrupt_immutable_copy_verification(tmp_path):
    path = tmp_path / 'plain.sys'
    path.write_bytes(synthetic_pe(0))
    with ProjectService.create(path, path, 'original', tmp_path / 'project') as project:
        before = project.store.connection.execute('SELECT payload,sha256 FROM current_snapshot').fetchone()
        copy = project.root / project.project.artifacts[0].relative_path
        copy.chmod(0o600)
        copy.write_bytes(b'X' * copy.stat().st_size)
        candidate = project.project.model_copy(deep=True)
        candidate.name = 'must not commit'
        checkpoint = Checkpoint()
        with pytest.raises(ValueError, match='immutable input'):
            project.store.save(candidate, checkpoint=checkpoint)
        assert project.store.connection.execute('SELECT payload,sha256 FROM current_snapshot').fetchone() == before
        assert any(count > 0 for _, count in checkpoint.counts)


def test_ordinary_create_preserves_injected_function_call_shapes(tmp_path, monkeypatch):
    path = tmp_path / 'plain.sys'
    path.write_bytes(synthetic_pe(0))
    actual_inspect, actual_save = core.inspect_artifact, ProjectStore.save
    actual_verify, actual_files = persistence.verify_artifact, ProjectStore._verify_files
    calls = []

    def inspect(path, side, root, *, created):
        calls.append('inspect')
        return actual_inspect(path, side, root, created=created)

    def save(store, project):
        calls.append('save')
        return actual_save(store, project)

    def verify(artifact, root):
        calls.append('verify')
        return actual_verify(artifact, root)

    def files(store, project):
        return actual_files(store, project)

    monkeypatch.setattr(core, 'inspect_artifact', inspect)
    monkeypatch.setattr(ProjectStore, 'save', save)
    monkeypatch.setattr(ProjectStore, '_verify_files', files)
    monkeypatch.setattr(persistence, 'verify_artifact', verify)
    with ProjectService.create(path, path, 'ordinary', tmp_path / 'project'):
        pass
    assert calls.count('inspect') == 2 and calls.count('save') == 1 and 'verify' in calls
