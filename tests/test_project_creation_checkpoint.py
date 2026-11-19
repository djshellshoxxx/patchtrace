"""Ordinary creation cancellation reaches real copies and the real first-save transaction."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from patchtrace import service as core
from patchtrace.input_readers import InputReadError
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


def pair(tmp_path):
    paths = tmp_path / 'older.dll', tmp_path / 'newer.dll'
    for path, version in zip(paths, (0, 1), strict=True):
        path.write_bytes(synthetic_pe(version))
    return paths


def files(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob('*')
            if path.is_file() and path.name != '.patchtrace.lock'}


def test_cancel_before_store_does_not_touch_destination(tmp_path):
    paths, root = pair(tmp_path), tmp_path / 'project'
    primary = InputReadError('cancelled')

    def stop(_count):
        raise primary

    with pytest.raises(InputReadError) as caught:
        ProjectService.create(*paths, 'cancelled', root, checkpoint=stop)
    assert caught.value is primary and not root.exists()


@pytest.mark.parametrize('database', ['new', 'zero-byte', 'empty-current'])
@pytest.mark.parametrize('phase', ['copy', 'precommit'])
def test_stop_preserves_existing_bytes_and_rolls_back_only_this_attempt(tmp_path, monkeypatch, database, phase):
    paths, root = pair(tmp_path), tmp_path / 'project'
    root.mkdir()
    database_path = root / 'project.sqlite3'
    if database == 'zero-byte':
        database_path.write_bytes(b'')
    elif database == 'empty-current':
        with ProjectStore(root, create=True):
            pass
    (root / 'keep.txt').write_bytes(b'preexisting analyst data')
    before = files(root)
    stores, statements, counts = [], [], []
    original_init = ProjectStore.__init__
    primary = InputReadError('cancelled')

    def initialize(store, *args, **kwargs):
        original_init(store, *args, **kwargs)
        stores.append(store)
        store.connection.set_trace_callback(statements.append)

    def checkpoint(count):
        counts.append(count)
        if phase == 'copy' and count > 0:
            raise primary
        if (phase == 'precommit' and stores and stores[0].connection.in_transaction and
                any(sql.startswith('INSERT INTO current_snapshot') for sql in statements)):
            raise primary

    monkeypatch.setattr(ProjectStore, '__init__', initialize)
    with pytest.raises(InputReadError) as caught:
        ProjectService.create(*paths, 'cancelled', root, checkpoint=checkpoint)
    assert caught.value is primary and files(root) == before
    assert any(count > 0 for count in counts)
    if phase == 'precommit':
        assert 'ROLLBACK' in statements and 'COMMIT' not in statements
    with ProjectService.create(*paths, 'healthy retry', root) as service:
        assert service.project.name == 'healthy retry'


def test_callback_does_not_reenter_after_successful_commit(tmp_path, monkeypatch):
    paths, root = pair(tmp_path), tmp_path / 'project'
    saved, counts = [], []
    original_save = ProjectStore.save

    def save(store, project, **kwargs):
        result = original_save(store, project, **kwargs)
        saved.append(result.id)
        return result

    def checkpoint(count):
        assert not saved, 'creation invoked the operation callback after a committed result'
        counts.append(count)

    monkeypatch.setattr(ProjectStore, 'save', save)
    with ProjectService.create(*paths, 'completed', root, checkpoint=checkpoint) as service:
        expected_id = service.project.id
    assert saved == [expected_id] and any(count > 0 for count in counts)
    with ProjectService.open(root) as reopened:
        assert reopened.project.id == expected_id


def test_explicit_checkpoint_cannot_replace_a_held_operation_policy(tmp_path, monkeypatch):
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError('conflicting operation policies reached I/O')

    readers = SimpleNamespace(checkpoint=unexpected)
    monkeypatch.setattr(core, 'ProjectStore', unexpected)
    with pytest.raises(InputReadError) as caught:
        ProjectService.create(tmp_path / 'old', tmp_path / 'new', 'invalid', tmp_path / 'destination',
                              input_readers=readers, checkpoint=lambda count: None)
    assert caught.value.reason == 'invalid' and not calls
