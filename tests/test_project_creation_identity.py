"""Actual PE/project creation with optional preallocated operation identity."""
from __future__ import annotations

import hashlib
from types import SimpleNamespace
from uuid import UUID

import pytest
from held_input_support import authored_pair, deny_source_opens

from patchtrace import service as core
from patchtrace.input_readers import InputReadError
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

EXPECTED_ID = 'd9460de3-79e5-4639-bdce-2496d1c3746c'


def inputs(tmp_path):
    paths = [tmp_path / f'{side}.sys' for side in ('older', 'newer')]
    for variant, path in enumerate(paths):
        path.write_bytes(synthetic_pe(variant))
    return paths


def owned_bytes(root):
    return {path: path.read_bytes() for path in [root / 'project.sqlite3', *sorted((root / 'artifacts').glob('*.bin'))]
            if path.is_file()}


@pytest.mark.parametrize('project_id', [EXPECTED_ID, 'legacy:研究', 'x' * 128])
def test_actual_create_commits_supplied_identity_and_reopens_without_sources(tmp_path, project_id):
    paths = inputs(tmp_path)
    expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    root = tmp_path / '案例' / 'project'
    with ProjectService.create(*paths, 'preallocated', root, project_id=project_id) as service:
        assert service.project.id == service.store.project_id == project_id
        assert service.project.revision == 0
        assert [artifact.sha256 for artifact in service.project.artifacts] == expected
        assert service.store.connection.execute('PRAGMA user_version').fetchone()[0] == 1
    for path in paths:
        path.unlink()
    with ProjectStore(root) as store:
        actual = store.load(recover_interrupted=False)
        assert actual.id == store.project_id == project_id
        assert [artifact.sha256 for artifact in actual.artifacts] == expected


def test_preallocated_held_create_keeps_existing_source_capability_boundary(tmp_path, monkeypatch):
    with authored_pair(tmp_path) as (paths, readers):
        expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
        deny_source_opens(monkeypatch, paths)
        with ProjectService.create(*paths, 'held', tmp_path / 'project',
                                   input_readers=readers, project_id=EXPECTED_ID) as service:
            assert service.project.id == EXPECTED_ID
            assert [artifact.sha256 for artifact in service.project.artifacts] == expected
        assert all(not reader.active and reader.opened == reader.closed == 1
                   for reader in (readers.older, readers.newer))


@pytest.mark.parametrize('project_id', ['', 'x' * 129, 17, True, b'bytes', ['list']])
def test_invalid_identity_refuses_before_store_source_or_held_checks(tmp_path, monkeypatch, project_id):
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError('invalid identity reached store/source/held I/O')

    monkeypatch.setattr(core, 'ProjectStore', unexpected)
    monkeypatch.setattr(core, 'inspect_artifact', unexpected)
    readers = SimpleNamespace(checkpoint=unexpected, older=SimpleNamespace(check=unexpected),
                              newer=SimpleNamespace(check=unexpected))
    root = tmp_path / 'must-not-exist'
    with pytest.raises(ValueError):
        ProjectService.create(tmp_path / 'absent-old', tmp_path / 'absent-new', 'invalid', root,
                              input_readers=readers, project_id=project_id)
    assert calls == [] and not root.exists()


def test_omitted_identity_retains_default_uuid_and_old_model_call_shape(tmp_path, monkeypatch):
    paths = inputs(tmp_path)
    actual = core.ComparisonProject

    def model(*, name, artifacts):
        return actual(name=name, artifacts=artifacts)

    monkeypatch.setattr(core, 'ComparisonProject', model)
    found = []
    for name in ('first', 'second'):
        with ProjectService.create(*paths, name, tmp_path / name) as service:
            found.append(service.project.id)
            assert str(UUID(service.project.id)) == service.project.id
    assert found[0] != found[1]


@pytest.mark.parametrize('identity', ['same', 'different'])
def test_preallocation_never_authorizes_reusing_a_committed_project(tmp_path, identity):
    paths = inputs(tmp_path)
    root = tmp_path / 'foreign'
    with ProjectService.create(*paths, 'existing', root) as service:
        existing_id = service.project.id
    foreign = root / 'analyst.txt'
    foreign.write_bytes(b'keep this existing record')
    before = owned_bytes(root)
    with pytest.raises(ValueError, match='project database already exists'):
        ProjectService.create(*paths, 'must refuse', root,
                              project_id=existing_id if identity == 'same' else EXPECTED_ID)
    assert owned_bytes(root) == before
    assert foreign.read_bytes() == b'keep this existing record'


@pytest.mark.parametrize('database', ['new', 'zero-byte', 'empty-current'])
def test_preallocated_first_save_cancel_and_healthy_retry_preserve_owned_boundaries(tmp_path, monkeypatch, database):
    with authored_pair(tmp_path) as (paths, readers):
        root = tmp_path / 'project'
        root.mkdir()
        database_path = root / 'project.sqlite3'
        if database == 'zero-byte':
            database_path.write_bytes(b'')
        elif database == 'empty-current':
            with ProjectStore(root, create=True):
                pass
        before = database_path.read_bytes() if database_path.exists() else None
        foreign = root / 'keep.txt'
        foreign.write_text('preexisting')
        actual_init = ProjectStore.__init__
        stores, statements = [], []

        def initialize(store, *args, **kwargs):
            actual_init(store, *args, **kwargs)
            stores.append(store)
            store.connection.set_trace_callback(statements.append)

        monkeypatch.setattr(ProjectStore, '__init__', initialize)
        primary = InputReadError('cancelled')

        def stop(count, kind):
            if stores and stores[0].connection.in_transaction and any(
                    sql.startswith('INSERT INTO current_snapshot') for sql in statements):
                raise primary
            return False

        readers.checkpoint.stop = stop
        with pytest.raises(InputReadError) as caught:
            ProjectService.create(*paths, 'cancel before commit', root,
                                  input_readers=readers, project_id=EXPECTED_ID)
        assert caught.value is primary
        assert 'ROLLBACK' in statements and 'COMMIT' not in statements
        assert foreign.read_text() == 'preexisting' and not list(root.rglob('*.bin'))
        assert (database_path.read_bytes() if database_path.exists() else None) == before
        readers.checkpoint.stop = lambda count, kind: False
        with ProjectService.create(*paths, 'healthy retry', root,
                                   input_readers=readers, project_id=EXPECTED_ID) as service:
            assert service.project.id == EXPECTED_ID


@pytest.mark.parametrize('phase', ['save-return', 'constructor'])
def test_unknown_after_commit_result_preserves_expected_identity_and_files(tmp_path, monkeypatch, phase):
    paths = inputs(tmp_path)
    root = tmp_path / 'project'
    expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
    actual_save = ProjectStore.save
    committed = []
    primary = InputReadError('limited')

    def save(store, project, **kwargs):
        result = actual_save(store, project, **kwargs)
        assert not store.connection.in_transaction
        committed.append(result.id)
        if phase == 'save-return':
            raise primary
        return result

    class FailingService(ProjectService):
        def __init__(self, *args, **kwargs):
            raise primary

    monkeypatch.setattr(ProjectStore, 'save', save)
    service_type = FailingService if phase == 'constructor' else ProjectService
    with pytest.raises(InputReadError) as caught:
        service_type.create(*paths, 'retained', root, project_id=EXPECTED_ID)
    assert caught.value is primary and committed == [EXPECTED_ID]
    for path in paths:
        path.unlink()
    with ProjectStore(root) as store:
        actual = store.load(recover_interrupted=False)
        assert actual.id == EXPECTED_ID
        assert [artifact.sha256 for artifact in actual.artifacts] == expected
