"""PIL stage creation owns cleanup only after mkdir succeeds; authored bytes only."""
from __future__ import annotations

from pathlib import Path

import pytest
from test_pilot_store import make

from patchtrace.pilot import keys, store
from patchtrace.service import ProjectService

TOKEN = '0123456789abcdef'


@pytest.fixture
def staging(tmp_path, monkeypatch):
    with ProjectService.sample(tmp_path / 'project') as service:
        assessment, config = make(service)
        monkeypatch.setattr(store.secrets, 'token_hex', lambda _size: TOKEN)
        target = service.root / keys.RELATIVE_ROOT / f'tmp-{TOKEN}'
        yield service, assessment, config, target


def contents(directory):
    return {p.relative_to(directory).as_posix(): p.read_bytes()
            for p in directory.rglob('*') if p.is_file()}


def test_occupied_directory_and_children_survive_failed_creation(staging):
    service, assessment, config, target = staging
    child = target / 'retained' / 'evidence.json'
    child.parent.mkdir(parents=True)
    child.write_bytes(b'{"owner":"an earlier authored operation"}\n')
    before = contents(target)
    with pytest.raises(FileExistsError):
        store.stage(service.root, assessment, config)
    assert target.is_dir() and contents(target) == before


def test_an_earlier_successful_stage_survives_a_later_name_collision(staging):
    service, assessment, config, target = staging
    first = store.stage(service.root, assessment, config)
    assert first == target
    before = contents(first)
    with pytest.raises(FileExistsError):
        store.stage(service.root, assessment, config)
    assert first.is_dir() and contents(first) == before
    assert store.read_sidecar(first)[1] == assessment


def test_a_competing_creator_before_mkdir_keeps_its_directory(staging, monkeypatch):
    service, assessment, config, target = staging
    target.parent.mkdir(parents=True)
    real_mkdir = Path.mkdir
    marker = target / 'competing-operation.json'
    def another_creator(path, *args, **kwargs):
        if path == target:
            real_mkdir(path, *args, **kwargs)
            marker.write_bytes(b'competing authored evidence')
            raise FileExistsError('authored competing creation')
        return real_mkdir(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'mkdir', another_creator)
    with pytest.raises(FileExistsError, match='competing creation'):
        store.stage(service.root, assessment, config)
    assert target.is_dir() and marker.read_bytes() == b'competing authored evidence'


def test_an_occupied_regular_file_survives_failed_creation(staging):
    service, assessment, config, target = staging
    target.parent.mkdir(parents=True)
    target.write_bytes(b'authored occupied filename')
    with pytest.raises(FileExistsError):
        store.stage(service.root, assessment, config)
    assert target.read_bytes() == b'authored occupied filename'


@pytest.mark.parametrize('error', [OSError, KeyboardInterrupt, SystemExit], ids=['write-error', 'interrupt', 'exit'])
@pytest.mark.parametrize('write_number', [1, 2], ids=['assessment', 'manifest'])
def test_write_failure_or_interruption_cleans_only_the_new_stage(staging, monkeypatch, error, write_number):
    service, assessment, config, target = staging
    sibling = target.parent / 'earlier-operation'
    sibling.mkdir(parents=True)
    marker = sibling / 'evidence.json'
    marker.write_bytes(b'authored sibling evidence')
    calls = []
    failure = error('authored stage write interruption')
    real_write = store._write
    def interrupted_write(path, data):
        real_write(path, data)
        calls.append(path.name)
        if len(calls) == write_number:
            raise failure
    monkeypatch.setattr(store, '_write', interrupted_write)
    with pytest.raises(error) as caught:
        store.stage(service.root, assessment, config)
    assert caught.value is failure and len(calls) == write_number
    assert not target.exists()
    assert marker.read_bytes() == b'authored sibling evidence'


def test_successful_stage_returns_verified_files_for_its_caller(staging):
    service, assessment, config, target = staging
    staged = store.stage(service.root, assessment, config)
    manifest, reopened = store.read_sidecar(staged)
    assert staged == target and reopened == assessment
    assert manifest.result_id == assessment.result_id
    assert set(contents(staged)) == {keys.ASSESSMENT_NAME, keys.MANIFEST_NAME}
