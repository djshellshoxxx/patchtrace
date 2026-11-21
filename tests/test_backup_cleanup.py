"""Backup failure and cancellation outcomes survive an independent staging-cleanup failure."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from patchtrace import cli, persistence, verified_backup
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def service(tmp_path):
    older, newer = tmp_path / 'older.bin', tmp_path / 'newer.bin'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    verified_backup.forget_all()
    with ProjectService.create(older, newer, 'Backup cleanup fixture', tmp_path / 'project') as current:
        yield current
    verified_backup.forget_all()


def _stages(directory):
    return list(directory.glob('.patchtrace-backup-*'))


@pytest.mark.parametrize('failure_type', (KeyboardInterrupt, SystemExit, OSError, ValueError))
def test_cleanup_denial_preserves_original_failure_and_retains_incomplete_copy(
        service, tmp_path, monkeypatch, failure_type):
    before = service.store.load(recover_interrupted=False)
    destination = tmp_path / 'backup'
    primary = failure_type('authored copy failure')
    primary.add_note('original diagnostic')
    attempted = []

    def fail_copy(*_args, **_kwargs):
        raise primary

    def refuse_cleanup(path, **_kwargs):
        attempted.append(path)
        raise PermissionError('authored cleanup denial with private detail')

    with monkeypatch.context() as patch:
        patch.setattr(persistence.shutil, 'copytree', fail_copy)
        patch.setattr(persistence.shutil, 'rmtree', refuse_cleanup)
        with pytest.raises(failure_type) as caught:
            service.backup(destination)
    assert caught.value is primary
    assert primary.__notes__ == [
        'original diagnostic',
        'PT-STORAGE: temporary backup cleanup failed; '
        'an incomplete staging directory may remain beside the destination',
    ]
    assert len(attempted) == 1 and _stages(tmp_path) == attempted
    assert (attempted[0] / 'project.sqlite3').is_file()
    assert not destination.exists()
    assert service.store.load(recover_interrupted=False) == before


def test_cleanup_check_denial_also_preserves_cancellation(service, tmp_path, monkeypatch):
    interruption = KeyboardInterrupt('authored cancellation')
    exists = Path.exists

    def fail_copy(*_args, **_kwargs):
        raise interruption

    def refuse_stage_check(path):
        if path.name.startswith('.patchtrace-backup-'):
            raise PermissionError('authored stage check denial')
        return exists(path)

    with monkeypatch.context() as patch:
        patch.setattr(persistence.shutil, 'copytree', fail_copy)
        patch.setattr(Path, 'exists', refuse_stage_check)
        with pytest.raises(KeyboardInterrupt) as caught:
            service.backup(tmp_path / 'backup')
    assert caught.value is interruption
    assert len(interruption.__notes__) == 1
    assert 'cleanup failed' in interruption.__notes__[0]
    assert len(_stages(tmp_path)) == 1
    assert not (tmp_path / 'backup').exists()


def test_cancellation_with_successful_cleanup_keeps_original_outcome(service, tmp_path, monkeypatch):
    before = service.store.load(recover_interrupted=False)
    interruption = KeyboardInterrupt('authored cancellation')

    def fail_copy(*_args, **_kwargs):
        raise interruption

    with monkeypatch.context() as patch:
        patch.setattr(persistence.shutil, 'copytree', fail_copy)
        with pytest.raises(KeyboardInterrupt) as caught:
            service.backup(tmp_path / 'backup')
    assert caught.value is interruption
    assert not getattr(interruption, '__notes__', [])
    assert _stages(tmp_path) == []
    assert not (tmp_path / 'backup').exists()
    assert service.store.load(recover_interrupted=False) == before


def test_cleanup_denial_does_not_replace_publication_refusal_or_remove_foreign_destination(
        service, tmp_path, monkeypatch):
    before = service.store.load(recover_interrupted=False)
    destination = tmp_path / 'backup'
    refusal = FileExistsError('authored independent final destination')

    def refuse_publication(_stage, path):
        path.mkdir()
        (path / 'keep.txt').write_text('independently created data')
        raise refusal

    def refuse_cleanup(*_args, **_kwargs):
        raise PermissionError('authored cleanup denial')

    with monkeypatch.context() as patch:
        patch.setattr(persistence, '_publish_no_replace', refuse_publication)
        patch.setattr(persistence.shutil, 'rmtree', refuse_cleanup)
        with pytest.raises(FileExistsError) as caught:
            service.backup(destination)
    assert caught.value is refusal
    assert (destination / 'keep.txt').read_text() == 'independently created data'
    assert {item.name for item in destination.iterdir()} == {'keep.txt'}
    assert len(_stages(tmp_path)) == 1
    assert service.store.load(recover_interrupted=False) == before


def test_success_does_not_clean_a_recreated_former_staging_path(service, tmp_path, monkeypatch):
    destination = tmp_path / 'backup'
    publish = persistence._publish_no_replace
    recreated = []

    def publish_then_recreate(stage, path):
        publish(stage, path)
        stage.mkdir()
        (stage / 'keep.txt').write_text('new owner after publication')
        recreated.append(stage)

    with monkeypatch.context() as patch:
        patch.setattr(persistence, '_publish_no_replace', publish_then_recreate)
        result = service.backup(destination)
    assert result == destination
    assert len(recreated) == 1
    assert (recreated[0] / 'keep.txt').read_text() == 'new owner after publication'
    with persistence.ProjectStore(destination) as copy:
        assert copy.load(recover_interrupted=False) == service.project


def test_cli_keeps_cancelled_exit_when_stage_cleanup_is_denied(service, tmp_path, monkeypatch, capsys):
    root = service.root
    before = service.project
    service.close()
    destination = tmp_path / 'backup'

    def fail_copy(*_args, **_kwargs):
        raise KeyboardInterrupt('authored copy cancellation')

    def refuse_cleanup(*_args, **_kwargs):
        raise PermissionError('authored cleanup denial')

    with monkeypatch.context() as patch:
        patch.setattr(persistence.shutil, 'copytree', fail_copy)
        patch.setattr(persistence.shutil, 'rmtree', refuse_cleanup)
        code = cli.main(['project', 'backup', str(root), '--out', str(destination), '--json'])
    out, err = capsys.readouterr()
    result = json.loads(out)
    assert code == 5 and result['status'] == 'cancelled'
    assert result['command'] == 'project backup' and result['result'] is None
    assert 'Traceback' not in err and 'cleanup denial' not in err
    assert not destination.exists()
    assert len(_stages(tmp_path)) == 1
    with ProjectService.open(root, maintenance=False) as reopened:
        assert reopened.project == before
