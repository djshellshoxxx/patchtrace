"""Owned input cleanup preserves the operation failure and reports retained bytes."""
from __future__ import annotations

from pathlib import Path

import pytest
from held_input_support import authored_pair

from patchtrace import ingestion
from patchtrace.input_readers import InputReadError
from patchtrace.sample import synthetic_pe


def refuse_stage_cleanup(monkeypatch, root):
    original = Path.unlink
    attempts = []

    def unlink(path, *args, **kwargs):
        if path.parent == root / 'artifacts' and path.name.startswith('.input-'):
            attempts.append(path)
            raise PermissionError('secondary-secret-native-path')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'unlink', unlink)
    return attempts


@pytest.mark.parametrize('kind', ['cancelled', 'limited', 'ordinary', 'interrupt'])
def test_primary_failure_survives_failed_owned_stage_cleanup(tmp_path, monkeypatch, kind):
    errors = {'cancelled': InputReadError('cancelled'), 'limited': InputReadError('limited'),
              'ordinary': ValueError('authored validation failure'),
              'interrupt': KeyboardInterrupt('authored interrupt')}
    error = errors[kind]
    with authored_pair(tmp_path) as (paths, readers):
        root = tmp_path / 'project'
        (root / 'artifacts').mkdir(parents=True)
        foreign = root / 'artifacts' / 'analyst-note.txt'
        foreign.write_bytes(b'foreign evidence')
        attempts = refuse_stage_cleanup(monkeypatch, root)

        def stop():
            raise error

        readers.older.on_read = stop
        with pytest.raises(type(error)) as caught:
            ingestion.inspect_artifact(paths[0], 'older', root, reader=readers.older)
        assert caught.value is error
        assert attempts and all(path.exists() for path in attempts)
        assert not readers.older.active and readers.older.opened == readers.older.closed
        assert foreign.read_bytes() == b'foreign evidence' and not list(root.rglob('*.bin'))
        notes = getattr(error, '__notes__', ())
        assert len(notes) == 1 and len(notes[0]) <= 160
        assert 'cleanup' in notes[0] and 'may remain' in notes[0]
        assert 'secondary-secret' not in notes[0] and str(tmp_path) not in notes[0]


def test_plain_malformed_pe_keeps_its_validation_error_when_cleanup_fails(tmp_path, monkeypatch):
    path = tmp_path / 'invalid.sys'
    path.write_bytes(b'NO' + synthetic_pe(0)[2:])
    root = tmp_path / 'project'
    attempts = refuse_stage_cleanup(monkeypatch, root)
    with pytest.raises(ValueError, match='PT-INPUT: missing DOS MZ header') as caught:
        ingestion.inspect_artifact(path, 'older', root)
    assert attempts and all(stage.exists() for stage in attempts)
    assert not list(root.rglob('*.bin'))
    assert any('may remain' in note for note in caught.value.__notes__)


def test_cleanup_failure_after_valid_copy_never_returns_an_artifact(tmp_path, monkeypatch):
    path = tmp_path / 'valid.sys'
    path.write_bytes(synthetic_pe(0))
    root = tmp_path / 'project'
    attempts = refuse_stage_cleanup(monkeypatch, root)
    created = []
    with pytest.raises((ValueError, OSError)):
        ingestion.inspect_artifact(path, 'older', root, created=created)
    assert attempts and all(stage.exists() for stage in attempts)
    # The exclusive publication remains owned by the existing caller's rollback
    # ledger, even though unlink failed before inspect could return an Artifact.
    assert any(p.suffix == '.bin' and p.exists() for p, _state in created)


def test_successful_cleanup_preserves_primary_error_without_false_retention_note(tmp_path):
    with authored_pair(tmp_path) as (paths, readers):
        error = InputReadError('cancelled')

        def stop():
            raise error

        readers.older.on_read = stop
        root = tmp_path / 'project'
        with pytest.raises(InputReadError) as caught:
            ingestion.inspect_artifact(paths[0], 'older', root, reader=readers.older)
        assert caught.value is error and not getattr(error, '__notes__', ())
        assert not list(root.rglob('.input-*')) and not list(root.rglob('*.bin'))
