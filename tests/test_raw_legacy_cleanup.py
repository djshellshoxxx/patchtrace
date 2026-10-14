"""SPEC-07h H8 (Phase D amendment): legacy duplicate raw output is removed on open, journalled, reversible.

Synthetic projects (`synthetic_pe` + `sample_diff`); the legacy layout is reproduced by importing a JSON
file (which stores the copy at runs/<id>/raw/result.ghidriff.json) and placing the backend's original
next to it, as projects written before the single-copy change hold it.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from patchtrace import raw_cleanup
from patchtrace.sample import sample_diff, synthetic_pe
from patchtrace.service import ProjectService


@pytest.fixture
def legacy(tmp_path):
    """(root, run_id, duplicate path, kept path) of a closed project holding two identical raw copies."""
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    svc = ProjectService.create(older, newer, 'Comparison', tmp_path / 'project')
    outside = tmp_path / 'outside.ghidriff.json'
    outside.write_text(json.dumps(sample_diff(svc.project)), encoding='utf-8')
    svc.import_diff(outside)
    run = svc.project.runs[-1]
    root = svc.root
    svc.close()
    kept = root / run.raw_path
    assert run.raw_path == f'runs/{run.id}/raw/result.ghidriff.json'
    duplicate = root / 'runs' / run.id / 'raw' / 'json' / 'o.dll-n.dll.ghidriff.json'
    duplicate.parent.mkdir(parents=True)
    duplicate.write_bytes(kept.read_bytes())
    return root, run.id, duplicate, kept


def _journal(root):
    path = root / 'backups' / 'raw-duplicates.jsonl'
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []


def test_open_removes_identical_legacy_copy(legacy):
    root, run_id, duplicate, kept = legacy
    digest = hashlib.sha256(kept.read_bytes()).hexdigest()
    with ProjectService.open(root) as svc:
        assert svc.project.runs[-1].raw_path == kept.relative_to(root).as_posix()
    assert not duplicate.exists() and kept.is_file()
    entries = _journal(root)
    assert len(entries) == 1
    entry = entries[0]
    assert entry['v'] == 1 and entry['run_id'] == run_id and entry['sha256'] == digest
    assert entry['removed'] == duplicate.relative_to(root).as_posix() and entry['kept'] == f'runs/{run_id}/raw/result.ghidriff.json'
    with ProjectService.open(root):  # idempotent: nothing left to do, nothing journalled twice
        pass
    assert len(_journal(root)) == 1


def test_restore_recreates_removed_copy(legacy):
    root, _run_id, duplicate, kept = legacy
    original = duplicate.read_bytes()
    ProjectService.open(root).close()
    assert raw_cleanup.restore_raw_duplicates(root) == 1
    assert duplicate.read_bytes() == original == kept.read_bytes()
    assert raw_cleanup.restore_raw_duplicates(root) == 0


@pytest.mark.parametrize('variant', ['other-bytes-same-size', 'other-size'])
def test_differing_copy_is_kept(legacy, variant, caplog):
    root, _run_id, duplicate, _kept = legacy
    data = bytearray(duplicate.read_bytes())
    if variant == 'other-size':
        data += b' '
    else:
        data[-2:] = b'  ' if data[-2:] != b'  ' else b'\n\n'
    duplicate.write_bytes(bytes(data))
    with caplog.at_level('WARNING'):
        ProjectService.open(root).close()
    assert duplicate.read_bytes() == bytes(data) and _journal(root) == []
    assert 'kept' in caplog.text.lower()


def test_unrelated_files_untouched(legacy):
    root, run_id, duplicate, _kept = legacy
    keep = [duplicate.with_name('o.dll-n.dll.ghidriff.md'), duplicate.parent.parent / 'analysis.log',
            root / 'runs' / 'quarantine-x' / 'raw' / 'json' / 'a.ghidriff.json',
            root / 'runs' / 'not-in-snapshot' / 'raw' / 'json' / 'a.ghidriff.json',
            root / 'runs' / 'not-in-snapshot' / 'raw' / 'result.ghidriff.json']
    for path in keep:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(duplicate.read_bytes())
    artifacts = sorted(p for p in (root / 'artifacts').rglob('*') if p.is_file())
    before = {p: p.read_bytes() for p in artifacts}
    ProjectService.open(root).close()
    assert not duplicate.exists()
    assert all(p.is_file() for p in keep)
    assert {p: p.read_bytes() for p in artifacts} == before


def test_tampered_kept_copy_blocks_cleanup(legacy):
    root, _run_id, duplicate, kept = legacy
    os.chmod(kept, 0o644)
    kept.write_bytes(kept.read_bytes() + b' ')
    with pytest.raises(ValueError, match='raw output'):
        ProjectService.open(root)
    assert duplicate.is_file()


def test_read_only_open_does_not_clean(legacy):
    root, _run_id, duplicate, _kept = legacy
    ProjectService.open(root, maintenance=False).close()
    assert duplicate.is_file() and _journal(root) == []


def test_series_reader_does_not_clean(legacy):
    from patchtrace.nway.series import read_project
    root, _run_id, duplicate, _kept = legacy
    read_project(root)
    assert duplicate.is_file()


def test_backup_round_trip_after_cleanup(legacy, tmp_path):
    root, _run_id, duplicate, _kept = legacy
    with ProjectService.open(root) as svc:
        copy = svc.backup(tmp_path / 'copy')
    with ProjectService.open(copy) as restored:  # raw hash still verifies in the relocated copy
        assert restored.project.runs[-1].raw_sha256
    assert not duplicate.exists()


@pytest.mark.skipif(os.name == 'nt', reason='symlink creation needs privileges on Windows')
def test_symlinked_duplicate_is_not_followed(legacy):
    root, _run_id, duplicate, kept = legacy
    duplicate.unlink()
    duplicate.symlink_to(kept)
    ProjectService.open(root).close()
    assert duplicate.is_symlink() and kept.is_file() and _journal(root) == []


def test_read_only_duplicate_is_removed(legacy):
    root, _run_id, duplicate, _kept = legacy
    os.chmod(duplicate, 0o444)
    ProjectService.open(root).close()
    assert not duplicate.exists()


def test_cleanup_never_raises(tmp_path, legacy, monkeypatch):
    root, _run_id, duplicate, _kept = legacy

    def boom(*_a, **_k):
        raise OSError('disk on fire')
    monkeypatch.setattr(raw_cleanup, '_append_journal', boom)
    with ProjectService.open(root) as svc:  # the open succeeds; nothing removed without a journal line
        assert svc.project.runs
    assert duplicate.is_file()
