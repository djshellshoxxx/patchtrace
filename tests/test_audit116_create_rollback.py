"""Audit #116 P2: a failed project creation must leave nothing that blocks a retry."""
from pathlib import Path

import pytest

from patchtrace.service import ProjectService
from tests.pe_builder import build_pe


def test_failed_create_leaves_no_owned_files_and_retry_works(tmp_path):
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'newer.exe'
    bad.write_bytes(b'MZ not a pe')
    root = tmp_path / 'case'
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(older, bad, 'x', root)
    leftovers = sorted(p.name for p in Path(root).rglob('*')) if root.exists() else []
    assert leftovers == [], f'failed creation stranded {leftovers}'
    bad.write_bytes(build_pe())
    service = ProjectService.create(older, bad, 'x', root)
    service.store.close()


def test_failed_create_keeps_files_that_were_already_in_the_folder(tmp_path):
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'newer.exe'
    bad.write_bytes(b'MZ not a pe')
    root = tmp_path / 'case'
    (root / 'keep').mkdir(parents=True)
    (root / 'keep' / 'note.txt').write_text('analyst file', encoding='utf-8')
    (root / 'readme.txt').write_text('mine', encoding='utf-8')
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(older, bad, 'x', root)
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob('*')) == ['keep', 'keep/note.txt', 'readme.txt']


def _windows_delete_rules(monkeypatch):
    """Emulate Windows on any OS: deleting a file whose write bit is clear fails with PermissionError.
    Immutable artifact copies are made read-only (ingestion.inspect_artifact), which is what left
    artifacts/<sha>.bin behind on the Windows CI leg."""
    import os
    import stat

    real_unlink = os.unlink

    def unlink(path, *, dir_fd=None):
        mode = os.stat(path, dir_fd=dir_fd, follow_symlinks=False).st_mode
        if stat.S_ISREG(mode) and not mode & stat.S_IWRITE:
            raise PermissionError(13, 'Access is denied (read-only file, emulated)', str(path))
        return real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, 'unlink', unlink)
    monkeypatch.setattr(os, 'remove', unlink)


def test_failed_create_removes_its_read_only_artifact_copies_under_windows_rules(tmp_path, monkeypatch):
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'newer.exe'
    bad.write_bytes(b'MZ not a pe')
    root = tmp_path / 'case'
    _windows_delete_rules(monkeypatch)
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(older, bad, 'x', root)
    assert not root.exists() or sorted(p.name for p in root.rglob('*')) == []


def test_a_read_only_file_already_in_the_folder_is_left_read_only(tmp_path, monkeypatch):
    import stat
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'newer.exe'
    bad.write_bytes(b'MZ not a pe')
    root = tmp_path / 'case'
    root.mkdir()
    kept = root / 'kept.txt'
    kept.write_text('analyst file', encoding='utf-8')
    kept.chmod(stat.S_IREAD)
    _windows_delete_rules(monkeypatch)
    with pytest.raises((ValueError, OSError)):
        ProjectService.create(older, bad, 'x', root)
    assert sorted(p.name for p in root.iterdir()) == ['kept.txt']
    assert not kept.stat().st_mode & stat.S_IWRITE
    kept.chmod(stat.S_IREAD | stat.S_IWRITE)
