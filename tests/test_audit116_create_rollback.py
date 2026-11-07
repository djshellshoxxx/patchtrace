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
    assert leftovers == ['.patchtrace.lock'], f'failed creation stranded {leftovers}'
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
    assert sorted(p.relative_to(root).as_posix() for p in root.rglob('*')) == ['.patchtrace.lock', 'keep', 'keep/note.txt', 'readme.txt']


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
    assert not root.exists() or sorted(p.name for p in root.rglob('*')) == ['.patchtrace.lock']


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
    assert sorted(p.name for p in root.iterdir()) == ['.patchtrace.lock', 'kept.txt']
    assert not kept.stat().st_mode & stat.S_IWRITE
    kept.chmod(stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.parametrize('failure', [ValueError, KeyboardInterrupt])
def test_failure_preserves_foreign_files_created_during_attempt(tmp_path, monkeypatch, failure):
    from patchtrace import service as module

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    actual = module.inspect_artifact

    def inspect(path, side, directory, **kwargs):
        if side == 'newer':
            (root / 'foreign.txt').write_text('concurrent analyst file')
            (root / 'artifacts' / 'foreign.bin').write_bytes(b'foreign')
            raise failure('synthetic interruption')
        return actual(path, side, directory, **kwargs)

    monkeypatch.setattr(module, 'inspect_artifact', inspect)
    with pytest.raises(failure):
        ProjectService.create(older, older, 'x', root)
    assert (root / 'foreign.txt').read_text() == 'concurrent analyst file'
    assert (root / 'artifacts' / 'foreign.bin').read_bytes() == b'foreign'
    assert sorted(p.name for p in (root / 'artifacts').iterdir()) == ['foreign.bin']
    assert not (root / 'project.sqlite3').exists()


def test_reused_readonly_artifact_is_not_claimed_or_removed(tmp_path):
    from patchtrace.ingestion import inspect_artifact

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    record = inspect_artifact(older, 'older', root)
    retained = root / record.relative_path
    mode = retained.stat().st_mode
    bad = tmp_path / 'bad.exe'
    bad.write_bytes(b'bad')
    with pytest.raises(ValueError):
        ProjectService.create(older, bad, 'x', root)
    assert retained.read_bytes() == older.read_bytes()
    assert retained.stat().st_mode == mode


def test_failure_after_artifact_publication_cleans_recorded_copy(tmp_path, monkeypatch):
    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    actual = Path.chmod

    def chmod(path, *args, **kwargs):
        if path.suffix == '.bin':
            raise OSError('synthetic immutable publication failure')
        return actual(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'chmod', chmod)
    with pytest.raises(ValueError, match='cannot read or preserve'):
        ProjectService.create(older, older, 'x', root)
    assert sorted(p.name for p in root.rglob('*')) == ['.patchtrace.lock']


def test_committed_first_snapshot_survives_exception_after_save(tmp_path, monkeypatch):
    from patchtrace.persistence import ProjectStore

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    actual = ProjectStore.save

    def save(store, project):
        actual(store, project)
        raise RuntimeError('synthetic failure after commit')

    monkeypatch.setattr(ProjectStore, 'save', save)
    with pytest.raises(RuntimeError, match='after commit'):
        ProjectService.create(older, older, 'committed', root)
    reopened = ProjectService.open(root)
    try:
        assert reopened.project.name == 'committed'
    finally:
        reopened.close()


def test_concurrent_destination_is_never_overwritten_or_claimed(tmp_path, monkeypatch):
    import os

    from patchtrace.ingestion import inspect_artifact

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    actual = os.link
    retained = []

    def link(source, destination, *args, **kwargs):
        Path(destination).write_bytes(b'concurrent foreign destination')
        retained.append(Path(destination))
        return actual(source, destination, *args, **kwargs)

    monkeypatch.setattr(os, 'link', link)
    ledger = []
    with pytest.raises(ValueError, match='existing immutable artifact has changed'):
        inspect_artifact(older, 'older', root, created=ledger)
    assert retained[0].read_bytes() == b'concurrent foreign destination'
    assert retained[0] not in [path for path, _ in ledger]


@pytest.mark.parametrize('replacement', ['regular', 'symlink'])
def test_replaced_owned_artifact_is_retained(tmp_path, monkeypatch, replacement):
    from patchtrace import service as module

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    actual = module.inspect_artifact
    foreign = tmp_path / 'foreign.bin'
    foreign.write_bytes(b'foreign target')
    recorded = []

    def inspect(path, side, directory, **kwargs):
        if side == 'newer':
            owned = recorded[0]
            owned.chmod(0o600)
            owned.unlink()
            if replacement == 'symlink':
                try:
                    owned.symlink_to(foreign)
                except OSError:
                    pytest.skip('symlinks unavailable on this host')
            else:
                owned.write_bytes(b'concurrent replacement')
            raise ValueError('synthetic failure after foreign replacement')
        result = actual(path, side, directory, **kwargs)
        recorded.append(directory / result.relative_path)
        return result

    monkeypatch.setattr(module, 'inspect_artifact', inspect)
    with pytest.raises(ValueError, match='foreign replacement'):
        ProjectService.create(older, older, 'x', root)
    assert recorded[0].exists()
    assert foreign.read_bytes() == b'foreign target'
    if replacement == 'regular':
        assert recorded[0].read_bytes() == b'concurrent replacement'
    else:
        assert recorded[0].is_symlink()


def test_unsupported_exclusive_publication_retains_existing_data(tmp_path, monkeypatch):
    import errno
    import os

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    root = tmp_path / 'case'
    root.mkdir()
    retained = root / 'notes.txt'
    retained.write_bytes(b'analyst notes')

    def unsupported(*args, **kwargs):
        raise OSError(errno.EOPNOTSUPP, 'hardlink publication unavailable')

    monkeypatch.setattr(os, 'link', unsupported)
    with pytest.raises(ValueError, match='cannot read or preserve input'):
        ProjectService.create(older, older, 'x', root)
    assert retained.read_bytes() == b'analyst notes'
    assert sorted(p.name for p in root.rglob('*')) == ['.patchtrace.lock', 'notes.txt']


def test_cleanup_retains_lock_until_owned_files_are_removed(tmp_path, monkeypatch):
    from patchtrace import service as module
    from patchtrace.persistence import ProjectStore

    older = tmp_path / 'older.exe'
    older.write_bytes(build_pe())
    bad = tmp_path / 'bad.exe'
    bad.write_bytes(b'bad')
    root = tmp_path / 'case'
    actual = module._remove_owned
    checked = []

    def remove(path, recorded, **kwargs):
        with pytest.raises(ValueError, match='locked by another writer'):
            ProjectStore(root, create=True)
        checked.append(path)
        return actual(path, recorded, **kwargs)

    monkeypatch.setattr(module, '_remove_owned', remove)
    with pytest.raises(ValueError, match='missing DOS|PE input size'):
        ProjectService.create(older, bad, 'x', root)
    assert checked
    with ProjectService.create(older, older, 'retry', root):
        pass
