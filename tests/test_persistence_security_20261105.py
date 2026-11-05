"""Authored local filesystem controls for project lock identity; no native engine evidence."""
from __future__ import annotations

import os

import pytest

from patchtrace import persistence
from patchtrace.persistence import ProjectLock, ProjectStore


def test_lock_refuses_hardlinked_foreign_file_without_writing(tmp_path):
    root = tmp_path / 'case'
    root.mkdir()
    foreign = tmp_path / 'foreign.txt'
    expected = b'Unrelated analyst data must survive opening a project.'
    foreign.write_bytes(expected)
    try:
        os.link(foreign, root / '.patchtrace.lock')
    except (OSError, NotImplementedError):
        pytest.skip('this filesystem cannot create hardlinks')
    lock = None
    try:
        with pytest.raises(ValueError, match='PT-STORAGE'):
            lock = ProjectLock(root)
    finally:
        if lock is not None:
            lock.close()
    assert foreign.read_bytes() == expected
    assert (root / '.patchtrace.lock').read_bytes() == expected
    assert not (root / 'project.sqlite3').exists()


def test_lock_refuses_path_substitution_after_open_without_writing(tmp_path, monkeypatch):
    root = tmp_path / 'case'
    root.mkdir()
    lock_path = root / '.patchtrace.lock'
    original = b'original persistent lock bytes'
    replacement = b'replacement persistent lock bytes'
    lock_path.write_bytes(original)
    displaced = root / 'displaced.lock'
    real_open = persistence.os.open

    def substitute(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if path == lock_path:
            try:
                lock_path.rename(displaced)
            except OSError:
                os.close(descriptor)
                pytest.skip('this filesystem refuses renaming an opened lock')
            lock_path.write_bytes(replacement)
        return descriptor

    monkeypatch.setattr(persistence.os, 'open', substitute)
    lock = None
    try:
        with pytest.raises(ValueError, match='PT-STORAGE'):
            lock = ProjectLock(root)
    finally:
        if lock is not None:
            lock.close()
    assert displaced.read_bytes() == original
    assert lock_path.read_bytes() == replacement
    # Refusal must release the old handle; the surviving path is independently lockable.
    monkeypatch.setattr(persistence.os, 'open', real_open)
    with ProjectStore(root, create=True):
        pass


def test_persistent_regular_lock_reuses_inode_and_excludes_second_writer(tmp_path):
    first = ProjectLock(tmp_path)
    path = tmp_path / '.patchtrace.lock'
    inode = path.stat().st_ino
    try:
        with pytest.raises(ValueError, match='PT-STORAGE'):
            ProjectLock(tmp_path)
    finally:
        first.close()
    second = ProjectLock(tmp_path)
    try:
        assert path.stat().st_ino == inode
    finally:
        second.close()


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='named pipes need POSIX')
def test_lock_refuses_nonregular_file_before_fdopen(tmp_path, monkeypatch):
    os.mkfifo(tmp_path / '.patchtrace.lock')

    def forbidden(*args, **kwargs):
        pytest.fail('nonregular lock reached buffered IO')

    monkeypatch.setattr(persistence.os, 'fdopen', forbidden)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectLock(tmp_path)


def test_lock_identity_refusal_closes_raw_descriptor_without_writing(tmp_path, monkeypatch):
    """Portable refusal control, including platforms without symlink/hardlink fixture support."""
    path = tmp_path / '.patchtrace.lock'
    expected = b'preserve original lock bytes'
    path.write_bytes(expected)
    opened = []
    real_open = persistence.os.open

    def record_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(persistence.os, 'open', record_open)
    monkeypatch.setattr(persistence.os.path, 'samestat', lambda *args: False)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectLock(tmp_path)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert path.read_bytes() == expected


@pytest.mark.skipif(os.name == 'nt', reason='uses POSIX flock interception')
def test_lock_rechecks_link_count_after_kernel_acquisition(tmp_path, monkeypatch):
    import fcntl

    path = tmp_path / '.patchtrace.lock'
    foreign = tmp_path / 'foreign-link'
    expected = b'ownership metadata must not be written after a new alias appears'
    path.write_bytes(expected)
    real_flock = fcntl.flock

    def add_alias(descriptor, operation):
        result = real_flock(descriptor, operation)
        if operation & fcntl.LOCK_EX:
            try:
                os.link(path, foreign)
            except (OSError, NotImplementedError):
                pytest.skip('this filesystem cannot create hardlinks')
        return result

    monkeypatch.setattr(fcntl, 'flock', add_alias)
    with pytest.raises(ValueError, match='PT-STORAGE'):
        ProjectLock(tmp_path)
    assert foreign.read_bytes() == expected
    assert path.read_bytes() == expected
    foreign.unlink()
    monkeypatch.setattr(fcntl, 'flock', real_flock)
    lock = ProjectLock(tmp_path)
    lock.close()
