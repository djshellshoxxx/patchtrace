"""Recovery must retain exact damaged evidence before replacing series.json."""
import hashlib

import pytest
from test_nway_series import builds, create  # noqa: F401

from patchtrace.nway import series as store


@pytest.mark.parametrize('existing', ['different', 'directory', 'symlink'])
def test_recovery_collision_preserves_damaged_series(builds, tmp_path, capsys, existing):  # noqa: F811
    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series = store.load(path)
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    if existing == 'directory':
        backup.mkdir()
    elif existing == 'symlink':
        target = tmp_path / 'target'
        target.write_bytes(damaged)
        try:
            backup.symlink_to(target)
        except OSError:
            pytest.skip('symlinks unavailable')
    else:
        backup.write_bytes(b'x' * len(damaged))
    with pytest.raises(store.NwayError, match='PT-NWAY-STORAGE'):
        store.save(series, path, replace_corrupt=True)
    assert path.read_bytes() == damaged
    if existing == 'different':
        assert backup.read_bytes() == b'x' * len(damaged)
    elif existing == 'directory':
        assert backup.is_dir()
    else:
        assert backup.is_symlink() and target.read_bytes() == damaged
    assert not list(root.glob('.series-*'))


def test_exact_recovery_copy_is_reused_without_replacement(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series, good = store.load(path), path.read_bytes()
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    backup.write_bytes(damaged)
    before = backup.stat()
    store.save(series, path, replace_corrupt=True)
    assert path.read_bytes() == good
    assert backup.read_bytes() == damaged
    assert backup.stat().st_ino == before.st_ino
    assert backup.stat().st_mtime_ns == before.st_mtime_ns
    assert store.load(path) == series


def test_oversized_recovery_never_uses_read_bytes(builds, tmp_path, capsys, monkeypatch):  # noqa: F811
    from pathlib import Path

    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series, good = store.load(path), path.read_bytes()
    damaged = b'x' * (3 * 1024 * 1024 + 7)
    path.write_bytes(damaged)
    monkeypatch.setattr(store, 'MAX_SERIES_BYTES', len(good) + 1)
    original_read = Path.read_bytes

    def bounded_only(self):
        if self == path:
            raise AssertionError('damaged original must be streamed')
        return original_read(self)

    monkeypatch.setattr(Path, 'read_bytes', bounded_only)
    store.save(series, path, replace_corrupt=True)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    assert backup.read_bytes() == damaged
    assert original_read(path) == good


@pytest.mark.parametrize('prior_copy', [False, True])
@pytest.mark.parametrize('failure', ['read', 'changed'])
def test_stream_failure_preserves_original_and_prior_copy(tmp_path, monkeypatch, prior_copy, failure):
    path = tmp_path / 'series.json'
    damaged = b'x' * (1024 * 1024 + 17)
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    if prior_copy:
        backup.write_bytes(damaged)
    original_open = store._open_recovery_file
    calls = []

    class GuardedSource:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def fileno(self):
            return self.stream.fileno()

        def seek(self, position):
            if failure == 'changed':
                path.write_bytes(b'y' * len(damaged))
            return self.stream.seek(position)

        def read(self, size=-1):
            assert 0 < size <= 1024 * 1024
            calls.append(size)
            if failure == 'read' and len(calls) == 5:
                raise OSError('authored second-pass read failure')
            return self.stream.read(size)

    def guarded_open(candidate):
        opened = original_open(candidate)
        return GuardedSource(opened) if candidate == path else opened

    monkeypatch.setattr(store, '_open_recovery_file', guarded_open)
    with pytest.raises(store.NwayError, match='PT-NWAY-STORAGE'):
        store._keep_corrupt_copy(path)
    assert path.read_bytes() == (damaged if failure == 'read' else b'y' * len(damaged))
    if prior_copy:
        assert backup.read_bytes() == damaged
    else:
        assert not backup.exists()
    assert calls and max(calls) <= 1024 * 1024


def test_replaced_new_copy_prevents_series_replacement(builds, tmp_path, capsys, monkeypatch):  # noqa: F811
    root = tmp_path / 'series'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    series = store.load(path)
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    backup = path.with_name(path.name + '.corrupt-' + hashlib.sha256(damaged).hexdigest()[:8])
    foreign = root / 'foreign'
    foreign.write_bytes(b'unrelated evidence')
    fsync = store.os.fsync

    def replace_on_sync(fd):
        fsync(fd)
        try:
            store.os.replace(foreign, backup)
        except PermissionError:
            pytest.skip('platform denies replacing the open recovery file')

    monkeypatch.setattr(store.os, 'fsync', replace_on_sync)
    with pytest.raises(store.NwayError, match='PT-NWAY-STORAGE'):
        store.save(series, path, replace_corrupt=True)
    assert path.read_bytes() == damaged
    assert backup.read_bytes() == b'unrelated evidence'
    assert not list(root.glob('.series-*'))


@pytest.mark.parametrize('failing_call', ['fstat', 'fdopen'])
def test_new_copy_descriptor_closed_on_setup_failure(tmp_path, monkeypatch, failing_call):
    path = tmp_path / 'series.json'
    damaged = b'{ damaged evidence'
    path.write_bytes(damaged)
    created = []
    original_open, original_stat, original_fdopen = store.os.open, store.os.fstat, store.os.fdopen

    def capture_open(candidate, flags, *args):
        fd = original_open(candidate, flags, *args)
        if flags & store.os.O_CREAT:
            created.append(fd)
        return fd

    def fail(fd, *args, **kwargs):
        if fd in created:
            raise OSError('authored descriptor setup failure')
        original = original_stat if failing_call == 'fstat' else original_fdopen
        return original(fd, *args, **kwargs)

    monkeypatch.setattr(store.os, 'open', capture_open)
    monkeypatch.setattr(store.os, failing_call, fail)
    with pytest.raises(store.NwayError, match='PT-NWAY-STORAGE'):
        store._keep_corrupt_copy(path)
    assert len(created) == 1
    with pytest.raises(OSError):
        original_stat(created[0])  # descriptor is closed even before its identity could be recorded
    assert path.read_bytes() == damaged
