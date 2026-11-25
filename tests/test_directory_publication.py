"""Exclusive publication of complete project backups on Windows and Linux."""
from __future__ import annotations

import ctypes
import errno
import importlib
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace

import pytest

from patchtrace import persistence
from patchtrace.service import ProjectService


def api():
    return importlib.import_module('patchtrace.directory_publication')


def staged(tmp_path, name='stage-Δ'):
    stage = tmp_path / name
    stage.mkdir()
    (stage / 'nested').mkdir()
    (stage / 'nested' / 'payload.txt').write_bytes(b'complete authored payload')
    return stage


@pytest.fixture
def public_operation(tmp_path):
    service = ProjectService.sample(tmp_path / 'source')
    destination = tmp_path / 'backup-Δ'
    try:
        yield lambda: service.backup(destination), destination, service.root / 'project.sqlite3'
    finally:
        service.close()


def test_public_operations_never_reserve_the_destination(public_operation, monkeypatch):
    perform, destination, original = public_operation
    before = original.read_bytes()
    mkdir = os.mkdir

    def exclusive_stage_only(path, *args, **kwargs):
        assert Path(path) != destination, 'public destination was created before complete publication'
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(os, 'mkdir', exclusive_stage_only)
    perform()
    assert original.read_bytes() == before and destination.is_dir()
    assert any(destination.iterdir())


@pytest.mark.parametrize('native_failure', [False, True], ids=['collision', 'native-error'])
def test_public_late_foreign_directory_keeps_its_identity(public_operation, monkeypatch, native_failure):
    perform, destination, original = public_operation
    publisher = api()
    move = publisher._native_move
    before = original.read_bytes()
    held = []
    identity = []

    def late_owner(stage, final):
        assert final == destination and not os.path.lexists(final)
        final.mkdir()
        info = final.stat()
        identity.append((info.st_dev, info.st_ino))
        if os.name != 'nt':
            held.append(os.open(final, os.O_RDONLY | os.O_DIRECTORY))
        if native_failure:
            raise OSError(errno.EIO, 'authored native publication failure')
        return move(stage, final)

    monkeypatch.setattr(publisher, '_native_move', late_owner)
    try:
        with pytest.raises(OSError):
            perform()
        assert identity, 'the actual public operation did not reach native publication'
        info = destination.stat()
        assert (info.st_dev, info.st_ino) == identity[0] and not list(destination.iterdir())
        if held:
            assert os.fstat(held[0]).st_nlink > 0
        assert original.read_bytes() == before
        assert not list(destination.parent.glob('.patchtrace-backup-*'))
    finally:
        for fd in held:
            os.close(fd)


@pytest.mark.parametrize('kind', ['empty-directory', 'directory', 'file', 'dangling-link', 'directory-link'])
def test_existing_destination_entries_are_untouched(tmp_path, kind):
    stage = staged(tmp_path)
    destination = tmp_path / 'destination'
    if kind == 'empty-directory':
        destination.mkdir()
    elif kind == 'directory':
        destination.mkdir()
        (destination / 'foreign.txt').write_bytes(b'foreign')
    elif kind == 'file':
        destination.write_bytes(b'foreign')
    else:
        target = tmp_path / 'other'
        if kind == 'directory-link':
            target.mkdir()
        try:
            destination.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            if os.name == 'nt':
                pytest.skip(f'Windows symlink capability unavailable: {type(exc).__name__}')
            raise
    before = destination.lstat()
    with pytest.raises(OSError):
        persistence._publish_no_replace(stage, destination)
    after = destination.lstat()
    assert (after.st_dev, after.st_ino, after.st_mode) == (before.st_dev, before.st_ino, before.st_mode)
    assert (stage / 'nested' / 'payload.txt').read_bytes() == b'complete authored payload'
    if kind == 'file':
        assert destination.read_bytes() == b'foreign'
    if kind == 'directory':
        assert (destination / 'foreign.txt').read_bytes() == b'foreign'


def test_success_publishes_the_complete_same_directory(tmp_path):
    stage = staged(tmp_path)
    before = stage.stat()
    destination = tmp_path / 'published-δ'
    api().publish_directory_no_replace(stage, destination)
    assert not stage.exists()
    after = destination.stat()
    assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
    assert (destination / 'nested' / 'payload.txt').read_bytes() == b'complete authored payload'


def test_two_publishers_have_exactly_one_winner_and_keep_the_loser(tmp_path):
    publisher = api()
    sources = [staged(tmp_path, 'one'), staged(tmp_path, 'two')]
    for number, stage in enumerate(sources):
        (stage / 'owner.txt').write_text(str(number))
    destination = tmp_path / 'winner'
    barrier = Barrier(2)

    def publish(index):
        barrier.wait(timeout=5)
        try:
            publisher.publish_directory_no_replace(sources[index], destination)
        except FileExistsError:
            return index, False
        return index, True

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, range(2)))
    assert sum(won for _, won in results) == 1
    winner = next(index for index, won in results if won)
    assert (destination / 'owner.txt').read_text() == str(winner)
    assert not sources[winner].exists() and sources[1-winner].is_dir()


@pytest.mark.parametrize('invalid', ['source-nul', 'target-nul', 'same-path', 'relative', 'different-parent'])
def test_invalid_paths_refuse_before_native_conversion(tmp_path, monkeypatch, invalid):
    publisher = api()
    stage = staged(tmp_path)
    source, destination = stage, tmp_path / 'destination'
    if invalid == 'source-nul':
        source = Path(str(stage) + '\0suffix')
    elif invalid == 'target-nul':
        destination = Path(str(destination) + '\0suffix')
    elif invalid == 'same-path':
        destination = stage
    elif invalid == 'relative':
        source = Path('relative')
    else:
        destination = tmp_path / 'different' / 'destination'
    monkeypatch.setattr(publisher, '_native_move', lambda *_: pytest.fail('invalid path reached native code'))
    with pytest.raises((OSError, ValueError)):
        publisher.publish_directory_no_replace(source, destination)
    assert stage.is_dir() and (stage / 'nested' / 'payload.txt').is_file()


@pytest.mark.parametrize('kind', ['file', 'symlink'])
def test_source_must_be_an_ordinary_stage_directory(tmp_path, monkeypatch, kind):
    publisher = api()
    stage = tmp_path / 'stage'
    if kind == 'file':
        stage.write_bytes(b'not a directory')
    else:
        other = staged(tmp_path, 'other')
        try:
            stage.symlink_to(other, target_is_directory=True)
        except OSError as exc:
            if os.name == 'nt':
                pytest.skip(f'Windows symlink capability unavailable: {type(exc).__name__}')
            raise
    monkeypatch.setattr(publisher, '_native_move', lambda *_: pytest.fail('invalid source reached native code'))
    with pytest.raises((OSError, ValueError)):
        publisher.publish_directory_no_replace(stage, tmp_path / 'destination')
    assert os.path.lexists(stage)


@pytest.mark.parametrize('tag', [0, 0xA0000003], ids=['reparse-attribute', 'junction-metadata'])
def test_windows_reparse_directory_metadata_is_refused_before_native_move(tmp_path, monkeypatch, tag):
    publisher = api()
    stage = staged(tmp_path)
    destination = tmp_path / 'destination'
    lstat = Path.lstat
    info = stage.lstat()
    metadata = SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x410, st_reparse_tag=tag)
    calls = []
    monkeypatch.setattr(Path, 'lstat', lambda path, *a, **kw:
                        metadata if path == stage else lstat(path, *a, **kw))
    monkeypatch.setattr(publisher, '_native_move', lambda *args: calls.append(args))
    with pytest.raises(OSError):
        publisher.publish_directory_no_replace(stage, destination)
    assert not calls and not os.path.lexists(destination)
    assert (stage / 'nested' / 'payload.txt').read_bytes() == b'complete authored payload'


@pytest.mark.skipif(os.name != 'nt', reason='native Windows junction creation is required')
def test_native_windows_stage_junction_is_not_published(tmp_path):
    publisher = api()
    target = staged(tmp_path, 'junction-target')
    stage = tmp_path / 'stage-junction'
    destination = tmp_path / 'destination'
    command = Path(os.environ['SystemRoot']) / 'System32' / 'cmd.exe'
    created = subprocess.run([str(command), '/d', '/c', 'mklink', '/J', str(stage), str(target)],
                             capture_output=True, text=True, timeout=10, check=False)
    if created.returncode:
        pytest.skip(f'native Windows junction capability unavailable (exit {created.returncode})')
    assert stage.is_junction() and stage.lstat().st_file_attributes & 0x400
    with pytest.raises(OSError):
        publisher.publish_directory_no_replace(stage, destination)
    assert stage.is_junction() and not os.path.lexists(destination)
    assert (target / 'nested' / 'payload.txt').read_bytes() == b'complete authored payload'


@pytest.mark.parametrize('code', [errno.EXDEV, errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP, errno.EACCES, errno.EIO])
def test_linux_native_errors_do_not_trigger_weaker_fallback(tmp_path, monkeypatch, code):
    publisher = api()
    stage = staged(tmp_path)
    destination = tmp_path / 'destination'
    calls = []

    def native(*args):
        calls.append(args)
        ctypes.set_errno(code)
        return -1

    monkeypatch.setattr(publisher, 'sys', SimpleNamespace(platform='linux'))
    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace(renameat2=native))
    monkeypatch.setattr(publisher.os, 'rename', lambda *_: pytest.fail('unsafe fallback'))
    monkeypatch.setattr(publisher.os, 'replace', lambda *_: pytest.fail('unsafe fallback'))
    with pytest.raises(OSError) as caught:
        publisher.publish_directory_no_replace(stage, destination)
    assert caught.value.errno == code
    assert calls == [(-100, os.fsencode(stage), -100, os.fsencode(destination), 1)]
    assert stage.is_dir() and not os.path.lexists(destination)


@pytest.mark.parametrize('platform', ['unsupported', 'missing-libc-symbol'])
def test_unavailable_native_operation_fails_closed(tmp_path, monkeypatch, platform):
    publisher = api()
    stage = staged(tmp_path)
    destination = tmp_path / 'destination'
    monkeypatch.setattr(publisher, 'sys', SimpleNamespace(platform='linux' if platform == 'missing-libc-symbol' else 'other'))
    monkeypatch.setattr(ctypes, 'CDLL', lambda *a, **kw: SimpleNamespace())
    monkeypatch.setattr(publisher.os, 'rename', lambda *_: pytest.fail('unsafe fallback'))
    with pytest.raises(OSError) as caught:
        publisher.publish_directory_no_replace(stage, destination)
    assert caught.value.errno == errno.ENOTSUP and stage.is_dir() and not os.path.lexists(destination)


def test_windows_dispatch_uses_the_existing_nonreplacing_python_primitive(tmp_path, monkeypatch):
    publisher = api()
    stage = staged(tmp_path)
    destination = tmp_path / 'destination'
    calls = []
    monkeypatch.setattr(publisher, 'sys', SimpleNamespace(platform='win32'))
    monkeypatch.setattr(publisher.os, 'rename', lambda *args: calls.append(args))
    monkeypatch.setattr(ctypes, 'CDLL', lambda *_a, **_k: pytest.fail('Windows loaded Linux primitive'))
    publisher.publish_directory_no_replace(stage, destination)
    assert calls == [(stage, destination)]
