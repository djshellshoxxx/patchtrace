"""Held stream publication uses bounded memory and retains exact source/destination identity."""
from __future__ import annotations

import hashlib
import os
import sys
from types import SimpleNamespace

import pytest

from patchtrace import owned_publication as owned


def sample():
    return (bytes(range(256)) * (3 * 4096)) + b'last block'


def test_snapshot_and_publication_reads_are_fixed_size_and_handle_short_reads(tmp_path, monkeypatch):
    data = sample()
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(data)
    read, requests = os.read, []

    def short(fd, size):
        requests.append(size)
        assert 0 < size <= owned.STREAM_CHUNK
        return read(fd, min(size, 8191))

    monkeypatch.setattr(os, 'read', short)
    with source.open('rb', buffering=0) as handle:
        with owned.FileSnapshot(handle.fileno(), maximum=2**31, expected_size=len(data),
                                expected_sha256=hashlib.sha256(data).hexdigest()) as snapshot:
            assert snapshot.read(65000, 20000) == data[65000:85000]
            assert len(snapshot._blocks) == 32 * ((len(data) + owned.SNAPSHOT_BLOCK - 1) // owned.SNAPSHOT_BLOCK)
            assert owned.publish_stream(target, snapshot)
        assert os.fstat(handle.fileno()).st_size == len(data)  # borrowed source was never closed
        with pytest.raises(owned.OwnedPublicationError, match='no longer borrowed'):
            snapshot.read(0, 1)
    assert requests and max(requests) == owned.STREAM_CHUNK
    assert target.read_bytes() == data


@pytest.mark.parametrize('damage', ['budget', 'size', 'digest'])
def test_snapshot_refuses_wrong_admission_and_identity(tmp_path, monkeypatch, damage):
    source = tmp_path / 'source'
    source.write_bytes(b'expected')
    with source.open('rb', buffering=0) as handle:
        kwargs = {'maximum': 8, 'expected_size': 8, 'expected_sha256': hashlib.sha256(b'expected').hexdigest()}
        if damage == 'budget':
            kwargs.update(maximum=7, expected_size=None)
        elif damage == 'size':
            kwargs['expected_size'] = 7
        else:
            kwargs['expected_sha256'] = '0' * 64
        if damage != 'digest':
            monkeypatch.setattr(os, 'read', lambda *args: pytest.fail('bad size must fail before reading'))
        with pytest.raises(owned.OwnedPublicationError):
            owned.FileSnapshot(handle.fileno(), **kwargs)


@pytest.mark.parametrize('callback_read', [False, True])
def test_snapshot_detects_same_inode_changes_even_with_coarse_change_metadata(tmp_path, monkeypatch, callback_read):
    target = tmp_path / 'source'
    target.write_bytes(b'expected content')
    monkeypatch.setattr(owned, '_observation', lambda info: (owned.file_identity(info), info.st_size))

    def mutate(snapshot):
        target.write_bytes(b'foreign! content')
        if callback_read:
            snapshot.read(0, snapshot.size)

    with pytest.raises(owned.OwnedPublicationError, match='block differs'):
        owned.inspect_file(target, maximum=100, inspect=mutate)
    assert target.read_bytes() == b'foreign! content'


def test_named_snapshot_rejects_replaced_leaf_after_validating_held_source(tmp_path, monkeypatch):
    target = tmp_path / 'source'
    target.write_bytes(b'expected')
    monkeypatch.setattr(owned, '_observation', lambda info: (owned.file_identity(info), info.st_size))

    def replace(snapshot):
        target.rename(tmp_path / 'displaced')
        target.write_bytes(b'foreign!')
        assert snapshot.read(0, snapshot.size) == b'expected'

    with pytest.raises(owned.OwnedPublicationError, match='identity changed'):
        owned.inspect_file(target, maximum=100, inspect=replace)
    assert target.read_bytes() == b'foreign!'
    assert (tmp_path / 'displaced').read_bytes() == b'expected'


@pytest.mark.parametrize('kind', ['file', 'directory', 'symlink'])
def test_stream_publication_preserves_conflicting_destination(tmp_path, kind):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'expected')
    if kind == 'file':
        target.write_bytes(b'prior')
    elif kind == 'directory':
        target.mkdir()
    else:
        try:
            target.symlink_to(source)
        except OSError:
            pytest.skip('symlink unavailable')
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        with pytest.raises((FileExistsError, owned.OwnedPublicationError)):
            owned.publish_stream(target, snapshot)
    assert target.is_symlink() if kind == 'symlink' else target.is_dir() if kind == 'directory' else target.read_bytes() == b'prior'


def test_stream_reuse_validates_existing_snapshot_and_preserves_validator_failure(tmp_path):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'expected')
    target.write_bytes(b'expected')
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        def exact(existing):
            assert existing.size == snapshot.size and existing.sha256 == snapshot.sha256
        assert not owned.publish_stream(target, snapshot, validate_existing=exact, maximum=100)

        def invalid(existing):
            raise FileNotFoundError('validator dependency is absent')
        with pytest.raises(FileNotFoundError, match='validator dependency'):
            owned.publish_stream(target, snapshot, validate_existing=invalid, maximum=100)
    assert target.read_bytes() == b'expected'


def test_snapshot_cancellation_during_hashing_closes_owned_leaf_without_running_parser(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(sample())
    read, interrupted = os.read, False
    primary = KeyboardInterrupt('authored snapshot cancellation')

    def receive(fd, size):
        nonlocal interrupted
        result = read(fd, size)
        interrupted = True
        return result

    def check():
        if interrupted:
            raise primary

    monkeypatch.setattr(os, 'read', receive)
    with pytest.raises(KeyboardInterrupt) as caught:
        owned.inspect_file(source, maximum=2**31, check=check,
                           inspect=lambda _: pytest.fail('cancelled snapshot cannot reach a parser'))
    assert caught.value is primary and source.read_bytes() == sample()


@pytest.mark.parametrize('damage', ['root-swap', 'parent-link'])
def test_stream_publication_refuses_changed_anchored_root_or_linked_parent(tmp_path, damage):
    source, root = tmp_path / 'source', tmp_path / 'root'
    source.write_bytes(b'expected')
    root.mkdir()
    anchor = owned.directory_anchor(root)
    target = root / 'child' / 'target'
    if damage == 'root-swap':
        root.rename(tmp_path / 'prior-root')
        root.mkdir()
    else:
        other = tmp_path / 'other'
        other.mkdir()
        try:
            (root / 'child').symlink_to(other, target_is_directory=True)
        except OSError:
            pytest.skip('symlink unavailable')
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        with pytest.raises(owned.OwnedPublicationError):
            owned.publish_stream(target, snapshot, anchor=anchor)
    assert not target.exists()


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux descriptor-link boundary')
@pytest.mark.parametrize('replacement', [b'foreign!', b'foreign bytes grow', b''])
def test_stream_publication_refuses_same_inode_destination_mutation_after_link(tmp_path, monkeypatch, replacement):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'expected')
    link = os.link

    def mutate(*args, **kwargs):
        link(*args, **kwargs)
        target.write_bytes(replacement)

    monkeypatch.setattr(os, 'link', mutate)
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        with pytest.raises(owned.OwnedPublicationError):
            owned.publish_stream(target, snapshot)
    assert target.read_bytes() == replacement


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux anonymous stage cleanup')
@pytest.mark.parametrize('failure', ['primary', 'standalone'])
def test_stream_cleanup_preserves_primary_and_propagates_standalone_cancellation(tmp_path, monkeypatch, failure):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'expected')
    original_open, original_close, stage = os.open, os.close, []
    primary = OSError('primary publication failure')

    def opened(path, flags, *args, **kwargs):
        fd = original_open(path, flags, *args, **kwargs)
        if flags & os.O_TMPFILE == os.O_TMPFILE:
            stage.append(fd)
        return fd

    def closed(fd):
        original_close(fd)
        if fd in stage:
            stage.remove(fd)
            raise KeyboardInterrupt('stage close cancellation')

    monkeypatch.setattr(os, 'open', opened)
    monkeypatch.setattr(os, 'close', closed)
    if failure == 'primary':
        def failed(*args, **kwargs):
            raise primary
        monkeypatch.setattr(os, 'link', failed)
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        try:
            raise ValueError('unrelated caller error')
        except ValueError as unrelated:
            with pytest.raises(BaseException) as caught:
                owned.publish_stream(target, snapshot)
            assert isinstance(caught.value, OSError if failure == 'primary' else KeyboardInterrupt)
            if failure == 'primary':
                assert caught.value is primary and any('KeyboardInterrupt' in note for note in primary.__notes__)
            assert not getattr(unrelated, '__notes__', [])
    assert not stage


@pytest.mark.parametrize('mutate', [False, True])
def test_portable_windows_stream_stage_verifies_after_rename_and_closes_only_owned_handle(tmp_path, monkeypatch, mutate):
    source, stage_path, target = tmp_path / 'source', tmp_path / 'stage', tmp_path / 'target'
    source.write_bytes(b'expected')
    descriptor = os.open(stage_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    calls = []

    def rename(handle, parent, name):
        calls.append(('rename', handle, parent, name))
        os.link(stage_path, target)
        if mutate:
            target.write_bytes(b'foreign!')

    def close(fd):
        calls.append(('close', fd))
        os.close(fd)

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=lambda *args: (1, 2, 3), check_parent=lambda *args: None,
                          rename=rename, discard=lambda handle: calls.append(('discard', handle)))
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=lambda *args: descriptor))
    api = SimpleNamespace(O_RDWR=os.O_RDWR, O_BINARY=0, close=close)
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        kwargs = dict(windows_factory=lambda: win, stage_writer=owned._write_stream_stage,
                      stage_verifier=owned._verify_stream_stage, os_api=api)
        if mutate:
            with pytest.raises(owned.OwnedPublicationError, match='bytes changed'):
                owned.publish_windows(target, snapshot, **kwargs)
        else:
            assert owned.publish_windows(target, snapshot, **kwargs)
        assert os.fstat(handle.fileno()).st_size == 8
    assert calls == [('rename', 17, 29, 'target'), ('close', descriptor)]
    assert target.read_bytes() == (b'foreign!' if mutate else b'expected')


@pytest.mark.skipif(os.name != 'nt', reason='native Windows held-source streaming publication acceptance')
def test_native_windows_stream_stage_denies_replacement_and_in_place_write(tmp_path, monkeypatch):
    source, target = tmp_path / 'source', tmp_path / 'target'
    source.write_bytes(b'expected')
    sync, checked = os.fsync, []

    def challenge(fd):
        sync(fd)
        stages = list(tmp_path.glob('.owned-*.tmp'))
        assert len(stages) == 1
        checked.append(stages[0])
        with pytest.raises(PermissionError):
            stages[0].rename(tmp_path / 'displaced')
        with pytest.raises(PermissionError):
            stages[0].write_bytes(b'foreign!')

    monkeypatch.setattr(os, 'fsync', challenge)
    with source.open('rb', buffering=0) as handle, owned.FileSnapshot(handle.fileno(), maximum=100) as snapshot:
        assert owned.publish_stream(target, snapshot)
    assert len(checked) == 1 and target.read_bytes() == b'expected'
