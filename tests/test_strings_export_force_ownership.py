"""Forced export owns cleanup and detects observed publication substitutions."""
from __future__ import annotations

import os
import sys

import pytest

from patchtrace.strings import export
from patchtrace.strings.contracts import StringsError


@pytest.mark.parametrize('failure', [False, True], ids=['publish', 'io-failure'])
def test_force_sync_cannot_publish_or_remove_a_substituted_source(tmp_path, monkeypatch, failure):
    target = tmp_path / 'report.json'
    prior = target if os.name == 'nt' else tmp_path / 'prior.json'
    prior.write_bytes(b'prior complete export')
    sync = os.fsync
    replaced = []
    descriptors = []

    def substitute(fd):
        descriptors.append(fd)
        sync(fd)
        stages = list(tmp_path.glob('.*.tmp'))
        if stages:
            assert len(stages) == 1
            stage = stages[0]
            try:
                stage.rename(tmp_path / 'held-original')
            except PermissionError:
                assert os.name == 'nt'
            else:
                stage.write_bytes(b'foreign bytes')
                replaced.append(stage)
        else:
            assert sys.platform.startswith('linux') and os.fstat(fd).st_nlink == 0
        if failure:
            raise OSError(5, 'authored sync failure')

    monkeypatch.setattr(os, 'fsync', substitute)
    if failure:
        with pytest.raises(StringsError, match='authored sync failure'):
            export.write_atomic(target, b'expected export', force=True)
        assert prior.read_bytes() == b'prior complete export'
        if prior != target:
            assert not target.exists()
    else:
        export.write_atomic(target, b'expected export', force=True)
        assert target.read_bytes() == b'expected export'
    for stage in replaced:
        assert stage.read_bytes() == b'foreign bytes'
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux exclusive-link boundary')
@pytest.mark.parametrize('replacement', ['ordinary', 'symlink'])
def test_force_preserves_a_destination_arriving_before_link(tmp_path, monkeypatch, replacement):
    target = tmp_path / 'report.json'
    foreign = tmp_path / 'foreign'
    foreign.write_bytes(b'foreign bytes')
    link = os.link
    sources = []

    def substitute(source, name, **kwargs):
        assert name == target.name
        descriptor = int(str(source).rsplit('/', 1)[-1])
        assert os.fstat(descriptor).st_nlink == 0
        sources.append(descriptor)
        if replacement == 'ordinary':
            target.write_bytes(b'foreign bytes')
        else:
            target.symlink_to(foreign)
        return link(source, name, **kwargs)

    monkeypatch.setattr(os, 'link', substitute)
    with pytest.raises(StringsError, match='replacement is unavailable on Linux'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'foreign bytes'
    assert foreign.read_bytes() == b'foreign bytes'
    assert target.is_symlink() == (replacement == 'symlink')
    assert set(tmp_path.iterdir()) == {target, foreign}
    assert len(sources) == 1
    with pytest.raises(OSError):
        os.fstat(sources[0])


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux replacement is unavailable')
def test_linux_existing_destination_never_reaches_the_historical_rename_boundary(tmp_path, monkeypatch):
    """The original vulnerable receipt remains in the historical evidence archive."""
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')

    def forbidden(*_args, **_kwargs):
        pytest.fail('existing Linux destination must not reach pathname replacement')

    monkeypatch.setattr(os, 'replace', forbidden)
    monkeypatch.setattr(os, 'rename', forbidden)
    monkeypatch.setattr(os, 'unlink', forbidden)
    with pytest.raises(StringsError, match='replacement is unavailable on Linux'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'prior complete export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux exclusive-publication content admission')
@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('replacement', [b'foreign content', b'longer foreign bytes', b''])
def test_same_inode_mutation_cannot_return_a_false_digest(tmp_path, monkeypatch, force, replacement):
    target = tmp_path / 'report.json'
    link = os.link
    modified = []

    def mutate(source, destination, **kwargs):
        assert destination == target.name
        link(source, destination, **kwargs)
        original = target.stat()
        target.write_bytes(replacement)
        # Same-length content with restored mtime still requires byte verification.
        os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert target.stat().st_ino == original.st_ino
        modified.append(target)

    monkeypatch.setattr(os, 'link', mutate)
    with pytest.raises(StringsError, match='bytes changed'):
        export.write_atomic(target, b'expected export', force=force)
    assert modified == [target]
    # Exclusive publication does not make a later external edit immutable.
    assert target.read_bytes() == replacement
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux directory-descriptor publication')
def test_force_parent_change_before_publication_preserves_both_directories(tmp_path, monkeypatch):
    parent = tmp_path / 'selected'
    parent.mkdir()
    target = parent / 'report.json'
    target.write_bytes(b'prior complete export')
    moved = tmp_path / 'moved'
    sync = os.fsync

    def substitute(fd):
        sync(fd)
        parent.rename(moved)
        parent.mkdir()
        target.write_bytes(b'foreign destination')

    monkeypatch.setattr(os, 'fsync', substitute)
    with pytest.raises(StringsError, match='identity changed'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'foreign destination'
    assert (moved / target.name).read_bytes() == b'prior complete export'
    assert list(parent.iterdir()) == [target]
    assert list(moved.iterdir()) == [moved / target.name]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux rooted final link boundary')
def test_force_final_parent_substitution_cannot_redirect_writes_or_cleanup(tmp_path, monkeypatch):
    parent = tmp_path / 'selected'
    parent.mkdir()
    target = parent / 'report.json'
    moved = tmp_path / 'moved'
    link = os.link
    foreign = parent / 'foreign'

    def substitute(source, destination, **kwargs):
        assert destination == target.name
        parent.rename(moved)
        parent.mkdir()
        target.write_bytes(b'foreign destination')
        foreign.write_bytes(b'foreign contents')
        return link(source, destination, **kwargs)

    monkeypatch.setattr(os, 'link', substitute)
    with pytest.raises(StringsError, match='identity changed'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'foreign destination'
    assert foreign.read_bytes() == b'foreign contents'
    # Publication used the held original directory, and the receipt was refused
    # because that directory no longer occupies the selected path. No rollback.
    assert (moved / target.name).read_bytes() == b'expected export'


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux anonymous staging capability')
def test_force_missing_anonymous_staging_support_preserves_the_destination(tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    monkeypatch.delattr(os, 'O_TMPFILE')
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export', force=True)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert target.read_bytes() == b'prior complete export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize('boundary', ['directory_anchor', 'publish_bytes'])
@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux force dispatch')
def test_force_unsupported_capability_is_typed_and_path_free(tmp_path, monkeypatch, boundary):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')

    def unavailable(*args, **kwargs):
        raise NotImplementedError(f'authored unavailable operation at {tmp_path}')

    monkeypatch.setattr(export, boundary, unavailable)
    with pytest.raises(StringsError) as caught:
        export.write_atomic(target, b'expected export', force=True)
    assert caught.value.code == 'PT-STR-EXPORT'
    assert 'unavailable' in caught.value.message and str(tmp_path) not in caught.value.message
    assert target.read_bytes() == b'prior complete export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux descriptor cleanup boundary')
@pytest.mark.parametrize('force', [False, True])
def test_cleanup_failure_preserves_primary_interrupt_and_closes_its_descriptor(tmp_path, monkeypatch, force):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    original = KeyboardInterrupt('authored interruption')
    descriptor = []
    close = os.close

    def interrupt(fd):
        descriptor.append(fd)
        raise original

    def close_then_fail(fd):
        close(fd)
        if descriptor and fd == descriptor[0]:
            raise OSError(5, 'authored cleanup failure')

    monkeypatch.setattr(os, 'fsync', interrupt)
    monkeypatch.setattr(os, 'close', close_then_fail)
    with pytest.raises(KeyboardInterrupt) as caught:
        export.write_atomic(target, b'new export', force=force)
    assert caught.value is original
    assert original.__notes__ == ['Publication descriptor cleanup also failed: OSError']
    with pytest.raises(OSError):
        os.fstat(descriptor[0])
    assert target.read_bytes() == b'prior complete export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux explicit cleanup exception ownership')
@pytest.mark.parametrize('force', [False, True])
@pytest.mark.parametrize('kind', ['io', 'interrupt', 'exit'])
def test_successful_cleanup_does_not_hide_fresh_failure_behind_caller_exception(tmp_path, monkeypatch, kind, force):
    target = tmp_path / 'report.json'
    caller = ValueError('unrelated caller exception')
    failure = {'io': OSError(5, 'authored close failure'),
               'interrupt': KeyboardInterrupt('authored close interrupt'), 'exit': SystemExit(23)}[kind]
    descriptor = []
    sync, close = os.fsync, os.close

    def remember(fd):
        descriptor.append(fd)
        sync(fd)

    def close_then_fail(fd):
        close(fd)
        if descriptor and fd == descriptor[0]:
            raise failure

    monkeypatch.setattr(os, 'fsync', remember)
    monkeypatch.setattr(os, 'close', close_then_fail)
    try:
        raise caller
    except ValueError:
        with pytest.raises(StringsError if kind == 'io' else type(failure)) as caught:
            export.write_atomic(target, b'new export', force=force)
        if kind == 'io':
            assert caught.value.code == 'PT-STR-EXPORT' and 'authored close failure' in str(caught.value)
        else:
            assert caught.value is failure
    assert not getattr(caller, '__notes__', [])
    with pytest.raises(OSError):
        os.fstat(descriptor[0])
    assert target.read_bytes() == b'new export'
    assert list(tmp_path.iterdir()) == [target]
