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
    target.write_bytes(b'prior complete export')
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
        assert target.read_bytes() == b'prior complete export'
    else:
        export.write_atomic(target, b'expected export', force=True)
        assert target.read_bytes() == b'expected export'
    for stage in replaced:
        assert stage.read_bytes() == b'foreign bytes'
    for fd in descriptors:
        with pytest.raises(OSError):
            os.fstat(fd)


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux linked-stage admission boundary')
@pytest.mark.parametrize('replacement', ['ordinary', 'symlink'])
def test_force_refuses_a_source_substituted_before_rename_admission(tmp_path, monkeypatch, replacement):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    foreign = tmp_path / 'foreign'
    foreign.write_bytes(b'foreign bytes')
    link = os.link
    stages = []

    def substitute(source, name, **kwargs):
        link(source, name, **kwargs)
        stage = tmp_path / name
        stages.append(stage)
        stage.rename(tmp_path / 'held-original')
        if replacement == 'ordinary':
            stage.write_bytes(b'foreign bytes')
        else:
            stage.symlink_to(foreign)

    monkeypatch.setattr(os, 'link', substitute)
    with pytest.raises(StringsError, match='staging identity changed'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'prior complete export'
    assert (tmp_path / 'held-original').read_bytes() == b'expected export'
    assert foreign.read_bytes() == b'foreign bytes'
    assert len(stages) == 1 and stages[0].read_bytes() == b'foreign bytes'
    assert stages[0].is_symlink() == (replacement == 'symlink')


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux pathname race remains detectable only after rename')
def test_final_linux_source_race_is_reported_without_deleting_foreign_bytes(tmp_path, monkeypatch):
    """Receipt refusal is not a claim that foreign bytes were never visible."""
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    replace = os.replace
    displaced = tmp_path / 'held-original'

    def substitute(source, destination, **kwargs):
        stage = tmp_path / source
        stage.rename(displaced)
        stage.write_bytes(b'foreign bytes')
        replace(source, destination, **kwargs)

    monkeypatch.setattr(os, 'replace', substitute)
    with pytest.raises(StringsError, match='destination identity changed'):
        export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'foreign bytes'  # known final pathname race, not ownership qualification
    assert displaced.read_bytes() == b'expected export'


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux linked-stage content admission')
@pytest.mark.parametrize('boundary', ['link', 'replace'])
@pytest.mark.parametrize('replacement', [b'foreign content', b'longer foreign bytes', b''])
def test_force_same_inode_mutation_cannot_return_a_false_digest(tmp_path, monkeypatch, boundary, replacement):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    real = getattr(os, boundary)
    stages = []

    def mutate(source, destination, **kwargs):
        stage = tmp_path / (destination if boundary == 'link' else source)
        if boundary == 'link':
            real(source, destination, **kwargs)
        original = stage.stat()
        stage.write_bytes(replacement)
        # Same-length content with restored mtime still requires byte verification.
        os.utime(stage, ns=(original.st_atime_ns, original.st_mtime_ns))
        assert stage.stat().st_ino == original.st_ino
        stages.append(stage)
        if boundary == 'replace':
            real(source, destination, **kwargs)

    monkeypatch.setattr(os, boundary, mutate)
    with pytest.raises(StringsError, match='bytes changed'):
        export.write_atomic(target, b'expected export', force=True)
    assert len(stages) == 1
    if boundary == 'link':
        assert target.read_bytes() == b'prior complete export'
        assert stages[0].read_bytes() == replacement
    else:
        # Postpublication refusal cannot undo visible writes; no rollback claim.
        assert target.read_bytes() == replacement


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


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux descriptor cleanup boundary')
def test_force_cleanup_failure_preserves_primary_interrupt_and_closes_its_descriptor(tmp_path, monkeypatch):
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
        export.write_atomic(target, b'new export', force=True)
    assert caught.value is original
    assert original.__notes__ == ['Export descriptor cleanup also failed: OSError']
    with pytest.raises(OSError):
        os.fstat(descriptor[0])
    assert target.read_bytes() == b'prior complete export'
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not sys.platform.startswith('linux'), reason='Linux explicit cleanup exception ownership')
@pytest.mark.parametrize('kind', ['io', 'interrupt', 'exit'])
def test_successful_force_cleanup_does_not_hide_fresh_failure_behind_caller_exception(tmp_path, monkeypatch, kind):
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
            export.write_atomic(target, b'new export', force=True)
        if kind == 'io':
            assert caught.value.code == 'PT-STR-EXPORT' and 'authored close failure' in str(caught.value)
        else:
            assert caught.value is failure
    assert not getattr(caller, '__notes__', [])
    with pytest.raises(OSError):
        os.fstat(descriptor[0])
    assert target.read_bytes() == b'new export'
    assert list(tmp_path.iterdir()) == [target]
