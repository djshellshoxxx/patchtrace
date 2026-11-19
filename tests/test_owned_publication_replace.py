"""Explicit Windows replacement keeps native source ownership; no live claim."""
from __future__ import annotations

import os
import sys
from types import SimpleNamespace

import pytest
from test_research_qualification_winpairs_publication import _portable_windows_information_calls

from patchtrace import owned_publication as owned
from patchtrace.strings import export


@pytest.mark.parametrize('replace', [False, True])
@pytest.mark.parametrize('name', ['report.json', 'receipt-\U0001f9ea.json'])
def test_native_replace_flag_is_explicit_and_keeps_owned_handle_parent_and_utf16_leaf(replace, name):
    fixture, calls, translated = _portable_windows_information_calls()
    win = owned.WindowsPublication.__new__(owned.WindowsPublication)
    win.__dict__.update(fixture.__dict__)
    win.rename(17, 29, name, replace=replace)
    assert len(calls) == 1 and not translated
    source, information_class, raw = calls[0]
    assert (source, information_class) == (17, 10)
    info = win.RenameInfo.from_buffer_copy(raw)
    encoded = name.encode('utf-16-le')
    assert bool(info.ReplaceIfExists) is replace and info.RootDirectory == 29
    assert info.FileNameLength == len(encoded)
    offset = win.RenameInfo.FileName.offset
    assert raw[offset:offset + len(encoded)] == encoded


@pytest.mark.parametrize('failure', ['none', 'write', 'rename', 'cancel'])
def test_windows_forced_publication_closes_and_discards_only_owned_handles(tmp_path, monkeypatch, failure):
    calls = []
    error = KeyboardInterrupt('authored cancellation') if failure == 'cancel' else OSError(5, 'authored failure')

    def stage(fd, data):
        calls.append(('write', fd, data))
        if failure in ('write', 'cancel'):
            raise error

    def rename(source, parent, name, *, replace=False):
        calls.append(('rename', source, parent, name, replace))
        if failure == 'rename':
            raise error

    def discard(source):
        calls.append(('discard', source))

    def close(fd):
        calls.append(('close', fd))

    win = SimpleNamespace(directory=lambda *args, **kwargs: 29, open_child=lambda *args, **kwargs: 17,
                          identity=lambda *args: (1, 2, 3), check_parent=lambda *args: None,
                          rename=rename, discard=discard)
    api = SimpleNamespace(O_RDWR=os.O_RDWR, O_BINARY=0, close=close)
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace(open_osfhandle=lambda *args: 91))
    kwargs = dict(windows_factory=lambda: win, stage_writer=stage, os_api=api, replace=True)
    if failure == 'none':
        assert owned.publish_windows(tmp_path / 'report.json', b'export', **kwargs)
        assert calls == [('write', 91, b'export'), ('rename', 17, 29, 'report.json', True), ('close', 91)]
    else:
        with pytest.raises(type(error)) as caught:
            owned.publish_windows(tmp_path / 'report.json', b'export', **kwargs)
        assert caught.value is error
        assert calls[0] == ('write', 91, b'export')
        assert calls[-2:] == [('discard', 17), ('close', 91)]
        if failure == 'rename':
            assert calls[1] == ('rename', 17, 29, 'report.json', True)


@pytest.mark.parametrize('reuse', [{'validate_existing': lambda data: None}, {'require_existing': True}])
def test_windows_force_cannot_be_combined_with_immutable_evidence_reuse(tmp_path, monkeypatch, reuse):
    monkeypatch.setitem(sys.modules, 'msvcrt', SimpleNamespace())
    with pytest.raises(ValueError, match='cannot reuse'):
        owned.publish_windows(tmp_path / 'report.json', b'export', replace=True, **reuse)


@pytest.mark.skipif(os.name != 'nt', reason='native Windows held-source replacement acceptance')
def test_native_windows_force_replaces_existing_destination_while_source_denies_substitution(
        tmp_path, monkeypatch):
    target = tmp_path / 'report.json'
    target.write_bytes(b'prior complete export')
    sync = os.fsync
    calls = []

    def substitute(fd):
        sync(fd)
        stages = list(tmp_path.glob('.owned-*.tmp'))
        assert len(stages) == 1
        calls.append(stages[0])
        with pytest.raises(PermissionError):
            stages[0].rename(tmp_path / 'displaced')
        with pytest.raises(PermissionError):
            stages[0].write_bytes(b'foreign bytes')

    monkeypatch.setattr(os, 'fsync', substitute)
    export.write_atomic(target, b'expected export', force=True)
    assert target.read_bytes() == b'expected export'
    assert len(calls) == 1 and list(tmp_path.iterdir()) == [target]
