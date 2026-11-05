"""Authored metadata publication controls; no network/native acquisition evidence."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k5_support import FIXTURES

from patchtrace.kbcorrelation import store, wiring
from patchtrace.kbcorrelation.store import KbcStoreError

pytestmark = pytest.mark.usefixtures('no_sockets')
NAME = 'examplenet.sys'
DATE = '2099-02-12'


def fixture(tmp_path):
    raw = (FIXTURES / f'{NAME}.json').read_bytes()
    source = tmp_path / 'source.json'
    source.write_bytes(raw)
    root = tmp_path / 'workspace'
    directory = root / wiring.INDEX_DIR
    directory.mkdir(parents=True)
    target = directory / f'{NAME}@{DATE}.json'
    return source, raw, root, target


@pytest.mark.parametrize('alias', ['symlink', 'hardlink', 'regular-file', 'directory'])
def test_preexisting_fixed_temporary_name_is_never_modified_or_published(tmp_path, alias):
    source, raw, root, target = fixture(tmp_path)
    fixed = target.with_name(target.name + '.tmp')
    foreign = tmp_path / 'foreign.txt'
    original = b'Unrelated analyst bytes must survive metadata publication.'
    foreign.write_bytes(original)
    if alias == 'regular-file':
        fixed.write_bytes(original)
    elif alias == 'directory':
        fixed.mkdir()
        (fixed / 'foreign.txt').write_bytes(original)
    else:
        try:
            if alias == 'symlink':
                fixed.symlink_to(foreign)
            else:
                os.link(foreign, fixed)
        except (OSError, NotImplementedError):
            pytest.skip(f'this filesystem cannot create a {alias}')
    result = wiring.save_winbindex_record(root, source, NAME, DATE)
    assert foreign.read_bytes() == original
    assert not target.is_symlink() and target.read_bytes() == raw
    if alias == 'directory':
        assert (fixed / 'foreign.txt').read_bytes() == original
    else:
        assert fixed.read_bytes() == original
    assert result['sha256'] == hashlib.sha256(raw).hexdigest()
    assert result['stored_as'] == f'winbindex/{target.name}'


@pytest.mark.parametrize('failure', ['flush', 'replace'])
def test_failed_publication_preserves_committed_record_foreign_fixed_temp_and_cleans_owned_stage(
        tmp_path, monkeypatch, failure):
    source, original, root, target = fixture(tmp_path)
    wiring.save_winbindex_record(root, source, NAME, DATE)
    source.write_bytes(original + b'\n')  # a valid corrected encoding, with distinct exact bytes
    fixed = target.with_name(target.name + '.tmp')
    foreign = b'Preexisting foreign temporary file.'
    fixed.write_bytes(foreign)
    previous = set(target.parent.iterdir())

    def refuse(*args, **kwargs):
        raise OSError('authored publication failure')

    if failure == 'flush':
        monkeypatch.setattr(store.os, 'fsync', refuse)
    else:
        real_replace = store.os.replace

        def fail_target(source_path, destination):
            if Path(destination) == target:
                refuse()
            return real_replace(source_path, destination)

        monkeypatch.setattr(store.os, 'replace', fail_target)
    with pytest.raises(KbcStoreError) as caught:
        wiring.save_winbindex_record(root, source, NAME, DATE)
    assert caught.value.code == 'PT-KBC-STORAGE'
    assert target.read_bytes() == original
    assert fixed.read_bytes() == foreign
    assert set(target.parent.iterdir()) == previous


def test_invalid_record_does_not_create_staging_or_touch_existing_record(tmp_path):
    source, original, root, target = fixture(tmp_path)
    wiring.save_winbindex_record(root, source, NAME, DATE)
    source.write_bytes(b'{"duplicate":1,"duplicate":2}')
    before = {path.name: path.read_bytes() for path in target.parent.iterdir()}
    with pytest.raises(KbcStoreError) as caught:
        wiring.save_winbindex_record(root, source, NAME, DATE)
    assert caught.value.code == 'PT-KBC-INPUT'
    assert {path.name: path.read_bytes() for path in target.parent.iterdir()} == before
    assert target.read_bytes() == original


def test_explicit_same_name_date_replacement_retains_previous_hardlink_alias_bytes(tmp_path):
    source, original, root, target = fixture(tmp_path)
    wiring.save_winbindex_record(root, source, NAME, DATE)
    foreign = tmp_path / 'old-record-alias.json'
    try:
        os.link(target, foreign)
    except (OSError, NotImplementedError):
        pytest.skip('this filesystem cannot create hardlinks')
    source.write_bytes(original + b'\n')
    result = wiring.save_winbindex_record(root, source, NAME, DATE)
    assert result['replaced'] is True
    assert target.read_bytes() == original + b'\n'
    assert foreign.read_bytes() == original


def test_preexisting_index_directory_symlink_does_not_publish_into_foreign_directory(tmp_path):
    source, raw, root, target = fixture(tmp_path)
    target.parent.rmdir()
    foreign = tmp_path / 'foreign-directory'
    foreign.mkdir()
    (foreign / 'keep.txt').write_bytes(b'foreign directory bytes')
    try:
        target.parent.symlink_to(foreign, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip('this filesystem cannot create directory symlinks')
    before = {path.name: path.read_bytes() for path in foreign.iterdir()}
    with pytest.raises(KbcStoreError) as caught:
        wiring.save_winbindex_record(root, source, NAME, DATE)
    assert caught.value.code == 'PT-KBC-STORAGE'
    assert {path.name: path.read_bytes() for path in foreign.iterdir()} == before
    assert source.read_bytes() == raw and target.parent.is_symlink()


def test_fdopen_failure_closes_raw_stage_descriptor_and_preserves_existing_bytes(tmp_path, monkeypatch):
    source, original, root, target = fixture(tmp_path)
    wiring.save_winbindex_record(root, source, NAME, DATE)
    source.write_bytes(original + b'\n')
    before = set(target.parent.iterdir())
    descriptors = []
    real_mkstemp = store.tempfile.mkstemp

    def record_stage(*args, **kwargs):
        descriptor, stage = real_mkstemp(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor, stage

    def refuse_buffering(*args, **kwargs):
        raise OSError('authored fdopen failure before ownership transfer')

    monkeypatch.setattr(store.tempfile, 'mkstemp', record_stage)
    monkeypatch.setattr(store.os, 'fdopen', refuse_buffering)
    try:
        with pytest.raises(KbcStoreError) as caught:
            wiring.save_winbindex_record(root, source, NAME, DATE)
        assert caught.value.code == 'PT-KBC-STORAGE'
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])
        assert target.read_bytes() == original
        assert set(target.parent.iterdir()) == before
    finally:
        # The baseline leaked this test's own descriptor; never leave a failed probe open.
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def test_successful_buffering_transfers_descriptor_ownership_without_double_close(tmp_path, monkeypatch):
    source, raw, root, target = fixture(tmp_path)
    real_fdopen, real_close = store.os.fdopen, store.os.close
    transferred, raw_closes = [], []

    def record_transfer(descriptor, *args, **kwargs):
        handle = real_fdopen(descriptor, *args, **kwargs)
        transferred.append(descriptor)
        return handle

    def record_close(descriptor):
        raw_closes.append(descriptor)
        return real_close(descriptor)

    monkeypatch.setattr(store.os, 'fdopen', record_transfer)
    monkeypatch.setattr(store.os, 'close', record_close)
    wiring.save_winbindex_record(root, source, NAME, DATE)
    assert len(transferred) == 1 and not set(transferred).intersection(raw_closes)
    with pytest.raises(OSError):
        os.fstat(transferred[0])
    assert target.read_bytes() == raw
