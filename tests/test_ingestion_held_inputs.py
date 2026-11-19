"""Actual authored PE copy/validation through a portable operation-owned reader."""
from __future__ import annotations

import hashlib
import os
import struct

import pytest
from held_input_support import Checkpoint, HeldFile, ReadStopped, authored_pair, deny_source_opens

from patchtrace import ingestion
from patchtrace.sample import synthetic_pe


def test_held_copy_denies_source_path_opens_and_keeps_original_descriptor(tmp_path, monkeypatch):
    with authored_pair(tmp_path, padding=ingestion.CHUNK_SIZE + 13) as (paths, readers):
        expected = hashlib.sha256(paths[0].read_bytes()).hexdigest()
        deny_source_opens(monkeypatch, paths)
        original_fingerprint = ingestion.file_fingerprint

        def fingerprint(path):
            assert path not in paths, 'held source used a path fingerprint'
            return original_fingerprint(path)

        monkeypatch.setattr(ingestion, 'file_fingerprint', fingerprint)
        artifact = ingestion.inspect_artifact(paths[0], 'older', tmp_path / 'project',
                                              reader=readers.older, checkpoint=readers.checkpoint)
        assert artifact.sha256 == expected and artifact.name == 'example.sys'
        assert artifact.size == readers.older.captured[2]
        assert hashlib.sha256((tmp_path / 'project' / artifact.relative_path).read_bytes()).hexdigest() == expected
        assert readers.older.opened == readers.older.closed == 1
        assert os.fstat(readers.older.fd).st_size == artifact.size
        assert readers.older.bytes_read == artifact.size
        assert sum(count for kind, count in readers.checkpoint.counts if kind == 'held') == artifact.size
        assert any(kind == 'core' and count > 0 for kind, count in readers.checkpoint.counts)
        assert readers.checkpoint.reserved_output == 123456


@pytest.mark.parametrize('failure', ['wrong-path', 'changed-before', 'changed-during', 'short-copy'])
def test_held_source_refusal_never_publishes_an_artifact(tmp_path, failure):
    with authored_pair(tmp_path) as (paths, readers):
        path, lease = paths[0], readers.older
        if failure == 'wrong-path':
            path = paths[1]
        elif failure == 'changed-before':
            lease.changed = True
        elif failure == 'changed-during':
            lease.on_read = lambda: setattr(lease, 'changed', True)
        else:
            def truncate_reader():
                lease.read_limit = 0
            lease.on_read = truncate_reader
            lease.read_limit = 128
        root = tmp_path / 'refused'
        with pytest.raises(ValueError):
            ingestion.inspect_artifact(path, 'older', root, reader=lease, checkpoint=readers.checkpoint)
        assert not list(root.rglob('*.bin')) and not list(root.rglob('.input-*'))
        assert not lease.active and lease.opened == lease.closed


def test_descriptor_state_change_is_refused_even_if_provider_check_is_disabled(tmp_path, monkeypatch):
    with authored_pair(tmp_path) as (paths, readers):
        lease = readers.older
        monkeypatch.setattr(lease, 'check', lambda path: None)
        once = []

        def changed():
            if not once:
                once.append(True)
                data = paths[0].read_bytes()
                paths[0].write_bytes(data + b'x')

        lease.on_read = changed
        with pytest.raises(ValueError, match='changed'):
            ingestion.inspect_artifact(paths[0], 'older', tmp_path / 'case', reader=lease)
        assert not list((tmp_path / 'case').rglob('*.bin'))


@pytest.mark.parametrize('mode', ['held', 'core'])
def test_checkpoint_can_stop_copy_or_project_stage_validation(tmp_path, mode):
    with authored_pair(tmp_path) as (paths, readers):
        readers.checkpoint.stop = lambda count, kind: kind == mode and count > 0
        with pytest.raises(ReadStopped, match='authored operation stopped'):
            ingestion.inspect_artifact(paths[0], 'older', tmp_path / 'case', reader=readers.older,
                                       checkpoint=readers.checkpoint)
        assert not readers.older.active and readers.older.opened == readers.older.closed
        assert not list((tmp_path / 'case').rglob('*.bin'))
        assert not list((tmp_path / 'case').rglob('.input-*'))


def test_held_pe_validator_uses_bound_reader_without_double_charging(tmp_path, monkeypatch):
    with authored_pair(tmp_path) as (paths, readers):
        deny_source_opens(monkeypatch, paths)
        ingestion.validate_pe(paths[0], reader=readers.older, checkpoint=readers.checkpoint)
        assert sum(count for _, count in readers.checkpoint.counts) == readers.older.bytes_read
        assert readers.older.bytes_read > 0
        assert readers.older.opened == readers.older.closed == 1


@pytest.mark.parametrize('kind', ['short', 'machine', 'sections', 'late-header'])
def test_held_pe_validation_keeps_complete_structure_checks(tmp_path, kind):
    data = bytearray(synthetic_pe(0))
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    if kind == 'machine':
        struct.pack_into('<H', data, offset + 4, 0x14C)
    elif kind == 'sections':
        struct.pack_into('<H', data, offset + 6, 65535)
    elif kind == 'late-header':
        data.extend(b'\0' * (65536 + 512 - len(data)))
        data[65536:65536 + 384] = data[offset:offset + 384]
        struct.pack_into('<I', data, 0x3C, 65536)
        data[65536:65540] = b'NOPE'
    path = tmp_path / 'input.sys'
    path.write_bytes(data)
    checkpoint = Checkpoint()
    lease = HeldFile(path, checkpoint)
    if kind == 'short':
        lease.read_limit = 10
    try:
        with pytest.raises(ValueError, match='PT-INPUT:'):
            ingestion.validate_pe(path, reader=lease, checkpoint=checkpoint)
        assert lease.opened == lease.closed == 1
    finally:
        lease.close()


def test_oversized_held_source_refuses_before_any_payload_read(tmp_path):
    path = tmp_path / 'sparse.sys'
    with path.open('wb') as stream:
        stream.truncate(ingestion.MAX_ARTIFACT_BYTES + 1)
    checkpoint = Checkpoint()
    lease = HeldFile(path, checkpoint)
    try:
        with pytest.raises(ValueError, match='1 GiB'):
            ingestion.inspect_artifact(path, 'older', tmp_path / 'case', reader=lease, checkpoint=checkpoint)
        assert lease.bytes_read == 0
        assert not list((tmp_path / 'case').rglob('*'))
    finally:
        lease.close()


def test_plain_full_hash_checkpoint_reports_exact_read_bytes_and_can_cancel(tmp_path):
    path = tmp_path / 'large.bin'
    data = b'x' * (ingestion.CHUNK_SIZE + 7)
    path.write_bytes(data)
    checkpoint = Checkpoint()
    assert ingestion.sha256_file(path, checkpoint=checkpoint) == hashlib.sha256(data).hexdigest()
    assert sum(count for _, count in checkpoint.counts) == len(data)
    checkpoint.stop = lambda count, kind: count > 0
    with pytest.raises(ReadStopped):
        ingestion.sha256_file(path, checkpoint=checkpoint)


def test_ordinary_path_copy_and_pe_validation_remain_available(tmp_path):
    source = tmp_path / 'ordinary.sys'
    source.write_bytes(synthetic_pe(0))
    artifact = ingestion.inspect_artifact(source, 'older', tmp_path / 'case')
    ingestion.verify_artifact(artifact, tmp_path / 'case')
    assert artifact.sha256 == hashlib.sha256(source.read_bytes()).hexdigest()
