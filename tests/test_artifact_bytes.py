"""Contract tests for the shared verified artifact byte reader (SPEC-26 seam)."""
from __future__ import annotations

import hashlib
import os
import time

import pytest

from patchtrace.artifact_bytes import MAX_READ_BYTES, ArtifactBytesError, VerifiedArtifactReader
from patchtrace.models import Artifact


def write(path, data: bytes):
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def test_reads_exact_bytes_including_nulls_and_high_bit(tmp_path):
    data = bytes(range(256)) * 4
    digest = write(tmp_path / 'a.bin', data)
    with VerifiedArtifactReader.open_path(tmp_path / 'a.bin', digest, len(data)) as reader:
        assert reader.size == len(data) and reader.sha256 == digest
        assert reader.read(0, 4) == b'\x00\x01\x02\x03'
        assert reader.read(250, 10) == bytes([250, 251, 252, 253, 254, 255, 0, 1, 2, 3])


def test_hash_and_size_mismatch_fail_closed(tmp_path):
    write(tmp_path / 'a.bin', b'abc')
    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_path(tmp_path / 'a.bin', 'f' * 64)
    assert exc.value.code == 'hash_mismatch'
    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_path(tmp_path / 'a.bin', expected_size=4)
    assert exc.value.code == 'size_mismatch'


def test_missing_file_is_unreadable(tmp_path):
    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_path(tmp_path / 'missing.bin')
    assert exc.value.code == 'unreadable'


@pytest.mark.parametrize('offset,length', [(-1, 1), (0, -1), (11, 0), (True, 1), (1.5, 1)])
def test_invalid_ranges_rejected(tmp_path, offset, length):
    write(tmp_path / 'a.bin', b'0123456789')
    with VerifiedArtifactReader.open_path(tmp_path / 'a.bin') as reader:
        with pytest.raises(ArtifactBytesError) as exc:
            reader.read(offset, length)
        assert exc.value.code == 'range_invalid'


def test_clipping_and_strict_end(tmp_path):
    write(tmp_path / 'a.bin', b'0123456789')
    with VerifiedArtifactReader.open_path(tmp_path / 'a.bin') as reader:
        assert reader.read(8, 100) == b'89'
        assert reader.read(10, 5) == b''
        with pytest.raises(ArtifactBytesError) as exc:
            reader.read(8, 100, clip=False)
        assert exc.value.code == 'range_invalid'


def test_read_cap(tmp_path):
    write(tmp_path / 'a.bin', b'x')
    with VerifiedArtifactReader.open_path(tmp_path / 'a.bin') as reader:
        with pytest.raises(ArtifactBytesError) as exc:
            reader.read(0, MAX_READ_BYTES + 1)
        assert exc.value.code == 'read_too_large'


def test_mutation_after_verification_detected(tmp_path):
    path = tmp_path / 'a.bin'
    write(path, b'0123456789')
    reader = VerifiedArtifactReader.open_path(path)
    time.sleep(0.01)  # inherent: lets the file's mtime tick past the one recorded when the reader opened it
    with path.open('ab') as stream:
        stream.write(b'tail')
    os.utime(path, ns=(time.time_ns(), time.time_ns() + 10_000_000))
    with pytest.raises(ArtifactBytesError) as exc:
        reader.read(0, 4)
    assert exc.value.code == 'artifact_changed'
    reader.close()


def test_closed_reader(tmp_path):
    write(tmp_path / 'a.bin', b'abc')
    reader = VerifiedArtifactReader.open_path(tmp_path / 'a.bin')
    reader.close()
    assert reader._block_digests == b''
    with pytest.raises(ArtifactBytesError) as exc:
        reader.read(0, 1)
    assert exc.value.code == 'closed'


def test_cancel_during_verification(tmp_path):
    write(tmp_path / 'a.bin', b'abc')
    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_path(tmp_path / 'a.bin', cancel=lambda: True)
    assert exc.value.code == 'cancelled'


def test_open_project_artifact_and_reject_traversal(tmp_path):
    data = b'MZ' + b'\x00' * 62
    digest = hashlib.sha256(data).hexdigest()
    (tmp_path / 'artifacts').mkdir()
    (tmp_path / 'artifacts' / f'{digest}.bin').write_bytes(data)
    good = Artifact(side='older', name='ü name.dll', sha256=digest, size=len(data),
                    relative_path=f'artifacts/{digest}.bin')
    with VerifiedArtifactReader.open_artifact(good, tmp_path) as reader:
        assert reader.read(0, 2) == b'MZ'
    bad = good.model_copy(update={'relative_path': 'artifacts/missing.bin'})
    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_artifact(bad, tmp_path)
    assert exc.value.code == 'unreadable'


def test_in_place_edit_with_restored_mtime_is_detected(tmp_path, monkeypatch):
    from patchtrace import artifact_bytes

    path = tmp_path / 'a.bin'
    path.write_bytes(b'AAAA')
    stamp = path.stat().st_mtime_ns
    with VerifiedArtifactReader.open_path(path, hashlib.sha256(b'AAAA').hexdigest()) as reader:
        # Creation time on Windows, or coarse filesystem change-time resolution, can leave all metadata equal.
        monkeypatch.setattr(artifact_bytes, '_stat_key', lambda _stream: reader._stat)
        with path.open('r+b') as handle:
            handle.write(b'BBBB')
        os.utime(path, ns=(stamp, stamp))
        with pytest.raises(ArtifactBytesError) as info:
            reader.read(0, 4)
        assert info.value.code == 'artifact_changed'


def test_change_between_hash_chunks_is_detected(tmp_path):
    path = tmp_path / 'big.bin'
    write(path, b'A' * (2 * 1024 * 1024 + 10))
    calls = []

    def cancel():
        calls.append(1)
        if len(calls) == 2:  # runs after the first chunk is hashed
            with path.open('r+b') as stream:
                stream.write(b'B' * 4096)
            os.utime(path, ns=(time.time_ns(), time.time_ns() + 10_000_000))
        return False

    with pytest.raises(ArtifactBytesError) as exc:
        VerifiedArtifactReader.open_path(path, cancel=cancel)
    assert exc.value.code == 'artifact_changed'


class ObservedStream:
    """Observe actual verification IO while preserving the real handle and filesystem behavior."""
    def __init__(self, stream, after_read=None, max_bytes=None):
        self.stream = stream
        self.requests = []
        self.after_read = after_read
        self.max_bytes = max_bytes

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read(self, size):
        self.requests.append(size)
        data = self.stream.read(size if self.max_bytes is None else min(size, self.max_bytes))
        if self.after_read is not None:
            self.after_read()
        return data


@pytest.mark.parametrize('offset,length', [(4093, 8), (0, 0), (8191, 7), (4096, 4096)])
def test_verified_ranges_cross_blocks_and_clip_exactly(tmp_path, offset, length):
    data = bytes(range(256)) * 33
    path = tmp_path / 'blocks.bin'
    write(path, data)
    with VerifiedArtifactReader.open_path(path) as reader:
        assert reader.read(offset, length) == data[offset:offset + length]


def test_scalar_reads_verify_only_touched_blocks(tmp_path):
    from patchtrace.artifact_bytes import VERIFY_BLOCK_BYTES

    path = tmp_path / 'blocks.bin'
    write(path, b'A' * (3 * VERIFY_BLOCK_BYTES + 17))
    with VerifiedArtifactReader.open_path(path) as reader:
        observed = ObservedStream(reader._stream)
        reader._stream = observed
        assert reader.read(VERIFY_BLOCK_BYTES + 11, 1) == b'A'
        assert observed.requests == [VERIFY_BLOCK_BYTES]
        assert len(reader._block_digests) == 4 * hashlib.sha256().digest_size
        observed.requests.clear()
        assert reader.read(reader.size, 0) == b''
        assert observed.requests == []


def test_boundary_read_rejects_changed_second_block_with_equal_metadata(tmp_path, monkeypatch):
    from patchtrace import artifact_bytes

    block = artifact_bytes.VERIFY_BLOCK_BYTES
    path = tmp_path / 'blocks.bin'
    write(path, b'A' * block + b'B' * block)
    with VerifiedArtifactReader.open_path(path) as reader:
        monkeypatch.setattr(artifact_bytes, '_stat_key', lambda _stream: reader._stat)
        with path.open('r+b') as stream:
            stream.seek(block)
            stream.write(b'C')
        # The unchanged requested block remains usable; the changed block never returns guessed bytes.
        assert reader.read(0, 1) == b'A'
        with pytest.raises(ArtifactBytesError) as exc:
            reader.read(block - 1, 2)
        assert exc.value.code == 'artifact_changed'


def test_change_during_read_is_checked_after_reading(tmp_path):
    path = tmp_path / 'blocks.bin'
    write(path, b'A' * 32)
    with VerifiedArtifactReader.open_path(path) as reader:
        def mutate():
            with path.open('ab') as stream:
                stream.write(b'tail')
        reader._stream = ObservedStream(reader._stream, after_read=mutate)
        with pytest.raises(ArtifactBytesError) as exc:
            reader.read(0, 1)
        assert exc.value.code == 'artifact_changed'


def test_short_os_reads_preserve_block_alignment_and_exact_ranges(tmp_path, monkeypatch):
    from patchtrace import artifact_bytes

    path = tmp_path / 'short.bin'
    data = bytes(range(256)) * (artifact_bytes.HASH_CHUNK // 256 + 17)
    digest = write(path, data)
    fdopen = artifact_bytes.os.fdopen
    monkeypatch.setattr(artifact_bytes.os, 'fdopen',
                        lambda *args, **kwargs: ObservedStream(fdopen(*args, **kwargs), max_bytes=333))
    with VerifiedArtifactReader.open_path(path, digest) as reader:
        assert reader.read(4093, 13) == data[4093:4106]
        assert reader.read(artifact_bytes.HASH_CHUNK - 2, 17) == data[
            artifact_bytes.HASH_CHUNK - 2:artifact_bytes.HASH_CHUNK + 15]
