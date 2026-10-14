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
    time.sleep(0.01)
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


def test_in_place_edit_with_restored_mtime_is_detected(tmp_path):
    import hashlib
    import os
    import sys

    import pytest

    from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
    if sys.platform == 'win32':
        pytest.skip('Windows st_ctime is creation time; documented residual risk')
    path = tmp_path / 'a.bin'
    path.write_bytes(b'AAAA')
    stamp = path.stat().st_mtime_ns
    reader = VerifiedArtifactReader.open_path(path, hashlib.sha256(b'AAAA').hexdigest())
    with path.open('r+b') as handle:
        handle.write(b'BBBB')
    os.utime(path, ns=(stamp, stamp))
    with pytest.raises(ArtifactBytesError) as info:
        reader.read(0, 4)
    assert info.value.code == 'artifact_changed'
    reader.close()
