"""CORE-10: reject bad headers before writing an input copy; never execute inputs."""
import struct

import pytest

from patchtrace import ingestion
from patchtrace.sample import synthetic_pe


@pytest.mark.parametrize('kind', [
    'dos', 'short', 'offset', 'signature', 'machine', 'optional', 'magic', 'sections',
], ids=['dos', 'short', 'offset', 'signature', 'machine', 'optional', 'magic', 'sections'])
def test_core10_invalid_prefix_is_refused_before_any_copy_write(tmp_path, monkeypatch, kind):
    data = bytearray(synthetic_pe(0))
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    if kind == 'dos':
        data = bytearray(b'x' * (2 * 1024 * 1024))
    elif kind == 'short':
        data = bytearray(b'MZ')
    elif kind == 'offset':
        struct.pack_into('<I', data, 0x3C, len(data))
    elif kind == 'signature':
        data[offset:offset + 4] = b'NOPE'
    elif kind == 'machine':
        struct.pack_into('<H', data, offset + 4, 0x14C)
    elif kind == 'optional':
        struct.pack_into('<H', data, offset + 20, 0)
    elif kind == 'magic':
        struct.pack_into('<H', data, offset + 24, 0x10B)
    else:
        struct.pack_into('<H', data, offset + 6, 0)
    source = tmp_path / 'input.bin'
    source.write_bytes(data)
    writes = []
    real_fdopen = ingestion.os.fdopen

    class Writer:
        def __init__(self, stream):
            self.stream = stream
        def __getattr__(self, name):
            return getattr(self.stream, name)
        def write(self, chunk):
            writes.append(len(chunk))
            return self.stream.write(chunk)
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return self.stream.__exit__(*args)

    def fdopen(fd, mode, *args, **kwargs):
        stream = real_fdopen(fd, mode, *args, **kwargs)
        return Writer(stream) if mode == 'wb' else stream

    monkeypatch.setattr(ingestion.os, 'fdopen', fdopen)
    root = tmp_path / 'case'
    with pytest.raises(ValueError, match='^PT-INPUT:'):
        ingestion.inspect_artifact(source, 'older', root)
    assert writes == []
    assert list((root / 'artifacts').iterdir()) == []


def test_core10_header_beyond_prefix_still_gets_full_validation(tmp_path):
    original = synthetic_pe(0)
    old_offset = struct.unpack_from('<I', original, 0x3C)[0]
    offset = 65536
    data = bytearray(original)
    data.extend(b'\0' * (offset + 512 - len(data)))
    data[offset:offset + 384] = original[old_offset:old_offset + 384]
    struct.pack_into('<I', data, 0x3C, offset)
    source = tmp_path / 'late-header.bin'
    source.write_bytes(data)
    artifact = ingestion.inspect_artifact(source, 'older', tmp_path / 'valid')
    assert (tmp_path / 'valid' / artifact.relative_path).read_bytes() == data
    data[offset:offset + 4] = b'NOPE'
    source.write_bytes(data)
    with pytest.raises(ValueError, match='missing PE signature'):
        ingestion.inspect_artifact(source, 'newer', tmp_path / 'invalid')
    assert list((tmp_path / 'invalid' / 'artifacts').iterdir()) == []
