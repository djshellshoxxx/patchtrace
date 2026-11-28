"""Known-answer and receipt checks. Only the Windows-specific case invokes system FDI."""
import ctypes as ct
import hashlib
import json
import struct
import sys
import zlib
from types import SimpleNamespace

import pytest

from tools import check_package_fdi_decoder as probe


def test_authored_fixture_contains_one_mszip_text_file():
    data = probe.cabinet_fixture()
    header = struct.unpack_from('<4sIIIIIBBHHHHH', data)
    assert header == (b'MSCF', 0, len(data), 0, 44, 0, 3, 1, 1, 1, 0, 23, 0)
    block, count, compression = struct.unpack_from('<IHH', data, 36)
    assert (count, compression) == (1, 1)
    size, offset, folder = struct.unpack_from('<IIH', data, 44)
    assert (offset, folder, data[60:block]) == (0, 0, b'readme.txt\0')
    checksum, length, expanded = struct.unpack_from('<IHH', data, block)
    chunk = data[block + 8:]
    assert (checksum, length, expanded, chunk[:2]) == (0, len(chunk), size, b'CK')
    assert zlib.decompress(chunk[2:], -15) == b'PatchTrace cabinet integration check.\r\n'


def test_callbacks_never_open_external_files_or_write_beyond_fixture():
    io = probe._FixtureIO(probe.cabinet_fixture())
    opened = io.callback(probe.abi.PFNOPEN, io.open, -1)
    name = ct.create_string_buffer(b'other.cab')
    assert opened(name, 0, 0) == -1 and io.failed and not io.cursors
    io = probe._FixtureIO(probe.cabinet_fixture())
    assert not io.output_open
    write = io.callback(probe.abi.PFNWRITE, io.write, 0xffffffff)
    assert write(999, None, 99) == 0xffffffff and io.failed and not io.output


@pytest.mark.parametrize('fault', ['none', 'tail', 'stderr', 'wrong-output', 'bad-exit', 'timeout'])
def test_decoder_check_only_credits_the_complete_supervised_known_answer(monkeypatch, fault):
    expected = probe._expected(probe.cabinet_fixture())
    raw = (json.dumps(expected, sort_keys=True) + '\r\n').encode()
    monkeypatch.setattr(probe, 'require_supported_platform', lambda: 'windows-amd64')

    def run(argv, **kwargs):
        assert argv[-1] == '--worker' and kwargs['memory_limit_bytes'] == 512 * 2**20
        assert kwargs['max_output_bytes'] == 4096 and kwargs['timeout_seconds'] == 45
        return SimpleNamespace(returncode=int(fault == 'bad-exit'), reason='timeout' if fault == 'timeout' else None,
                               stderr_total=int(fault == 'stderr'), stdout_total=len(raw) + int(fault == 'tail'),
                               log_bytes=raw if fault != 'wrong-output' else raw.replace(b'cabinet.dll', b'not-fdi.dll'))

    monkeypatch.setattr(probe, 'run_process', run)
    if fault == 'none':
        assert probe.check() == expected
    else:
        with pytest.raises(ValueError, match='known-answer'):
            probe.check()


@pytest.mark.skipif(sys.platform != 'win32', reason='installed Windows system cabinet library')
def test_installed_system_fdi_decodes_authored_text_and_rejects_false_signature():
    receipt = probe.check()
    assert receipt['text_sha256'] == hashlib.sha256(b'PatchTrace cabinet integration check.\r\n').hexdigest()
    assert receipt['files'] == 1 and receipt['malformed_header_rejected'] is True
