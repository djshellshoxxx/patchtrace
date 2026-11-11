"""ACQ-12: identification's documented validator and AMD64/PE32+ gate."""
import struct
from pathlib import Path

import pytest

from patchtrace import ingestion
from patchtrace.acquisition import quarantine
from patchtrace.sample import synthetic_pe


def test_acq12_identification_spec_names_validate_pe():
    spec = Path(__file__).resolve().parents[1] / 'docs' / 'specs' / 'acquisition.md'
    row = next(line for line in spec.read_text(encoding='utf-8').splitlines()
               if line.startswith('5. Identification:'))
    assert 'ingestion.validate_pe' in row
    assert quarantine.validate_pe is ingestion.validate_pe


@pytest.mark.parametrize('machine,magic,expected', [
    (0x8664, 0x20B, 'pe'),
    (0x14C, 0x20B, 'unknown'),
    (0xAA64, 0x20B, 'unknown'),
    (0x8664, 0x10B, 'unknown'),
], ids=['amd64', 'x86', 'arm64', 'pe32'])
def test_acq12_identification_requires_amd64_pe32plus(tmp_path, machine, magic, expected):
    data = bytearray(synthetic_pe(0))
    offset = struct.unpack_from('<I', data, 0x3C)[0]
    struct.pack_into('<H', data, offset + 4, machine)
    struct.pack_into('<H', data, offset + 24, magic)
    path = tmp_path / 'synthetic.bin'
    path.write_bytes(data)
    assert quarantine.identify(path) == (expected, machine)
