"""SPEC-33 s5.3/s6.3/s6.4: `.pdata`, base relocations, export RVAs and relocation-masked body hashes. Real
self-made fixture (clang+lld) plus synthetic PEs from tests/pe_builder.py; nothing is executed."""
from __future__ import annotations

import struct
import sys

import pytest
from pe_builder import RDATA, PeSpec, SectionSpec, build_pe, build_pe_ex
from tier_w_builders import ROOT, TIER_W_FIXTURES

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import msf  # noqa: E402
from tools.calibration.tier_w.pe_tables import PeTableError, PeView, masked_body_sha256  # noqa: E402


def test_fixture_tables_agree_with_pdb():
    procs = {p.rva: p for p in msf.read_pdb(TIER_W_FIXTURES / 'tiny_v1.pdb').procedures}
    with PeView(TIER_W_FIXTURES / 'tiny_v1.pe') as view:
        assert view.machine == 'x64' and view.image_base == 0x180000000
        pdata = view.runtime_functions()
        assert len(pdata) == 7 and not any(r.chained for r in pdata)
        assert all(r.end - r.begin == procs[r.begin].size for r in pdata)  # .pdata extent == private size
        starts, widths = view.relocations()
        assert starts == [0x2000, 0x2008, 0x2010, 0x2018] and widths == [8, 8, 8, 8]
        exports = view.export_rvas()
        names = {p.name: p.rva for p in procs.values()}
        assert names['checksum'] in exports and names['clamp_index'] not in exports and 0x2000 in exports
        masked = masked_body_sha256(view, [(0x2000, 0x2020)], (starts, widths))
        assert masked != masked_body_sha256(view, [(0x2000, 0x2020)], ([], []))
        assert masked == masked_body_sha256(view, [(0x2000, 0x2010), (0x2010, 0x2020)], (starts, widths))


def synth(path, *, pdata=b'', xdata=b'\x01\0\0\0', reloc=b'', text=b'\xcc' * 0x100, bss=False):
    sections = [SectionSpec('.text', text), SectionSpec('.xdata', xdata, RDATA), SectionSpec('.pdata', pdata or
                b'\0' * 12, RDATA), SectionSpec('.reloc', reloc or b'\0' * 8, RDATA)]
    if bss:
        sections.append(SectionSpec('.bss', b'', 0xC0000080, virtual_size=0x40, raw_size=0))
    extra = {3: (0x3000, len(pdata)) if pdata else (0, 0), 5: (0x4000, len(reloc)) if reloc else (0, 0)}
    path.write_bytes(build_pe(PeSpec(sections=sections, extra_directories=extra, kind='dll')))
    return path


def rf(begin, end, unwind=0x2000):
    return struct.pack('<III', begin, end, unwind)


def test_pdata_chained_indirect_and_range(tmp_path):
    chained = b'\x01\0\0\0' + b'\x21\0\0\0'  # version 1; second record has UNW_FLAG_CHAININFO
    path = synth(tmp_path / 'a.pe', pdata=rf(0x1000, 0x1010) + rf(0x1010, 0x1020, 0x2004) + rf(0x1020, 0x1030, 0x3001)
                 + rf(0, 0), xdata=chained)
    with PeView(path) as view:
        assert [(r.begin, r.chained) for r in view.runtime_functions()] == [(0x1000, False), (0x1010, True),
                                                                            (0x1020, True)]
    bad = synth(tmp_path / 'b.pe', pdata=rf(0x1010, 0x1000))
    with PeView(bad) as view, pytest.raises(PeTableError, match='pdata'):
        view.runtime_functions()


def test_relocation_masking_and_errors(tmp_path):
    reloc = struct.pack('<II', 0x1000, 16) + struct.pack('<4H', 0xA010, 0x3020, 0x5030, 0x0000)
    one = synth(tmp_path / 'one.pe', reloc=reloc)
    text = bytearray(b'\xcc' * 0x100)
    text[0x10:0x18] = b'\x11' * 8   # DIR64 target: differs between the two images
    text[0x20:0x24] = b'\x22' * 4   # HIGHLOW
    text[0x30:0x38] = b'\x33' * 8   # unknown type 5, masked as 8 bytes
    two = synth(tmp_path / 'two.pe', reloc=reloc, text=bytes(text))
    hashes = []
    for path in (one, two):
        with PeView(path) as view:
            relocs = view.relocations()
            assert relocs == ([0x1010, 0x1020, 0x1030], [8, 4, 8])
            assert any('type 5' in w for w in view.warnings)
            hashes.append(masked_body_sha256(view, [(0x1000, 0x1040)], relocs))
    assert hashes[0] == hashes[1]
    text[0x3A] = 0x44                # outside every relocation: the hash must change
    three = synth(tmp_path / 'three.pe', reloc=reloc, text=bytes(text))
    with PeView(three) as view:
        assert masked_body_sha256(view, [(0x1000, 0x1040)], view.relocations()) != hashes[0]
    bad = synth(tmp_path / 'bad.pe', reloc=struct.pack('<II', 0x1000, 4))
    with PeView(bad) as view, pytest.raises(PeTableError, match='relocation'):
        view.relocations()


def test_exports_exclude_forwarders(tmp_path):
    data, info = build_pe_ex(PeSpec(kind='dll', exports=('x.dll', ['a', 'b'])))
    blob = bytearray(data)
    edir = info['export_dir_off']
    funcs_rva, = struct.unpack_from('<I', blob, edir + 28)
    dir_rva, = struct.unpack_from('<I', blob, info['dir_off'])
    sec = next(s for s in info['sections'] if s[1] <= funcs_rva < s[1] + s[2])
    struct.pack_into('<I', blob, sec[3] + funcs_rva - sec[1], dir_rva + 4)   # first export -> forwarder string
    path = tmp_path / 'e.pe'
    path.write_bytes(bytes(blob))
    with PeView(path) as view:
        assert view.export_rvas() == frozenset({0x1000})


def test_bss_zero_fill_and_body_cap(tmp_path):
    path = synth(tmp_path / 'z.pe', bss=True)
    with PeView(path) as view:
        bss = next(s for s in view.sections() if s.name == '.bss')
        assert view.read_rva(bss.virtual_address, 0x40) == bytes(0x40)
        assert view.read_rva(0x1000, 2) == b'\xcc\xcc' and len(view.read_rva(0x10F0, 0x20)) == 0x20
        with pytest.raises(PeTableError, match='cap'):
            masked_body_sha256(view, [(0x1000, 0x1000 + 17 * 1024 * 1024)], ([], []))
        with pytest.raises(PeTableError):
            view.read_rva(2**32 - 4, 8)


def test_non_pe_rejected(tmp_path):
    path = tmp_path / 'n.pe'
    path.write_bytes(b'not a pe file at all' * 10)
    with pytest.raises(PeTableError):
        PeView(path)
    with pytest.raises(PeTableError):
        PeView(TIER_W_FIXTURES / 'tiny_v1.pe', expected_sha256='0' * 64)
