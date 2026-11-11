"""SPEC-33 s5.3/s6.3/s6.4: `.pdata`, base relocations, export RVAs and relocation-masked body hashes. Real
self-made fixture (clang+lld) plus synthetic PEs from tests/pe_builder.py; nothing is executed."""
from __future__ import annotations

import hashlib
import struct
import sys

import pytest
from pe_builder import RDATA, PeSpec, SectionSpec, build_pe, build_pe_ex
from tier_w_builders import ROOT, TIER_W_FIXTURES

from patchtrace import artifact_bytes
from patchtrace.artifact_bytes import MAX_READ_BYTES

sys.path.insert(0, str(ROOT))
from tools.calibration.tier_w import msf, pe_tables  # noqa: E402
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


# -- PE-2 / PE-3 (audit 20261015): the fixes the product readers got, applied to this copy ------------------------------
def test_directory_larger_than_one_read_is_read_completely(tmp_path):
    # A real 17 MiB .reloc: two blocks, the end-of-table zero block, then padding that ends in a marker. One reader
    # call is capped at MAX_READ_BYTES (16 MiB), so the directory can only be read in pieces.
    size = MAX_READ_BYTES + 1024 * 1024
    head = (struct.pack('<II', 0x1000, 12) + struct.pack('<2H', 0xA010, 0x3020)
            + struct.pack('<II', 0x2000, 12) + struct.pack('<2H', 0xA000, 0x0000))
    marker = bytes(range(1, 65))
    reloc = head + bytes(size - len(head) - len(marker)) + marker
    with PeView(synth(tmp_path / 'big.pe', reloc=reloc)) as view:
        assert view.overview.directory('BaseReloc').size == size
        assert view.relocations() == ([0x1010, 0x1020, 0x2000], [8, 4, 8])
        data = view.read_rva(0x4000, size)
        assert len(data) == size and data[:len(head)] == head and data[-len(marker):] == marker
        assert hashlib.sha256(data).digest() == hashlib.sha256(reloc).digest()


def test_small_pieces_give_the_same_tables_as_one_read(tmp_path, monkeypatch):
    # Piece boundaries fall inside relocation blocks, .pdata entries and a function body.
    reloc = b''.join(struct.pack('<II', 0x1000 + 0x1000 * page, 8 + 2 * 30)
                     + struct.pack('<30H', *(0xA000 | 8 * i for i in range(30))) for page in range(3))
    pdata = b''.join(rf(0x1000 + 0x10 * i, 0x1010 + 0x10 * i) for i in range(12))
    path = synth(tmp_path / 'p.pe', reloc=reloc, pdata=pdata, text=bytes(range(256)))
    with PeView(path) as view:
        whole = (view.relocations(), view.runtime_functions(), view.read_rva(0x0F80, 0x200),
                 masked_body_sha256(view, [(0x1000, 0x1100)], view.relocations()))
        monkeypatch.setattr(artifact_bytes, 'MAX_READ_BYTES', 64)
        monkeypatch.setattr(pe_tables, 'MAX_READ_BYTES', 64, raising=False)
        pieces = (view.relocations(), view.runtime_functions(), view.read_rva(0x0F80, 0x200),
                  masked_body_sha256(view, [(0x1000, 0x1100)], view.relocations()))
    assert pieces == whole
    assert len(whole[0][0]) == 90 and len(whole[1]) == 12 and whole[2] == bytes(0x80) + bytes(range(256)) + bytes(0x80)


@pytest.mark.parametrize('call', [
    lambda view: view.read_rva(0x1000, 2),
    lambda view: view.runtime_functions(),
    lambda view: view.relocations(),
    lambda view: masked_body_sha256(view, [(0x1000, 0x1010)], ([], [])),
], ids=['read_rva', 'pdata', 'reloc', 'body_hash'])
def test_failed_read_is_a_pe_table_error(tmp_path, call):
    reloc = struct.pack('<II', 0x1000, 12) + struct.pack('<2H', 0xA010, 0x0000)
    with PeView(synth(tmp_path / 'c.pe', reloc=reloc, pdata=rf(0x1000, 0x1010))) as view:
        view.reader.close()   # every later read fails with ArtifactBytesError('closed')
        with pytest.raises(PeTableError, match='closed'):
            call(view)


def test_unknown_relocation_types_warn_once_per_type(tmp_path):
    kinds = (5, 7, 11)
    count = 99_999
    entries = [(kinds[i % 3] << 12) | (i & 0xFFF) for i in range(count)] + [0]
    reloc = struct.pack('<II', 0x1000, 8 + 2 * len(entries)) + struct.pack(f'<{len(entries)}H', *entries)
    with PeView(synth(tmp_path / 'u.pe', reloc=reloc)) as view:
        before = len(view.warnings)
        starts, widths = view.relocations()
        assert view.warnings[before:] == [f'relocation type {kind} masked as 8 bytes' for kind in kinds]
        assert len(starts) == count and set(widths) == {8} and starts == sorted(starts)   # no entry was dropped
        view.relocations()
        assert len(view.warnings) == before + len(kinds)   # a second walk of the same table adds nothing
