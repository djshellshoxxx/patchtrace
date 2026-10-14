"""SectionMap, compare_overviews and the Authenticode adapter."""
from __future__ import annotations

import sys

import pytest
from pe_builder import PeSpec, SectionSpec, build_pe

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import (
    FileRange,
    PeOverview,
    SectionInfo,
    SectionMap,
    compare_overviews,
    inspect_pe,
)
from patchtrace.pe_overview import authenticode as auth


def sec(name, va, vsize, roff, rsize):
    return SectionInfo(name, va, vsize, roff, rsize, 0x60000020, (), None, 0, False)


def overview(sections, soh=0x200, size=0x2000):
    return PeOverview(size=size, sha256='0' * 64, status='ok', size_of_headers=soh, sections=tuple(sections))


def smap(sections, **kw) -> SectionMap:
    return overview(sections, **kw).section_map()


STD = [sec('.text', 0x1000, 0x180, 0x200, 0x200), sec('.data', 0x2000, 0x300, 0x400, 0x200)]


def test_header_region_maps_one_to_one():
    m = smap(STD)
    assert m.rva_to_file_ranges(0, 0x200) == (FileRange(0, 0x200),)
    assert m.rva_to_file_ranges(0x3C, 4) == (FileRange(0x3C, 4),)
    assert SectionMap.from_overview(overview(STD)) == m


def test_header_region_end_and_gap():
    m = smap(STD)
    assert m.rva_to_file_ranges(0x1FF, 2) is None  # runs into the gap after headers
    assert m.rva_to_file_ranges(0x200, 1) is None


def test_inside_section():
    m = smap(STD)
    assert m.rva_to_file_ranges(0x1000, 4) == (FileRange(0x200, 4),)
    assert m.rva_to_file_ranges(0x1010, 0x20) == (FileRange(0x210, 0x20),)
    assert m.rva_to_file_ranges(0x117F, 1) == (FileRange(0x37F, 1),)
    assert SectionMap.rva_to_offset(m, 0x2005) == 0x405


def test_virtual_only_tail_returns_none():
    m = smap([sec('.bss', 0x1000, 0x800, 0x200, 0x100)])
    assert m.rva_to_file_ranges(0x1000, 0x100) == (FileRange(0x200, 0x100),)
    assert m.rva_to_file_ranges(0x1000, 0x101) is None
    assert m.rva_to_file_ranges(0x10FF, 2) is None
    assert m.rva_to_file_ranges(0x1100, 1) is None
    assert m.rva_to_file_ranges(0x1700, 0x100) is None


def test_fully_virtual_section_none_and_raw_padding_unmapped():
    m = smap([sec('.bss', 0x1000, 0x800, 0, 0), sec('.pad', 0x2000, 0x10, 0x400, 0x200)])
    assert m.rva_to_file_ranges(0x1000, 1) is None
    assert m.rva_to_file_ranges(0x2000, 0x10) == (FileRange(0x400, 0x10),)
    assert m.rva_to_file_ranges(0x2010, 1) is None  # raw padding past VirtualSize is not mapped


def test_span_two_contiguous_sections():
    m = smap([sec('.a', 0x1000, 0x100, 0x200, 0x100), sec('.b', 0x1100, 0x100, 0x300, 0x100)])
    assert m.rva_to_file_ranges(0x10F0, 0x20) == (FileRange(0x2F0, 0x10), FileRange(0x300, 0x10))
    assert m.rva_to_file_ranges(0x1000, 0x200) == (FileRange(0x200, 0x100), FileRange(0x300, 0x100))


def test_span_across_gap_or_into_virtual_tail_is_none():
    m = smap([sec('.a', 0x1000, 0x100, 0x200, 0x100), sec('.b', 0x2000, 0x100, 0x300, 0x100)])
    assert m.rva_to_file_ranges(0x10F0, 0x20) is None
    assert m.rva_to_file_ranges(0x10F0, 0x1000) is None
    m = smap([sec('.a', 0x1000, 0x200, 0x200, 0x100), sec('.b', 0x1200, 0x100, 0x300, 0x100)])
    assert m.rva_to_file_ranges(0x10F0, 0x120) is None  # .a virtual tail between the two


def test_span_header_into_adjacent_first_section():
    m = smap([sec('.a', 0x200, 0x100, 0x200, 0x100)])
    assert m.rva_to_file_ranges(0x1F0, 0x20) == (FileRange(0x1F0, 0x10), FileRange(0x200, 0x10))


def test_overlapping_sections_are_ambiguous():
    m = smap([sec('.a', 0x1000, 0x200, 0x200, 0x200), sec('.b', 0x1100, 0x200, 0x400, 0x200)])
    assert m.rva_to_file_ranges(0x1000, 0x10) == (FileRange(0x200, 0x10),)
    assert m.rva_to_file_ranges(0x1100, 4) is None
    assert m.rva_to_file_ranges(0x11FF, 1) is None
    assert m.rva_to_file_ranges(0x1000, 0x200) is None  # range runs into the overlap
    assert m.rva_to_file_ranges(0x1200, 0x100) == (FileRange(0x500, 0x100),)


def test_section_overlapping_headers_is_ambiguous():
    m = smap([sec('.a', 0x100, 0x400, 0x200, 0x400)])
    assert m.rva_to_file_ranges(0x80, 4) == (FileRange(0x80, 4),)
    assert m.rva_to_file_ranges(0x180, 4) is None


@pytest.mark.parametrize('rva,length', [(-1, 4), (0x1000, -1), (0xFFFFFFFF, 2), (0x1_0000_0000, 1),
                                        (0xFFFFF000, 0x2000), (2 ** 70, 1), (0x1000, 2 ** 70)])
def test_negative_and_overflow_return_none(rva, length):
    assert smap(STD).rva_to_file_ranges(rva, length) is None


def test_non_integer_and_zero_length():
    m = smap(STD)
    assert m.rva_to_file_ranges(0x1000, 0) == ()
    assert m.rva_to_file_ranges('4096', 4) is None  # type: ignore[arg-type]
    assert m.rva_to_file_ranges(True, 4) is None  # type: ignore[arg-type]


def test_ranges_clipped_to_actual_file_size():
    m = smap(STD, size=0x480)  # file ends inside .data raw data
    assert m.rva_to_file_ranges(0x2000, 0x80) == (FileRange(0x400, 0x80),)
    assert m.rva_to_file_ranges(0x2000, 0x81) is None


def test_empty_and_missing_sections():
    assert smap([], soh=0).rva_to_file_ranges(0, 1) is None
    assert PeOverview(size=10, sha256='', status='not_pe').section_map().rva_to_file_ranges(0, 1) is None


def test_map_from_real_inspection_matches_bytes(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.text', bytes(range(256)) * 2), SectionSpec('.data', b'DATA' * 64)])
    data = build_pe(spec)
    path = tmp_path / 'x.exe'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        ov = inspect_pe(reader)
        m = ov.section_map()
        ranges = m.rva_to_file_ranges(ov.sections[1].virtual_address + 4, 8)
        assert ranges is not None and len(ranges) == 1
        assert reader.read(ranges[0].file_offset, ranges[0].length) == b'DATA' * 2


# -- comparison ---------------------------------------------------------------------------------------

def inspect_bytes(tmp_path, data, name):
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader)


def by_field(rows):
    return {r.field: r for r in rows}


def test_identical_files_compare_unchanged(tmp_path):
    data = build_pe(PeSpec(imports={'k.dll': ['f']}, exports=('x', ['a']), rsds=(bytes(16), 1, 'a.pdb')))
    a = inspect_bytes(tmp_path, data, 'a.exe')
    b = inspect_bytes(tmp_path, data, 'b.exe')
    rows = compare_overviews(a, b)
    assert rows and all(r.status in ('unchanged', 'unavailable') for r in rows)
    assert by_field(rows)['SHA-256'].status == 'unchanged' and by_field(rows)['Section names'].status == 'unchanged'
    assert all(r.provenance and r.reason for r in rows)
    assert by_field(rows)['TLS directory'].status == 'unchanged'


def test_changed_fields_and_import_summary(tmp_path):
    old = inspect_bytes(tmp_path, build_pe(PeSpec(imports={'a.dll': ['f'], 'b.dll': ['g']}, timestamp=1,
                                                 overlay=b'x' * 10)), 'o.exe')
    new = inspect_bytes(tmp_path, build_pe(PeSpec(
        pe32plus=False, imports={'b.dll': ['g'], 'C.dll': ['h', 'i']}, exports=('x', ['a']), timestamp=2,
        sections=[SectionSpec('.text', b'\x90' * 64), SectionSpec('.extra', b'1' * 64)],
        cert_payloads=[b'sig'])), 'n.exe')
    rows = by_field(compare_overviews(old, new))
    for name in ('SHA-256', 'Machine', 'Optional header format', 'Image base', 'Section count', 'Section names',
                 'COFF timestamp (untrusted)', 'File size (bytes)', 'Certificate table present (signature not verified)',
                 'Overlay present', 'Imported function count'):
        assert rows[name].status == 'changed', name
    assert rows['Imported DLLs'].reason == 'added: c.dll; removed: a.dll'
    assert rows['Overlay present'].older == 'yes' and rows['Overlay present'].newer == 'no'
    assert rows['Export count'].status == 'unavailable' and 'older' in rows['Export count'].reason
    assert rows['Export count'].older == '' and rows['Export count'].newer == '1'
    assert rows['Machine'].provenance == 'COFF file header'
    assert rows['File size (bytes)'].provenance == 'recorded file identity'
    assert rows['Section names'].provenance == 'section table'
    assert rows['Entrypoint RVA'].status == 'unchanged'


def test_unavailable_when_not_pe(tmp_path):
    good = inspect_bytes(tmp_path, build_pe(), 'g.exe')
    bad = inspect_bytes(tmp_path, b'not a pe file at all', 'b.bin')
    rows = by_field(compare_overviews(good, bad))
    assert rows['Machine'].status == 'unavailable' and 'newer' in rows['Machine'].reason
    assert rows['SHA-256'].status == 'changed' and rows['File size (bytes)'].status == 'changed'
    both = by_field(compare_overviews(bad, bad))
    assert both['Machine'].status == 'unavailable' and both['SHA-256'].status == 'unchanged'


def test_no_import_directory_vs_imports(tmp_path):
    a = inspect_bytes(tmp_path, build_pe(), 'a.exe')
    b = inspect_bytes(tmp_path, build_pe(PeSpec(imports={'k.dll': ['f']})), 'b.exe')
    rows = by_field(compare_overviews(a, b))
    assert rows['Imported DLLs'].status == 'changed' and rows['Imported DLLs'].older == '(none)'


# -- Authenticode ---------------------------------------------------------------------------------------

@pytest.mark.parametrize('hr,status', [
    (0, 'trusted_no_revocation_check'),
    (0x800B0100, 'unsigned'),
    (0x800B0003, 'unknown'),
    (0x800B0001, 'unknown'),
    (0x80096010, 'invalid'),
    (0x800B0109, 'untrusted'),
    (0x800B0111, 'untrusted'),
    (0x800B0101, 'untrusted'),
    (0x12345678, 'unknown'),
    (-2146762496, 'unsigned'),  # signed 32-bit form of 0x800B0100
    (1, 'unknown'),
])
def test_classify_hresult(hr, status):
    assert auth.classify_hresult(hr) == status


def test_trust_result_is_data_and_statuses_documented():
    res = auth.TrustResult('unsigned', 0x800B0100, 'x')
    assert res.to_dict()['status'] == 'unsigned'
    assert set(auth.STATUSES) >= {auth.classify_hresult(h) for h in (0, 0x800B0100, 1)}
    assert all('fully valid' not in d for d in auth._DETAIL.values())


@pytest.mark.skipif(sys.platform == 'win32', reason='non-Windows behavior')
def test_non_windows_is_unavailable_without_windll(tmp_path):
    path = tmp_path / 'a.exe'
    path.write_bytes(build_pe())
    res = auth.verify_authenticode(path)
    assert res.status == 'unavailable' and res.hresult is None


@pytest.mark.skipif(sys.platform != 'win32', reason='WinVerifyTrust is Windows only')
def test_native_unsigned_file_does_not_raise(tmp_path):
    path = tmp_path / 'unsigned.exe'
    path.write_bytes(build_pe())
    res = auth.verify_authenticode(path)
    assert res.status in ('unsigned', 'unknown')
