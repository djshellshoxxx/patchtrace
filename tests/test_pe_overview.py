"""PE overview inspection: well-formed images, hostile input, limits and cancellation."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from pe_builder import CODE, DATA, PeSpec, SectionSpec, build_pe, build_pe_ex

from patchtrace.artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe


def run(tmp_path: Path, data: bytes, name: str = 'sample.bin', **kw):
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_pe(reader, **kw)


def codes(ov) -> set[str]:
    return {w.code for w in ov.warnings}


def noise(n: int, seed: bytes = b'seed') -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(seed + struct.pack('<I', counter)).digest()
        counter += 1
    return bytes(out[:n])


# -- well formed images ------------------------------------------------------------------------

def test_pe32plus_exe_full_fields(tmp_path):
    spec = PeSpec(imports={'KERNEL32.dll': ['CreateFileW', 7], 'USER32.dll': ['MessageBoxA']},
                  exports=('lib.dll', ['zeta', 'alpha']), rsds=(bytes(range(16)), 3, 'C:\\build\\app.pdb'),
                  overlay=b'TAIL' * 50, cert_payloads=[b'sig' * 10])
    data, info = build_pe_ex(spec)
    ov = run(tmp_path, data)
    assert ov.status == 'ok' and ov.warnings == ()
    assert ov.size == len(data) and ov.sha256 == hashlib.sha256(data).hexdigest()
    assert ov.header_magic.startswith('4d5a')
    assert ov.pe_kind.kind == 'EXE' and ov.pe_kind.reason
    assert ov.machine.code == 0x8664 and ov.machine.name == 'AMD64'
    assert ov.optional_magic == 'PE32+'
    assert ov.image_base == 0x140000000 and ov.entrypoint_rva == 0x1000
    assert ov.entrypoint_va == 0x140001000
    assert ov.section_alignment == 0x1000 and ov.file_alignment == 0x200
    assert ov.size_of_headers == info['size_of_headers'] and ov.size_of_image == info['size_of_image']
    assert ov.subsystem.name == 'WINDOWS_CUI'
    assert 'DYNAMIC_BASE' in ov.dll_characteristics and 'EXECUTABLE_IMAGE' in ov.characteristics
    assert [s.name for s in ov.sections] == ['.text', '.idata']
    text = ov.sections[0]
    assert (text.virtual_address, text.virtual_size, text.raw_offset, text.raw_size) == (0x1000, 64, 0x200, 0x200)
    assert 'CODE' in text.flags and text.entropy is not None and text.sampled is False
    assert [d.name for d in ov.imports.dlls] == ['KERNEL32.dll', 'USER32.dll']
    assert ov.imports.dlls[0].functions == ('CreateFileW', '#7')
    assert ov.imports.total_dlls == 2 and ov.imports.total_functions == 3 and not ov.imports.truncated
    assert ov.exports.dll_name == 'lib.dll' and ov.exports.names == ('alpha', 'zeta') and ov.exports.count == 2
    assert ov.codeview.pdb_path == 'C:\\build\\app.pdb' and ov.codeview.age == 3
    assert ov.codeview.guid == '03020100-0504-0706-0809-0a0b0c0d0e0f'
    assert ov.certificates.present and ov.certificates.signature_status == 'not_verified'
    assert ov.certificates.file_offset == info['cert_off'] and len(ov.certificates.entries) == 1
    assert ov.certificates.entries[0].revision == 0x200 and ov.certificates.entries[0].cert_type == 2
    assert ov.directory('Debug').present and not ov.directory('TLS').present
    json.dumps(ov.to_dict())


def test_pe32_i386_dll(tmp_path):
    spec = PeSpec(pe32plus=False, kind='dll', imports={'a.dll': ['f1', 2, 'f3']}, exports=('b.dll', ['e']))
    ov = run(tmp_path, build_pe(spec))
    assert ov.status == 'ok'
    assert ov.optional_magic == 'PE32' and ov.machine.name == 'I386'
    assert ov.pe_kind.kind == 'DLL' and ov.image_base == 0x400000 and ov.entrypoint_va == 0x401000
    assert ov.imports.dlls[0].functions == ('f1', '#2', 'f3')
    assert ov.exports.names == ('e',)


def test_kinds_exe_dll_sys_and_unknown(tmp_path):
    assert run(tmp_path, build_pe(PeSpec(kind='exe'))).pe_kind.kind == 'EXE'
    assert run(tmp_path, build_pe(PeSpec(kind='dll'))).pe_kind.kind == 'DLL'
    sys_ov = run(tmp_path, build_pe(PeSpec(kind='sys')))
    assert sys_ov.pe_kind.kind == 'SYS' and sys_ov.subsystem.name == 'NATIVE'
    data, info = build_pe_ex(PeSpec(kind='exe'))
    patched = bytearray(data)
    struct.pack_into('<H', patched, info['e_lfanew'] + 4 + 18, 0)  # no characteristics
    assert run(tmp_path, bytes(patched)).pe_kind.kind == 'unknown'


def test_timestamp_is_labelled_untrusted(tmp_path):
    ov = run(tmp_path, build_pe(PeSpec(timestamp=0x5F000000)))
    assert ov.coff_timestamp.raw == 0x5F000000
    assert ov.coff_timestamp.iso_utc == '2020-07-04T04:05:20Z'
    assert 'untrusted' in ov.coff_timestamp.note.lower()
    zero = run(tmp_path, build_pe(PeSpec(timestamp=0)))
    assert zero.coff_timestamp.raw == 0 and zero.coff_timestamp.iso_utc is None


def test_unicode_and_space_file_names(tmp_path):
    ov = run(tmp_path, build_pe(), name='zażółć gęślą jaźń 文件.dll')
    assert ov.status == 'ok'


def test_section_name_sanitized(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.te\x01\xe9', b'\x90' * 16)])
    ov = run(tmp_path, build_pe(spec))
    assert ov.sections[0].name == '.te?\xe9'


# -- not PE and truncation ---------------------------------------------------------------------

@pytest.mark.parametrize('data', [b'', b'M', b'\x7fELF' + b'\0' * 100, b'ZM' + b'\0' * 100, b'PK\x03\x04' * 50])
def test_not_mz_is_not_pe(tmp_path, data):
    ov = run(tmp_path, data)
    assert ov.status == 'not_pe' and 'not_mz' in codes(ov)
    assert ov.sections is None and ov.machine is None


def test_mz_with_wrong_pe_signature(tmp_path):
    data, info = build_pe_ex(PeSpec())
    bad = bytearray(data)
    bad[info['e_lfanew']:info['e_lfanew'] + 4] = b'NE\0\0'
    ov = run(tmp_path, bytes(bad))
    assert ov.status == 'not_pe' and 'pe_signature_missing' in codes(ov)


def test_every_header_truncation_is_handled(tmp_path):
    spec = PeSpec(imports={'k.dll': ['f']}, cert_payloads=[b'x' * 16])
    data, info = build_pe_ex(spec)
    full_headers = info['section_table_off'] + 40 * len(info['sections'])
    seen_partial = False
    for cut in range(0, full_headers + 1):
        ov = run(tmp_path, data[:cut])
        assert ov.status in ('partial', 'not_pe', 'ok')
        if cut < 2:
            assert ov.status == 'not_pe'
        elif cut < full_headers:
            assert ov.status in ('partial', 'not_pe') and ov.warnings, cut
            seen_partial |= ov.status == 'partial'
    assert seen_partial


@pytest.mark.parametrize('cut,code', [
    (40, 'too_short'),
    (0x80 + 2, 'lfanew_out_of_range'),
    (0x80 + 4 + 10, 'coff_truncated'),
])
def test_specific_truncation_codes(tmp_path, cut, code):
    data = build_pe(PeSpec())
    ov = run(tmp_path, data[:cut])
    assert ov.status == 'partial' and code in codes(ov)


def test_truncated_optional_header_keeps_earlier_fields(tmp_path):
    data, info = build_pe_ex(PeSpec())
    ov = run(tmp_path, data[:info['opt_off'] + 30])
    assert ov.status == 'partial' and 'optional_header_truncated' in codes(ov)
    assert ov.machine.name == 'AMD64' and ov.entrypoint_rva == 0x1000 and ov.size_of_image is None


def test_truncated_section_table_and_missing_raw_data(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.text', b'\x90' * 600), SectionSpec('.data', b'1' * 100, DATA)])
    data, info = build_pe_ex(spec)
    ov = run(tmp_path, data[:info['section_table_off'] + 60])
    assert ov.status == 'partial' and 'section_table_truncated' in codes(ov)
    assert len(ov.sections) == 1
    ov2 = run(tmp_path, data[:info['sections'][1][3] + 10])  # second section's raw data cut short
    assert ov2.sections[1].entropy_bytes == 10


@pytest.mark.parametrize('value,code', [
    (0x7FFF, 'lfanew_out_of_range'),
    (0x10001, 'lfanew_over_cap'),
    (0xFFFFFFFF, 'lfanew_over_cap'),
])
def test_hostile_e_lfanew(tmp_path, value, code):
    data = bytearray(build_pe())
    struct.pack_into('<I', data, 0x3C, value)
    ov = run(tmp_path, bytes(data))
    assert ov.status == 'partial' and code in codes(ov) and ov.sections is None


def test_e_lfanew_cap_is_configurable(tmp_path):
    data = build_pe(PeSpec(e_lfanew=0x200))
    assert run(tmp_path, data).status == 'ok'
    ov = run(tmp_path, data, limits=Limits(max_lfanew=0x100))
    assert ov.status == 'partial' and 'lfanew_over_cap' in codes(ov)


def test_section_count_over_cap(tmp_path):
    data, info = build_pe_ex(PeSpec())
    bad = bytearray(data)
    struct.pack_into('<H', bad, info['e_lfanew'] + 6, 0xFFFF)
    ov = run(tmp_path, bytes(bad))
    assert ov.status == 'partial' and 'section_count_over_cap' in codes(ov)
    assert len(ov.sections) <= 96
    many = PeSpec(sections=[SectionSpec(f's{i}', b'a' * 8) for i in range(5)])
    ov = run(tmp_path, build_pe(many), limits=Limits(max_sections=3))
    assert 'section_count_over_cap' in codes(ov) and len(ov.sections) == 3


def test_directory_count_over_cap(tmp_path):
    data, info = build_pe_ex(PeSpec())
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['dir_off'] - 4, 40)
    ov = run(tmp_path, bytes(bad))
    assert 'directories_over_cap' in codes(ov) and len(ov.data_directories) == 16


def test_unknown_optional_magic(tmp_path):
    data, info = build_pe_ex(PeSpec())
    bad = bytearray(data)
    struct.pack_into('<H', bad, info['opt_off'], 0x107)
    ov = run(tmp_path, bytes(bad))
    assert ov.status == 'partial' and 'optional_magic_unknown' in codes(ov) and ov.optional_magic is None


# -- hostile directories --------------------------------------------------------------------------

def test_import_rva_out_of_file(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'k.dll': ['f']}))
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['dir_off'] + 8, 0x7FFFF000)
    ov = run(tmp_path, bytes(bad))
    assert ov.status == 'partial' and 'import_rva_out_of_file' in codes(ov) and ov.imports is None


def test_import_name_rva_out_of_file_keeps_going(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'k.dll': ['f', 'g']}))
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['import_desc_off'] + 12, 0x7FFFF000)
    ov = run(tmp_path, bytes(bad))
    assert 'import_rva_out_of_file' in codes(ov) and ov.imports.dlls[0].functions == ('f', 'g')
    assert ov.imports.dlls[0].name.startswith('<unreadable')


def test_import_name_pointer_loop(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'k.dll': ['aa', 'bb', 'cc', 'dd']}))
    bad = bytearray(data)
    first = struct.unpack_from('<Q', bad, info['first_thunk_off'])[0]
    for i in range(1, 4):
        struct.pack_into('<Q', bad, info['first_thunk_off'] + 8 * i, first)
    ov = run(tmp_path, bytes(bad))
    assert 'import_name_pointer_loop' in codes(ov) and ov.status == 'partial'
    assert ov.imports.dlls[0].functions == ('aa',) and ov.imports.dlls[0].truncated


def test_import_descriptor_loop(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'a.dll': ['f'], 'b.dll': ['g']}))
    bad = bytearray(data)
    off = info['import_desc_off']
    bad[off + 20:off + 40] = bad[off:off + 20]
    ov = run(tmp_path, bytes(bad))
    assert 'import_descriptor_loop' in codes(ov) and [d.name for d in ov.imports.dlls] == ['a.dll']


def test_import_unterminated_thunk_table_hits_function_cap(tmp_path):
    data, info = build_pe_ex(PeSpec(imports={'a.dll': [f'f{i}' for i in range(20)]}))
    bad = bytearray(data)
    ov = run(tmp_path, bytes(bad), limits=Limits(max_functions_per_dll=5))
    assert 'import_functions_over_cap' in codes(ov)
    assert len(ov.imports.dlls[0].functions) == 5 and ov.imports.dlls[0].truncated and ov.imports.truncated


def test_import_dll_and_total_name_caps(tmp_path):
    spec = PeSpec(imports={f'd{i}.dll': ['x', 'y', 'z'] for i in range(6)})
    ov = run(tmp_path, build_pe(spec), limits=Limits(max_import_dlls=3))
    assert 'import_dlls_over_cap' in codes(ov) and len(ov.imports.dlls) == 3 and ov.imports.truncated
    ov = run(tmp_path, build_pe(spec), limits=Limits(max_total_names=4))
    assert 'import_names_over_cap' in codes(ov) and ov.imports.total_functions == 4


def test_overlong_name_is_truncated(tmp_path):
    spec = PeSpec(imports={'A' * 700 + '.dll': ['f']})
    ov = run(tmp_path, build_pe(spec))
    assert 'name_truncated' in codes(ov) and len(ov.imports.dlls[0].name) == 512


def test_export_count_bomb(tmp_path):
    data, info = build_pe_ex(PeSpec(exports=('x.dll', ['a', 'b', 'c'])))
    bad = bytearray(data)
    struct.pack_into('<II', bad, info['export_dir_off'] + 20, 0xFFFFFFFF, 0xFFFFFFFF)
    ov = run(tmp_path, bytes(bad))
    assert ov.status == 'partial' and 'export_count_implausible' in codes(ov)
    assert 'export_names_over_cap' in codes(ov) and len(ov.exports.names) <= 20000 and ov.exports.truncated
    assert ov.exports.count == 0xFFFFFFFF


def test_export_name_cap_and_out_of_file_table(tmp_path):
    names = [f'n{i:03}' for i in range(50)]
    ov = run(tmp_path, build_pe(PeSpec(exports=('x.dll', names))), limits=Limits(max_export_names=10))
    assert len(ov.exports.names) == 10 and ov.exports.truncated and 'export_names_over_cap' in codes(ov)
    data, info = build_pe_ex(PeSpec(exports=('x.dll', ['a'])))
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['export_dir_off'] + 32, 0x7FFFF000)
    ov = run(tmp_path, bytes(bad))
    assert 'export_rva_out_of_file' in codes(ov) and ov.exports.names == ()


def test_export_directory_out_of_file(tmp_path):
    data, info = build_pe_ex(PeSpec(exports=('x.dll', ['a'])))
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['dir_off'], 0x7FFFF000)
    ov = run(tmp_path, bytes(bad))
    assert ov.exports is None and 'export_rva_out_of_file' in codes(ov)


def test_debug_entry_out_of_range(tmp_path):
    data, info = build_pe_ex(PeSpec(rsds=(bytes(16), 1, 'x.pdb')))
    bad = bytearray(data)
    rva, _ = struct.unpack_from('<II', bad, info['dir_off'] + 6 * 8)
    entry_off = info['sections'][-1][3] + (rva - info['sections'][-1][1])
    struct.pack_into('<I', bad, entry_off + 24, 0x7FFFFFF0)
    ov = run(tmp_path, bytes(bad))
    assert ov.codeview is None and 'debug_unparseable' in codes(ov)


def test_certificate_table_beyond_file_and_bad_entry(tmp_path):
    data, info = build_pe_ex(PeSpec(cert_payloads=[b'x' * 24]))
    ov = run(tmp_path, data[:-10])
    assert 'certificate_table_out_of_file' in codes(ov) and ov.certificates.present
    bad = bytearray(data)
    struct.pack_into('<I', bad, info['cert_off'], 4)
    ov = run(tmp_path, bytes(bad))
    assert 'certificate_entry_invalid' in codes(ov) and ov.certificates.entries == ()


def test_multiple_certificate_entries(tmp_path):
    ov = run(tmp_path, build_pe(PeSpec(cert_payloads=[b'a' * 9, b'b' * 30])))
    assert [e.length for e in ov.certificates.entries] == [17, 38] and ov.status == 'ok'


# -- overlay, entropy, hints, checksum --------------------------------------------------------------

def test_overlay_without_and_with_certificate(tmp_path):
    plain = run(tmp_path, build_pe(PeSpec()))
    assert plain.overlay is None
    data, info = build_pe_ex(PeSpec(overlay=b'OVERLAY!' * 8))
    ov = run(tmp_path, data)
    assert ov.overlay.offset == info['overlay_off'] and ov.overlay.size == 64 and ov.overlay.entropy is not None
    # certificate table alone is not overlay
    data, info = build_pe_ex(PeSpec(cert_payloads=[b'c' * 40]))
    ov = run(tmp_path, data)
    assert ov.overlay is None and ov.certificates.present
    # overlay followed by a certificate table: overlay excludes the table
    data, info = build_pe_ex(PeSpec(overlay=b'Z' * 100, cert_payloads=[b'c' * 40]))
    ov = run(tmp_path, data)
    assert ov.overlay.offset == info['overlay_off'] and ov.overlay.offset + ov.overlay.size == info['cert_off']
    assert ov.overlay.size >= 100


def test_data_after_certificate_table_is_informational(tmp_path):
    data, info = build_pe_ex(PeSpec(cert_payloads=[b'c' * 40]))
    ov = run(tmp_path, data + b'trailer')
    assert 'data_after_certificate_table' in codes(ov) and ov.status == 'ok'


def test_high_entropy_executable_section_hint_is_low_confidence(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.text', noise(8192)), SectionSpec('.rsrc', b'A' * 8192, DATA)])
    ov = run(tmp_path, build_pe(spec))
    assert ov.sections[0].entropy > 7.5 and ov.sections[1].entropy < 0.1
    assert len(ov.packer_hints) == 1
    hint = ov.packer_hints[0]
    assert hint.confidence == 'low' and 'entropy alone' in hint.evidence and hint.name != 'UPX'


def test_high_entropy_data_section_or_tiny_section_gives_no_hint(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.text', b'\x90' * 4096), SectionSpec('.blob', noise(8192), DATA),
                            SectionSpec('.tiny', noise(256), CODE)])
    assert run(tmp_path, build_pe(spec)).packer_hints == ()


def test_upx_layout_is_medium_and_names_alone_low(tmp_path):
    upx = PeSpec(sections=[SectionSpec('UPX0', b'', CODE, virtual_size=0x4000, raw_size=0),
                           SectionSpec('UPX1', noise(2048), CODE)])
    hints = run(tmp_path, build_pe(upx)).packer_hints
    assert hints[0].name == 'UPX' and hints[0].confidence == 'medium' and hints[0].evidence
    renamed = PeSpec(sections=[SectionSpec('.aspack', b'\x90' * 64)])
    hints = run(tmp_path, build_pe(renamed)).packer_hints
    assert [(h.name, h.confidence) for h in hints] == [('ASPack', 'low')]
    assert all(h.confidence in ('low', 'medium') for h in hints)


def test_entropy_sampling_cap(tmp_path):
    spec = PeSpec(sections=[SectionSpec('.text', noise(4096))])
    ov = run(tmp_path, build_pe(spec), limits=Limits(entropy_cap=1024))
    assert ov.sections[0].sampled is True and ov.sections[0].entropy_bytes == 1024
    ov = run(tmp_path, build_pe(spec))
    assert ov.sections[0].sampled is False and ov.sections[0].entropy_bytes == 4096


def independent_checksum(data: bytes, field_off: int) -> int:
    """Literal re-statement of the documented algorithm, one 16-bit word at a time."""
    buf = bytearray(data)
    buf[field_off:field_off + 4] = b'\0\0\0\0'
    if len(buf) % 2:
        buf.append(0)
    checksum = 0
    for i in range(0, len(buf), 2):
        word = buf[i] | (buf[i + 1] << 8)
        checksum = (checksum & 0xFFFFFFFF) + word + (checksum >> 32)
        if checksum > 0xFFFFFFFF:
            checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    return (checksum & 0xFFFF) + len(data)


def test_checksum_matches_independent_computation(tmp_path):
    data, info = build_pe_ex(PeSpec(overlay=b'\xff' * 1001))  # odd length, high bytes
    expected = independent_checksum(data, info['checksum_off'])
    stored = bytearray(data)
    struct.pack_into('<I', stored, info['checksum_off'], expected)
    ov = run(tmp_path, bytes(stored))
    assert ov.checksum.computed == expected and ov.checksum.stored == expected and ov.checksum.match is True
    ov = run(tmp_path, data)
    assert ov.checksum.stored == 0 and ov.checksum.computed == expected and ov.checksum.match is False


def test_checksum_crosses_chunk_boundaries(tmp_path):
    data, info = build_pe_ex(PeSpec(sections=[SectionSpec('.text', noise(5000))], overlay=noise(3001)))
    expected = independent_checksum(data, info['checksum_off'])
    ov = run(tmp_path, data, limits=Limits(chunk=64))
    assert ov.checksum.computed == expected
    ov = run(tmp_path, data, limits=Limits(chunk=0x44 + 2))  # chunk edge inside the checksum field
    assert ov.checksum.computed == expected


def test_checksum_skipped_for_large_files(tmp_path):
    data = build_pe()
    ov = run(tmp_path, data, limits=Limits(checksum_max_file=100))
    assert ov.checksum.computed is None and ov.checksum.match is None
    assert 'checksum_skipped_large' in codes(ov) and ov.status == 'partial'


# -- cancellation, identity, API ---------------------------------------------------------------------

def test_cancelled_before_start_and_midway(tmp_path):
    data = build_pe(PeSpec(imports={'k.dll': ['f']}, sections=[SectionSpec('.text', noise(4096))]))
    ov = run(tmp_path, data, cancel=lambda: True)
    assert ov.status == 'cancelled' and ov.sha256 and ov.size == len(data)
    calls = {'n': 0}

    def after_some():
        calls['n'] += 1
        return calls['n'] > 6

    ov = run(tmp_path, data, cancel=after_some)
    assert ov.status == 'cancelled' and ov.machine is not None and ov.imports is None


def test_every_cancellation_point_yields_valid_overview(tmp_path):
    data = build_pe(PeSpec(imports={'k.dll': ['f']}, exports=('x', ['a']), overlay=b'o' * 50,
                           cert_payloads=[b'c']))
    total = {'n': 0}

    def count():
        total['n'] += 1
        return False

    assert run(tmp_path, data, cancel=count).status == 'ok'
    for stop in range(1, total['n'] + 1):
        calls = {'n': 0}

        def cancel(stop=stop, calls=calls):
            calls['n'] += 1
            return calls['n'] >= stop

        assert run(tmp_path, data, cancel=cancel).status == 'cancelled'


def test_identical_files_give_identical_overviews(tmp_path):
    data = build_pe(PeSpec(imports={'k.dll': ['f']}))
    a = run(tmp_path, data, name='a.exe')
    b = run(tmp_path, data, name='b.exe')
    assert a == b and a.to_dict() == b.to_dict()


def test_reader_errors_propagate(tmp_path):
    path = tmp_path / 'a.exe'
    path.write_bytes(build_pe())
    reader = VerifiedArtifactReader.open_path(path)
    reader.close()
    with pytest.raises(ArtifactBytesError) as exc:
        inspect_pe(reader)
    assert exc.value.code == 'closed'


def test_random_garbage_never_raises(tmp_path):
    base, info = build_pe_ex(PeSpec(imports={'k.dll': ['f', 'g']}, exports=('x', ['a', 'b']),
                                    rsds=(bytes(16), 1, 'p.pdb'), cert_payloads=[b'c' * 20]))
    for seed in range(60):
        rnd = noise(len(base), b'fuzz%d' % seed)
        mutated = bytearray(base)
        for k in range(24):
            pos = rnd[k * 2] * 256 % len(base) if seed % 2 else (rnd[k * 2] * 7 + rnd[k * 2 + 1]) % 0x400
            mutated[pos] = rnd[k * 2 + 1]
        ov = run(tmp_path, bytes(mutated))
        assert ov.status in ('ok', 'partial', 'not_pe')
        json.dumps(ov.to_dict())


def test_package_has_no_qt_or_third_party_pe_imports():
    root = Path(__file__).parents[1] / 'src' / 'patchtrace' / 'pe_overview'
    text = '\n'.join(p.read_text(encoding='utf-8') for p in root.glob('*.py'))
    for banned in ('PySide', 'PyQt', 'import pefile', 'import lief', 'subprocess'):
        assert banned not in text


def test_pe32plus_thunk_with_reserved_high_bits_is_not_masked_to_another_rva(tmp_path):
    data, info = build_pe_ex(PeSpec(pe32plus=True, imports={'k.dll': ['f']}))
    bad = bytearray(data)
    struct.pack_into('<Q', bad, info['first_thunk_off'], 0x80001000)
    ov = run(tmp_path, bytes(bad))
    assert 'import_thunk_reserved_bits' in codes(ov)
    assert not any(name == 'f' for name in ov.imports.dlls[0].functions)

