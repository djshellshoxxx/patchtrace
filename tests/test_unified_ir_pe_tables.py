"""SPEC-31 S1: PE tables for the IR (ir/pe_tables.py): .pdata with chained entries, EH signature, relocations,
hostile tables. Images are synthetic bytes from tests/pe_builder.py; nothing is executed."""
from __future__ import annotations

import json
import struct

import pytest
from pe_builder import CODE, RDATA, PeSpec, SectionSpec, build_pe

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.unified.ir import pe_tables as pt
from patchtrace.unified.limits import UnifiedError

BASE = 0x180000000
TEXT, XDATA, PDATA, RELOC = 0x1000, 0x2000, 0x3000, 0x4000     # section RVAs (4 KiB each in the builder)


def unwind(flags=0, prolog=4, codes=b'', frame=0, handler=None, data=b'', chain=None):
    count = len(codes) // 2
    body = bytes([1 | (flags << 3), prolog, count, frame]) + codes + (b'\0\0' if count & 1 else b'')
    if chain is not None:
        body += struct.pack('<III', *chain)
    elif flags & 3:
        body += struct.pack('<I', handler) + data
    return body


def reloc_block(page, entries):
    body = b''.join(struct.pack('<H', (kind << 12) | offset) for kind, offset in entries)
    if len(body) % 4:
        body += b'\0\0'                                   # blocks are 32-bit aligned (padding entry)
    return struct.pack('<II', page, 8 + len(body)) + body


def image(tmp_path, *, xdata=b'', functions=(), relocs=b'', pdata_size=None, name='img.dll'):
    pdata = b''.join(struct.pack('<III', *f) for f in functions)
    spec = PeSpec(kind='dll', image_base=BASE, sections=[
        SectionSpec('.text', b'\x90' * 0x800, CODE), SectionSpec('.xdata', xdata or b'\0', RDATA),
        SectionSpec('.pdata', pdata or b'\0', RDATA), SectionSpec('.reloc', relocs or b'\0', RDATA)],
        extra_directories={3: (PDATA, len(pdata) if pdata_size is None else pdata_size),
                           5: (RELOC, len(relocs))})
    path = tmp_path / name
    path.write_bytes(build_pe(spec))
    return VerifiedArtifactReader.open_path(path)


def test_sections_and_executable_map(tmp_path):
    with image(tmp_path) as reader:
        tables = pt.read_pe_tables(reader)
    assert tables.image_base == BASE and tables.size_of_image >= RELOC + 0x1000
    assert tables.is_executable(TEXT) and not tables.is_executable(XDATA) and not tables.is_executable(0x10)


def test_not_a_pe32plus_is_unsupported(tmp_path):
    path = tmp_path / 'bad.bin'
    path.write_bytes(b'MZ' + b'\0' * 200)
    with VerifiedArtifactReader.open_path(path) as reader, pytest.raises(UnifiedError) as caught:
        pt.read_pe_tables(reader)
    assert caught.value.code == 'PT-UNIFIED-UNSUPPORTED' and caught.value.reason == 'not-pe32plus'


def test_pdata_chained_entries_merge_chunks(tmp_path):
    primary = unwind(codes=b'\x04\x01\x02\x03')
    chunk = unwind(flags=4, chain=(TEXT, TEXT + 0x40, XDATA))                # chains to the primary entry
    xdata = primary.ljust(0x40, b'\0') + chunk
    functions = [(TEXT, TEXT + 0x40, XDATA), (TEXT + 0x400, TEXT + 0x420, XDATA + 0x40)]
    with image(tmp_path, xdata=xdata, functions=functions) as reader:
        tables = pt.read_pe_tables(reader)
    assert sorted(tables.primaries) == [TEXT] and tables.primaries[TEXT].chunks == [(TEXT + 0x400, TEXT + 0x420)]
    assert tables.extent(TEXT, [(TEXT, 0x40), (TEXT + 0x400, 0x20)]) == 1          # union equal: pdata-confirmed
    assert tables.extent(TEXT, [(TEXT, 0x40)]) == 2                                # Ghidra lost the chunk: conflict
    assert tables.extent(TEXT, [(TEXT, 0x30), (TEXT + 0x400, 0x20)]) == 2
    assert tables.extent(TEXT + 0x400, [(TEXT + 0x400, 0x20)]) == 0                # a chunk is not a function entry
    assert tables.extent(TEXT + 0x80, [(TEXT + 0x80, 0x10)]) == 0                  # leaf function: no entry
    assert tables.warnings == []


def test_adjacent_ghidra_ranges_are_coalesced_before_comparison(tmp_path):
    xdata = unwind()
    with image(tmp_path, xdata=xdata, functions=[(TEXT, TEXT + 0x40, XDATA)]) as reader:
        tables = pt.read_pe_tables(reader)
    assert tables.extent(TEXT, [(TEXT, 0x20), (TEXT + 0x20, 0x20)]) == 1


def test_alignment_padding_gaps_up_to_15_bytes_still_confirm_the_extent(tmp_path):
    # MinGW/GCC bodies have padding gaps Ghidra leaves out (real _CRT_INIT: ten ranges, pdata one); the tail may too
    with image(tmp_path, xdata=unwind(), functions=[(TEXT, TEXT + 0x80, XDATA)]) as reader:
        tables = pt.read_pe_tables(reader)
    assert tables.extent(TEXT, [(TEXT, 0x20), (TEXT + 0x2f, 0x3b), (TEXT + 0x70, 0x0b)]) == 1   # gaps 15 and 6, tail 5
    assert tables.extent(TEXT, [(TEXT, 0x20), (TEXT + 0x30, 0x4c)]) == 2                         # gap 16: not padding
    assert tables.extent(TEXT, [(TEXT, 0x20), (TEXT + 0x31, 0x4f)]) == 2                         # gap 17
    assert tables.extent(TEXT, [(TEXT + 4, 0x7c)]) == 2                                           # starts after the entry
    assert tables.extent(TEXT, [(TEXT, 0x90)]) == 2                                               # Ghidra runs past pdata
    assert tables.extent(TEXT, [(TEXT, 0x60)]) == 2                                               # tail gap 32


def _eh(tmp_path, shift, name):
    begin = TEXT + shift
    scope = struct.pack('<I', 2) + struct.pack('<IIII', begin + 0x10, begin + 0x30, 1, begin + 0x38) \
        + struct.pack('<IIII', begin + 0x04, begin + 0x08, 0, begin + 0x3c)
    xdata = unwind(flags=1, prolog=7, codes=b'\x01\x74\x02\x00', frame=0x15, handler=TEXT + 0x7f0, data=scope)
    with image(tmp_path, xdata=xdata, functions=[(begin, begin + 0x40, XDATA)], name=name) as reader:
        tables = pt.read_pe_tables(reader)
        return json.loads(tables.eh_for(begin))


def test_eh_signature_function_relative(tmp_path):
    a, b = _eh(tmp_path, 0, 'a.dll'), _eh(tmp_path, 0x100, 'b.dll')
    assert a == b                                           # a moved function with the same scopes: equal signature
    assert a['scopes'] == [[0x10, 0x30, 1, 0x38], [0x04, 0x08, 0, 0x3c]] and a['hlen'] == 4 + 32
    assert a['fl'] == 1 and a['prolog'] == 7 and a['frame'] == [5, 1] and a['codes'] == '01740200'
    assert a['handler'] == TEXT + 0x7f0                      # the handler stays an RVA to be mapped by the consumer


def test_changed_scope_table_changes_the_signature(tmp_path):
    a = _eh(tmp_path, 0, 'a.dll')
    begin = TEXT
    scope = struct.pack('<I', 1) + struct.pack('<IIII', begin + 0x10, begin + 0x34, 1, begin + 0x38)   # end differs
    xdata = unwind(flags=1, prolog=7, codes=b'\x01\x74\x02\x00', frame=0x15, handler=TEXT + 0x7f0, data=scope)
    with image(tmp_path, xdata=xdata, functions=[(begin, begin + 0x40, XDATA)], name='c.dll') as reader:
        c = json.loads(pt.read_pe_tables(reader).eh_for(begin))
    assert c != a and c['scopes'] == [[0x10, 0x34, 1, 0x38]]


def test_opaque_handler_data_is_kept_as_handler_only(tmp_path):
    xdata = unwind(flags=1, handler=TEXT + 0x7f0, data=struct.pack('<I', 0x2800))    # C++ FuncInfo-style RVA
    with image(tmp_path, xdata=xdata, functions=[(TEXT, TEXT + 0x40, XDATA)]) as reader:
        eh = json.loads(pt.read_pe_tables(reader).eh_for(TEXT))
    assert eh['scopes'] is None and eh['hlen'] is None and eh['handler'] == TEXT + 0x7f0


def test_function_without_unwind_data_has_no_eh(tmp_path):
    with image(tmp_path, xdata=unwind(), functions=[(TEXT, TEXT + 0x40, XDATA)]) as reader:
        tables = pt.read_pe_tables(reader)
        assert tables.eh_for(TEXT + 0x200) is None


def test_unreadable_unwind_info_is_unavailable_not_absent(tmp_path):
    with image(tmp_path, xdata=b'\0', functions=[(TEXT, TEXT + 0x40, 0x2ff8)]) as reader:   # unwind info past the section
        tables = pt.read_pe_tables(reader)
    assert tables.warnings == ['pdata-unreadable'] and tables.primaries == {}


def test_reloc_dir64_only_others_warn(tmp_path):
    blocks = reloc_block(TEXT, [(10, 0x10), (0, 0), (3, 0x20), (3, 0x24), (10, 0x08)]) + reloc_block(XDATA, [(10, 0x40)])
    with image(tmp_path, relocs=blocks) as reader:
        tables = pt.read_pe_tables(reader)
    assert list(tables.relocs) == [TEXT + 8, TEXT + 0x10, XDATA + 0x40]
    assert tables.warnings == ['reloc-type-3']
    assert tables.reloc_in(TEXT + 8, TEXT + 16) and not tables.reloc_in(TEXT + 9, TEXT + 16)
    assert tables.reloc_in(XDATA + 0x40, XDATA + 0x48) and not tables.reloc_in(XDATA + 0x41, XDATA + 0x80)


def test_relocation_outside_the_image_is_dropped_with_a_warning(tmp_path):
    with image(tmp_path, relocs=reloc_block(0x40000, [(10, 0x10)])) as reader:
        tables = pt.read_pe_tables(reader)
    assert list(tables.relocs) == [] and tables.warnings == ['reloc-out-of-image']


@pytest.mark.parametrize('case', ['unsorted', 'overlap', 'empty-range', 'out-of-section', 'truncated'])
def test_hostile_pdata_is_discarded_never_fatal(tmp_path, case):
    xdata = unwind()
    functions = {
        'unsorted': [(TEXT + 0x80, TEXT + 0xc0, XDATA), (TEXT, TEXT + 0x40, XDATA)],
        'overlap': [(TEXT, TEXT + 0x80, XDATA), (TEXT + 0x40, TEXT + 0xc0, XDATA)],
        'empty-range': [(TEXT, TEXT, XDATA)],
        'out-of-section': [(TEXT + 0x7f0, TEXT + 0x1800, XDATA)],
        'truncated': [(TEXT, TEXT + 0x40, XDATA)],
    }[case]
    size = 13 if case == 'truncated' else None
    with image(tmp_path, xdata=xdata, functions=functions, pdata_size=size) as reader:
        tables = pt.read_pe_tables(reader)
    assert tables.primaries == {} and 'pdata-unreadable' in tables.warnings
    assert tables.extent(TEXT, [(TEXT, 0x40)]) == 0 and tables.eh_for(TEXT) is None


def test_huge_runtime_function_count_is_a_limit_error(tmp_path):
    with image(tmp_path, xdata=unwind(), functions=[(TEXT, TEXT + 0x40, XDATA)],
               pdata_size=pt.MAX_RUNTIME_FUNCTIONS * 12 + 12) as reader, pytest.raises(UnifiedError) as caught:
        pt.read_pe_tables(reader)
    assert caught.value.code == 'PT-UNIFIED-LIMIT' and caught.value.reason == 'pdata-cap'


def test_huge_relocation_directory_is_a_limit_error(tmp_path):
    spec = PeSpec(kind='dll', image_base=BASE, sections=[SectionSpec('.text', b'\x90' * 64, CODE)],
                  extra_directories={5: (TEXT, pt.MAX_RELOC_DIRECTORY + 1)})
    path = tmp_path / 'r.dll'
    path.write_bytes(build_pe(spec))
    with VerifiedArtifactReader.open_path(path) as reader, pytest.raises(UnifiedError) as caught:
        pt.read_pe_tables(reader)
    assert caught.value.reason == 'reloc-cap'


def test_chain_cycles_are_discarded(tmp_path):
    a = unwind(flags=4, chain=(TEXT + 0x40, TEXT + 0x80, XDATA + 0x40))
    b = unwind(flags=4, chain=(TEXT, TEXT + 0x40, XDATA))
    xdata = a.ljust(0x40, b'\0') + b
    with image(tmp_path, xdata=xdata, functions=[(TEXT, TEXT + 0x40, XDATA), (TEXT + 0x40, TEXT + 0x80, XDATA + 0x40)]) \
            as reader:
        tables = pt.read_pe_tables(reader)
    assert tables.primaries == {} and 'pdata-unreadable' in tables.warnings
