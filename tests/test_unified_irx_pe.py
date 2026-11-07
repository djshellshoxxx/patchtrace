"""irx audit: PE table hardening (hostile `.pdata`, chains, base relocations)."""
from __future__ import annotations

import struct

from hypothesis import given
from hypothesis import strategies as st

from patchtrace.unified.ir import pe_tables
from patchtrace.unified.ir.pe_tables import Section, _Covered, _Rva


@given(st.lists(st.tuples(st.integers(0, 200), st.integers(1, 60)), max_size=8), st.integers(-5, 300))
def test_section_cover_is_the_union_even_for_overlapping_sections(spans, rva):
    sections = [Section(f's{i}', start, start + size, True) for i, (start, size) in enumerate(spans)]
    assert (rva in _Covered(sections)) == any(s.start <= rva < s.end for s in sections)


class FlatMap:
    """A fake section map: RVA == file offset inside [0, len(data))."""

    def __init__(self, data):
        self.data = data

    def rva_to_file_ranges(self, rva, length):
        if rva < 0 or rva + length > len(self.data):
            return None
        return [type('R', (), {'file_offset': rva, 'length': length})]


class FlatReader:
    def __init__(self, data):
        self.data = data

    def read(self, offset, length, clip=False):
        return self.data[offset:offset + length]


def rva_reader(data):
    return _Rva(FlatReader(data), FlatMap(data))


class Directory:
    present = True

    def __init__(self, rva, size):
        self.rva, self.size = rva, size


def relocations(blocks, size_of_image=0x10000):
    data = b''.join(blocks)
    tables = pe_tables.PeTables(image_base=0x140000000, size_of_image=size_of_image)
    pe_tables._read_relocations(rva_reader(data), Directory(0, len(data)), size_of_image, tables)
    return tables


def block(page, entries):
    body = b''.join(struct.pack('<H', e) for e in entries)
    return struct.pack('<II', page, 8 + len(body)) + body


def test_reloc_blocks_of_hostile_size_terminate_with_a_warning():
    for size in (0, 1, 2, 7, 9, 10_000):
        tables = relocations([struct.pack('<II', 0x1000, size)])
        assert 'reloc-unreadable' in tables.warnings and len(tables.relocs) == 0
    assert len(relocations([struct.pack('<II', 0x1000, 8)]).relocs) == 0      # header-only block is legal


def test_reloc_entries_keep_dir64_only_and_warn_once_per_other_type():
    entries = [0xA010, 0xA020, 0x3030, 0x3031, 0x0000, 0xAFFF]
    tables = relocations([block(0x2000, entries)])
    assert list(tables.relocs) == [0x2010, 0x2020, 0x2FFF] and tables.warnings == ['reloc-type-3']


def test_reloc_beyond_the_image_is_dropped_with_one_warning():
    tables = relocations([block(0xFFF0000, [0xA001, 0xA002])], size_of_image=0x10000)
    assert len(tables.relocs) == 0 and tables.warnings == ['reloc-out-of-image']


def unwind(flags, chain=None):
    head = bytes([1 | (flags << 3), 0, 0, 0]) + bytes(0)
    return head + (struct.pack('<III', *chain) if chain else b'')


def put(data, at, raw):
    data[at:at + len(raw)] = raw


def test_chained_unwind_cycles_and_self_chains_are_unreadable_not_endless():
    data = bytearray(0x400)
    put(data, 0x200, unwind(4, chain=(0x110, 0x120, 0x300)))        # A (0x100) chains to B (0x110) ...
    put(data, 0x300, unwind(4, chain=(0x100, 0x110, 0x200)))        # ... and B chains back to A
    tables = pe_tables.PeTables(image_base=0x140000000, size_of_image=0x400)
    pe_tables._resolve_chains(rva_reader(bytes(data)), [(0x100, 0x110, 0x200), (0x110, 0x120, 0x300)], tables)
    assert tables.primaries == {} and 'pdata-unreadable' in tables.warnings
    put(data, 0x200, unwind(4, chain=(0x100, 0x110, 0x200)))        # A chains to itself
    tables = pe_tables.PeTables(image_base=0x140000000, size_of_image=0x400)
    pe_tables._resolve_chains(rva_reader(bytes(data)), [(0x100, 0x110, 0x200)], tables)
    assert tables.primaries == {} and 'pdata-unreadable' in tables.warnings


def test_a_long_chain_beyond_the_hop_bound_is_unreadable():
    n = pe_tables.MAX_CHAIN_HOPS + 3
    data = bytearray(0x4000)
    entries = []
    for i in range(n):
        begin, unwind_rva = 0x100 + 0x10 * i, 0x1000 + 0x20 * i
        raw = unwind(4, chain=(begin - 0x10, begin, unwind_rva - 0x20)) if i else unwind(0)
        put(data, unwind_rva, raw)
        entries.append((begin, begin + 0x10, unwind_rva))
    tables = pe_tables.PeTables(image_base=0x140000000, size_of_image=0x4000)
    pe_tables._resolve_chains(rva_reader(bytes(data)), entries, tables)
    assert tables.primaries == {} and 'pdata-unreadable' in tables.warnings
