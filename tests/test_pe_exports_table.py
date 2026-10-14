"""WBQ S4: export address table entries (ordinal, RVA, forwarder, name) from well-formed and hostile images.

Synthetic PEs only (tests/pe_builder.py and tests/pe_exports_builder.py); nothing is executed or loaded.
"""
from __future__ import annotations

import struct
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_builder import PeSpec, build_pe
from pe_exports_builder import (
    EDATA_RVA,
    H_AOF,
    H_AON,
    H_AOO,
    H_BASE,
    H_NFUNCS,
    H_NNAMES,
    ExportSpec,
    build_exports,
    patch,
)

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import Limits, inspect_pe
from patchtrace.pe_overview._common import Cancelled, Ctx, clean_text
from patchtrace.pe_overview.exports_table import ExportEntry, ExportTable, parse_export_entries

FAST = settings(deadline=None, max_examples=150,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
CAP = Limits().max_export_names

# slot: 0 code, 1 gap, 2 code, 3 forwarder, 4 code (ordinal only), 5 forwarder (ordinal only); base 10
RICH = ExportSpec(
    functions=[0x1000, None, 0x1010, 'NTDLL.RtlAllocateHeap', 0x1020, 'NTDLL.#291'],
    names=[('AliasOfAlpha', 0), ('Alpha', 0), ('Beta', 2), ('Fwd', 3)], base=10)
RICH_ROWS = [
    ('AliasOfAlpha', 10, 0x1000, None), ('Alpha', 10, 0x1000, None), ('Beta', 12, 0x1010, None),
    ('Fwd', 13, None, 'NTDLL.RtlAllocateHeap'), (None, 14, 0x1020, None), (None, 15, None, 'NTDLL.#291'),
]


def parse(tmp_path: Path, data: bytes, *, limits: Limits | None = None, cancel=None, rva: int | None = None,
          size: int | None = None) -> tuple[ExportTable | None, set[str]]:
    """The S5 call shape: Export data directory (rva, size) of the real header and section parse."""
    path = tmp_path / 'sample.dll'
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        ov = inspect_pe(reader)
        directory = ov.directory('Export')
        ctx = Ctx(reader, cancel, limits or Limits())
        table = parse_export_entries(ctx, ov.section_map(), directory.rva if rva is None else rva,
                                     directory.size if size is None else size)
        return table, {w.code for w in ctx.warnings}


def rows(table: ExportTable) -> list[tuple]:
    return [(e.name, e.ordinal, e.rva, e.forwarder) for e in table.entries]


def assert_sane(table: ExportTable | None, cap: int = CAP) -> None:
    """Invariants that hold for any input, however hostile."""
    if table is None:
        return
    assert isinstance(table.truncated, bool) and len(table.entries) <= cap
    keys = [(e.ordinal, e.name or '') for e in table.entries]
    assert keys == sorted(keys)
    for e in table.entries:
        assert isinstance(e, ExportEntry)
        assert e.name is None or isinstance(e.name, str)
        assert isinstance(e.ordinal, int) and e.ordinal >= 0
        assert e.rva is None or (isinstance(e.rva, int) and 0 < e.rva < 2 ** 32)
        assert e.forwarder is None or isinstance(e.forwarder, str)
        assert e.rva is None or e.forwarder is None  # a slot is a code address or a forwarder, never both


# -- well formed ---------------------------------------------------------------------------------------

def test_named_exports_from_the_shared_builder(tmp_path):
    data = build_pe(PeSpec(kind='dll', exports=('lib.dll', ['zeta', 'alpha', 'mid'])))
    table, codes = parse(tmp_path, data)
    assert rows(table) == [('alpha', 1, 0x1000, None), ('mid', 2, 0x1000, None), ('zeta', 3, 0x1000, None)]
    assert table.truncated is False and codes == set()


@pytest.mark.parametrize('pe32plus', [True, False], ids=['pe32plus', 'pe32'])
def test_forwarders_gaps_aliases_and_ordinal_only_exports(tmp_path, pe32plus):
    spec = ExportSpec(RICH.functions, RICH.names, RICH.base, pe32plus)
    table, codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == RICH_ROWS
    assert table.truncated is False and codes == set()


def test_names_agree_with_the_existing_names_only_parse(tmp_path):
    data, _lay = build_exports(RICH)
    table, _codes = parse(tmp_path, data)
    path = tmp_path / 'sample.dll'
    with VerifiedArtifactReader.open_path(path) as reader:
        listed = inspect_pe(reader).exports.names
    assert sorted(e.name for e in table.entries if e.name) == sorted(listed)


def test_ordinal_is_base_plus_index_across_gaps(tmp_path):
    spec = ExportSpec(functions=[0x1000, None, None, 0x1010], names=[('B', 3)], base=0x40)
    table, _codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [(None, 0x40, 0x1000, None), ('B', 0x43, 0x1010, None)]


def test_ordinals_may_exceed_sixteen_bits_and_are_reported_as_stored(tmp_path):
    spec = ExportSpec(functions=[0x1000, 0x1010], names=[('A', 1)], base=0xFFFFFFF0)
    table, _codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [(None, 0xFFFFFFF0, 0x1000, None), ('A', 0xFFFFFFF1, 0x1010, None)]


def test_a_name_on_an_empty_slot_keeps_the_name_and_leaves_the_address_unknown(tmp_path):
    spec = ExportSpec(functions=[0x1000, None], names=[('Ghost', 1)])
    table, _codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [(None, 1, 0x1000, None), ('Ghost', 2, None, None)]


def test_more_names_than_addresses_is_a_legal_alias_table(tmp_path):
    spec = ExportSpec(functions=[0x1000], names=[('A', 0), ('B', 0), ('C', 0)])
    table, codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [('A', 1, 0x1000, None), ('B', 1, 0x1000, None), ('C', 1, 0x1000, None)]
    assert not table.truncated and codes == set()


def test_the_same_name_text_twice_on_one_slot_is_one_entry(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000], names=[('dup', 0), ('dup2', 0)]))
    twin = patch(data, lay.off(lay.strings['dup2']), '5s', b'dup\0\0')  # a second copy of the string, other RVA
    table, codes = parse(tmp_path, twin)
    assert rows(table) == [('dup', 1, 0x1000, None)] and not table.truncated and codes == set()


def test_empty_table_is_complete(tmp_path):
    table, codes = parse(tmp_path, build_exports(ExportSpec())[0])
    assert table == ExportTable((), False) and codes == set()


def test_unnamed_only_table(tmp_path):
    table, _codes = parse(tmp_path, build_exports(ExportSpec(functions=[0x1000, 0x1010, 0x1020]))[0])
    assert rows(table) == [(None, 1, 0x1000, None), (None, 2, 0x1010, None), (None, 3, 0x1020, None)]


def test_names_and_forwarders_are_untrusted_text(tmp_path):
    spec = ExportSpec(functions=[0x1000, 'A\x01.f\x7f'], names=[('ev\x07il\xff', 0), ('', 1)])
    table, _codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [('ev?il\xff', 1, 0x1000, None), ('', 2, None, 'A?.f?')]


# -- the forwarder range -------------------------------------------------------------------------------

def test_forwarder_range_is_the_directory_range_half_open(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1000, 0x1000, 0x1000, 0x1000]))
    end = EDATA_RVA + lay.size
    values = (EDATA_RVA - 1, EDATA_RVA, end - 1, end, 0x1010)
    bad = patch(data, lay.off(lay.eat_rva), '<5I', *values)
    table, codes = parse(tmp_path, bad)
    # first byte of the header and last byte of the blob are NULs: empty forwarder strings
    assert rows(table) == [(None, 1, EDATA_RVA - 1, None), (None, 2, None, ''), (None, 3, None, ''),
                           (None, 4, end, None), (None, 5, 0x1010, None)]
    assert codes == set()


def test_a_forwarder_pointing_at_its_own_slot_reads_bounded_text(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000]))
    table, codes = parse(tmp_path, patch(data, lay.off(lay.eat_rva), '<I', lay.eat_rva))
    own_bytes = struct.pack('<I', lay.eat_rva).split(b'\0')[0]  # the slot's own value, read as the string
    assert rows(table) == [(None, 1, None, clean_text(own_bytes))] and codes == set()


def test_zero_directory_size_means_nothing_is_a_forwarder(tmp_path):
    data, lay = build_exports(ExportSpec(functions=['NTDLL.Foo']))
    table, _codes = parse(tmp_path, data, size=0)
    assert rows(table) == [(None, 1, lay.strings['NTDLL.Foo'], None)]


def test_forwarder_string_that_cannot_be_read_is_unknown_not_an_export(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 'A.f']))
    beyond = EDATA_RVA + lay.size + 0x40  # inside the claimed range below, outside every section
    bad = patch(data, lay.off(lay.eat_rva), '<I', beyond)
    table, codes = parse(tmp_path, bad, size=lay.size + 0x100)
    assert rows(table) == [(None, 1, None, None), (None, 2, None, 'A.f')]
    assert table.truncated and 'export_rva_out_of_file' in codes


def test_overlong_forwarder_is_cut_at_the_name_limit(tmp_path):
    spec = ExportSpec(functions=['D.' + 'x' * 600])
    table, codes = parse(tmp_path, build_exports(spec)[0])
    assert rows(table) == [(None, 1, None, 'D.' + 'x' * 510)]
    assert table.truncated and 'name_truncated' in codes


def test_overlong_name_is_cut_at_the_name_limit(tmp_path):
    table, codes = parse(tmp_path, build_exports(ExportSpec(functions=[0x1000], names=[('N' * 600, 0)]))[0])
    assert rows(table) == [('N' * 512, 1, 0x1000, None)]
    assert table.truncated and 'name_truncated' in codes


# -- counts and caps -----------------------------------------------------------------------------------

@pytest.mark.parametrize('counts', [(0xFFFFFFFF, 2), (2, 0xFFFFFFFF), (0xFFFFFFFF, 0xFFFFFFFF)],
                         ids=['addresses', 'names', 'both'])
def test_oversize_counts_neither_loop_nor_allocate(tmp_path, counts):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)]))
    bad = patch(data, lay.header_field(H_NFUNCS), '<II', *counts)
    started = time.monotonic()
    table, codes = parse(tmp_path, bad)
    assert time.monotonic() - started < 5
    assert_sane(table)
    assert table.truncated and {'export_table_over_cap', 'export_count_implausible'} <= codes


def test_entry_cap_keeps_the_first_ordinals_and_marks_the_table_truncated(tmp_path):
    spec = ExportSpec(functions=[0x1000 + 0x10 * (i % 4) for i in range(25)],
                      names=[(f'n{i:02d}', i) for i in range(25)])
    table, codes = parse(tmp_path, build_exports(spec)[0], limits=Limits(max_export_names=10))
    assert [(e.name, e.ordinal) for e in table.entries] == [(f'n{i:02d}', i + 1) for i in range(10)]
    assert table.truncated and 'export_table_over_cap' in codes


def test_name_count_over_the_cap_is_truncated_even_when_the_addresses_fit(tmp_path):
    spec = ExportSpec(functions=[0x1000, 0x1010, 0x1020], names=[(f'n{i:02d}', 0) for i in range(12)])
    table, codes = parse(tmp_path, build_exports(spec)[0], limits=Limits(max_export_names=10))
    # ten aliases of slot 0; slots 1 and 2 are not claimed ordinal-only because two names were never read
    assert [(e.name, e.ordinal) for e in table.entries] == [(f'n{i:02d}', 1) for i in range(10)]
    assert table.truncated and 'export_table_over_cap' in codes


def test_alias_fan_out_is_cut_at_the_entry_cap(tmp_path):
    names = [(f'a{i}', i // 2) for i in range(10)]  # two names on each of the first five slots
    spec = ExportSpec(functions=[0x1000] * 10, names=names)
    table, codes = parse(tmp_path, build_exports(spec)[0], limits=Limits(max_export_names=10))
    # 10 aliased entries + 5 ordinal-only slots would be 15: the first ten by ordinal are kept
    assert [(e.name, e.ordinal) for e in table.entries] == [(n, i + 1) for n, i in names]
    assert table.truncated and 'export_table_over_cap' in codes


def test_slot_cap_with_a_complete_name_table_still_reports_unnamed_slots(tmp_path):
    table, codes = parse(tmp_path, build_exports(ExportSpec(functions=[0x1000] * 30))[0],
                         limits=Limits(max_export_names=10))
    assert [e.ordinal for e in table.entries] == list(range(1, 11)) and all(e.name is None for e in table.entries)
    assert table.truncated and 'export_table_over_cap' in codes


def test_twenty_thousand_exports_in_budget(tmp_path):
    n = CAP
    spec = ExportSpec(functions=[0x1000] * n, names=[(f'Export_{i:06d}_with_a_reasonably_long_name', i)
                                                     for i in range(n)])
    data = build_exports(spec)[0]
    started = time.monotonic()
    table, codes = parse(tmp_path, data)
    assert time.monotonic() - started < 3
    assert len(table.entries) == n and not table.truncated and codes == set()
    assert table.entries[0].name == 'Export_000000_with_a_reasonably_long_name' and table.entries[-1].ordinal == n


# -- table pointers outside the file -------------------------------------------------------------------

@pytest.mark.parametrize(('field', 'pointer', 'expected'), [
    (H_AOF, 0x7FFFF000, [('a', 1, None, None), ('b', 2, None, None)]),  # names survive, addresses are unknown
    (H_AON, 0x7FFFF000, []),  # without the name table no slot can be called ordinal-only
    (H_AOO, 0x7FFFF000, []),
    (H_AOF, 0, [('a', 1, None, None), ('b', 2, None, None)]),  # RVA 0 is the DOS header, not a table
    (H_AON, 0, []),
    (H_AOO, 0, []),
], ids=['address-table', 'name-pointers', 'ordinals', 'address-table-null', 'name-pointers-null', 'ordinals-null'])
def test_unreadable_table_degrades_without_guessing(tmp_path, field, pointer, expected):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)]))
    table, codes = parse(tmp_path, patch(data, lay.header_field(field), '<I', pointer))
    assert rows(table) == expected and table.truncated and 'export_rva_out_of_file' in codes


def test_directory_header_outside_the_file_is_none(tmp_path):
    table, codes = parse(tmp_path, build_exports(RICH)[0], rva=0x7FFFF000)
    assert table is None and 'export_rva_out_of_file' in codes


def test_name_pointer_outside_the_file_drops_that_name_only(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010, 0x1020], names=[('a', 0), ('b', 1), ('c', 2)]))
    bad = patch(data, lay.off(lay.names_rva) + 4, '<I', 0x7FFFF000)
    table, codes = parse(tmp_path, bad)
    # slot 1 has a name we cannot read: it is neither named 'b' nor reported as ordinal-only
    assert rows(table) == [('a', 1, 0x1000, None), ('c', 3, 0x1020, None)]
    assert table.truncated and 'export_rva_out_of_file' in codes


def test_null_name_pointer_is_not_read_as_the_dos_header(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000], names=[('a', 0)]))
    table, _codes = parse(tmp_path, patch(data, lay.off(lay.names_rva), '<I', 0))
    assert rows(table) == [] and table.truncated


def test_table_cut_by_the_end_of_the_section_keeps_the_readable_prefix(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)]))
    # claim far more names than the section holds: the readable prefix is used, the rest is unknown
    table, codes = parse(tmp_path, patch(data, lay.header_field(H_NNAMES), '<I', 50))
    assert ('a', 1, 0x1000, None) in rows(table) and table.truncated and 'export_rva_out_of_file' in codes
    assert_sane(table)


# -- ordinal table and name table abuse ----------------------------------------------------------------

@pytest.mark.parametrize(('index', 'ordinal'), [(2, 3), (0xFFFF, 0x10000)], ids=['at-count', 'max-word'])
def test_name_index_outside_the_address_table_has_no_address(tmp_path, index, ordinal):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)]))
    table, codes = parse(tmp_path, patch(data, lay.off(lay.ords_rva) + 2, '<H', index))
    # 'b' still names a real ordinal 3 / 0x10000 per the table, but there is no such slot; slot 1 is now unnamed
    assert rows(table) == [('a', 1, 0x1000, None), (None, 2, 0x1010, None), ('b', ordinal, None, None)]
    assert 'export_ordinal_out_of_range' in codes


def test_ordinal_table_values_are_unbiased_indexes_and_the_last_one_is_valid(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)], base=7))
    table, codes = parse(tmp_path, patch(data, lay.off(lay.ords_rva), '<HH', 1, 0))  # swap the two bindings
    assert rows(table) == [('b', 7, 0x1000, None), ('a', 8, 0x1010, None)] and codes == set()


def test_repeated_name_pointer_is_a_loop_and_later_repeats_are_dropped(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010, 0x1020], names=[('a', 0), ('b', 1), ('c', 2)]))
    bad = patch(data, lay.off(lay.names_rva) + 4, '<I', lay.strings['a'])
    table, codes = parse(tmp_path, bad)
    assert rows(table) == [('a', 1, 0x1000, None), ('c', 3, 0x1020, None)]
    assert table.truncated and 'export_name_table_loop' in codes


def test_twenty_thousand_pointers_to_one_name_collapse(tmp_path):
    n = CAP
    spec = ExportSpec(functions=[0x1000] * n, names=[('same', i) for i in range(n)])
    started = time.monotonic()
    table, codes = parse(tmp_path, build_exports(spec)[0])
    assert time.monotonic() - started < 3
    assert rows(table) == [('same', 1, 0x1000, None)] and table.truncated and 'export_name_table_loop' in codes


def test_overlapping_tables_stay_bounded(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010, 0x1020], names=[('a', 0), ('b', 1), ('c', 2)]))
    bad = patch(data, lay.header_field(H_AON), '<II', lay.eat_rva, lay.eat_rva)  # names and ordinals read the EAT
    table, _codes = parse(tmp_path, bad)
    assert_sane(table)


def test_name_pointers_into_the_directory_itself_stay_bounded(tmp_path):
    data, lay = build_exports(ExportSpec(functions=[0x1000, 0x1010], names=[('a', 0), ('b', 1)]))
    bad = patch(data, lay.off(lay.names_rva), '<II', lay.names_rva, lay.header_rva)
    table, _codes = parse(tmp_path, bad)
    assert_sane(table)


# -- control flow and fuzz -----------------------------------------------------------------------------

def test_cancel_is_polled(tmp_path):
    with pytest.raises(Cancelled):
        parse(tmp_path, build_exports(RICH)[0], cancel=lambda: True)


@FAST
@given(edits=st.lists(st.one_of(
    st.tuples(st.integers(0, 39), st.integers(0, 255)),  # directory header bytes
    st.tuples(st.integers(0, 511), st.integers(0, 255)),  # tables and strings
), min_size=1, max_size=40), dwords=st.lists(st.tuples(
    st.integers(0, 9), st.sampled_from([0, 1, 5, 0xFFFF, 0x1000, 0x2000, 0x2100, 0x7FFFF000, 0xFFFFFFFF])),
    max_size=4))
def test_mutated_directories_never_raise(tmp_path, edits, dwords):
    data, lay = build_exports(RICH)
    bad = bytearray(data)
    for offset, value in edits:
        bad[lay.off(EDATA_RVA) + offset] = value
    for slot, value in dwords:
        struct.pack_into('<I', bad, lay.off(EDATA_RVA) + 4 * slot, value)
    started = time.monotonic()
    table, _codes = parse(tmp_path, bytes(bad))
    assert time.monotonic() - started < 5
    assert_sane(table)
    again, _ = parse(tmp_path, bytes(bad))
    assert again == table  # deterministic


def test_header_field_offsets_are_what_the_builder_wrote(tmp_path):
    data, lay = build_exports(RICH)
    base, nfuncs, nnames, aof, aon, aoo = struct.unpack_from('<IIIIII', data, lay.header_field(H_BASE))
    assert (base, nfuncs, nnames) == (10, 6, 4) and (aof, aon, aoo) == (lay.eat_rva, lay.names_rva, lay.ords_rva)


@st.composite
def export_specs(draw):
    """Random valid tables: code slots, gaps, forwarders, optional names and aliases, any small Base."""
    slots = draw(st.lists(st.one_of(
        st.none(), st.sampled_from([0x1000, 0x1010, 0x1020, 0x1030]),
        st.sampled_from(['NTDLL.Foo', 'KERNEL32.#17', 'api-ms-win-core-x.Bar'])), max_size=12))
    names = [(f'{prefix}{i:02d}', i) for i in range(len(slots))
             for prefix in ('Sym', 'Alias') if draw(st.booleans())]
    return ExportSpec(slots, sorted(names), draw(st.integers(0, 1000)), draw(st.booleans()))


def pefile_symbols(pefile, data: bytes) -> list[tuple]:
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    return sorted(((s.ordinal, s.name.decode('latin-1') if s.name else None,
                    None if s.forwarder else s.address, s.forwarder.decode('latin-1') if s.forwarder else None)
                   for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.address),  # pefile also lists empty slots
                  key=lambda t: (t[0], t[1] or ''))


def test_pefile_agrees_on_the_populated_slots(tmp_path):
    pefile = pytest.importorskip('pefile')
    data, _lay = build_exports(RICH)
    table, _codes = parse(tmp_path, data)
    assert [(e.ordinal, e.name, e.rva, e.forwarder) for e in table.entries] == pefile_symbols(pefile, data)


@FAST
@given(spec=export_specs())
def test_pefile_agrees_on_random_valid_tables(tmp_path, spec):
    pefile = pytest.importorskip('pefile')
    if not spec.names and not any(spec.functions):
        return  # pefile raises on a directory with nothing in it; there is nothing to compare
    data, _lay = build_exports(spec)
    table, codes = parse(tmp_path, data)
    ours = [(e.ordinal, e.name, e.rva, e.forwarder) for e in table.entries if e.rva or e.forwarder]
    assert ours == pefile_symbols(pefile, data) and not table.truncated and codes == set()
