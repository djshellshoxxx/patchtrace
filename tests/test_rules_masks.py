"""R4: byte patterns - the PE tables (`pe_overview/tables.py`), masks, the stand-in and the iced-x86 decoders, and byte
windows (`rules/{masks,window}.py`, `rules/adapters/mask_iced.py`; docs/specs/program-e/YRX-integration-plan.md s5 to s7).

Every image is SYNTHETIC and only ever read as bytes. The decoder is the stand-in of `tests/rules_fixtures.py`; the tests
that compare it with the real iced-x86 (and test its adapter) need `pip install iced-x86==1.21.0` and skip with a reason
without it - they are meant to run in CI once the integrator pins the decoder, and `test_decoder_pin_and_install_agree`
turns that skip into a failure the moment the pin appears in `pyproject.toml`.
"""
from __future__ import annotations

import dataclasses
import difflib
import os
import struct
import tomllib
from pathlib import Path

import pytest
import rules_fixtures as rf
from hypothesis import given, settings
from hypothesis import strategies as st
from pe_builder import CODE, RDATA, PeSpec, SectionSpec, build_pe_ex

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import tables as pt
from patchtrace.pe_overview.models import ImportDll, ImportsInfo
from patchtrace.rules import masks, window
from patchtrace.rules.contracts import FunctionRef, PairSource
from patchtrace.rules.errors import RuleError
from patchtrace.rules.limits import DEFAULT_LIMITS, RuleLimits
from patchtrace.rules.ports import DecodedInstruction, MaskSpan

ROOT = Path(__file__).resolve().parents[1]
DECODER = rf.SubsetDecoder()
TEXT_RVA, FILE_AT = 0x1000, 0x400


def hexed(*parts: str) -> bytes:
    return bytes.fromhex(''.join(parts))


def call_slot(at: int, slot: int, opcode: bytes = b'\xff\x15') -> bytes:
    """`call [rip+disp32]` placed at RVA `at` that goes through the import slot at RVA `slot`."""
    return opcode + struct.pack('<i', slot - (at + 6))


# --- pe_overview/tables.py -------------------------------------------------------------------------------------------

def pe_image(tmp_path, *, text=b'\xcc' * 0x100, pdata=b'', xdata=b'\x01\0\0\0', reloc=b'', imports=None,
             bss=False, pe32plus=True, name='img.dll'):
    """A DLL with .text (0x1000), .xdata (0x2000), .pdata (0x3000), .reloc (0x4000) and the builder's import section."""
    sections = [SectionSpec('.text', text, CODE), SectionSpec('.xdata', xdata, RDATA),
                SectionSpec('.pdata', pdata or b'\0' * 12, RDATA), SectionSpec('.reloc', reloc or b'\0' * 8, RDATA)]
    if bss:
        sections.append(SectionSpec('.bss', b'', 0xC0000080, virtual_size=0x40, raw_size=0))
    spec = PeSpec(pe32plus=pe32plus, kind='dll', sections=sections, imports=imports or {},
                  extra_directories={3: (0x3000, len(pdata)) if pdata else (0, 0),
                                     5: (0x4000, len(reloc)) if reloc else (0, 0)})
    data, info = build_pe_ex(spec)
    path = tmp_path / name
    path.write_bytes(data)
    reader = VerifiedArtifactReader.open_path(path)
    return pt.PeTables.open(reader), reader, info


def runtime_function(begin: int, end: int, unwind: int = 0x2000) -> bytes:
    return struct.pack('<III', begin, end, unwind)


def test_runtime_functions_chained_indirect_and_function_extents(tmp_path):
    chained = b'\x01\0\0\0' + b'\x21\0\0\0'   # two unwind records; the second has UNW_FLAG_CHAININFO (flags 4 << 3 | 1)
    pdata = (runtime_function(0x1000, 0x1010) + runtime_function(0x1010, 0x1020, 0x2004)
             + runtime_function(0x1020, 0x1030, 0x3001) + runtime_function(0, 0))
    tables, reader, _ = pe_image(tmp_path, pdata=pdata, xdata=chained)
    with reader:
        assert [(f.begin, f.end, f.chained) for f in tables.runtime_functions()] == [
            (0x1000, 0x1010, False), (0x1010, 0x1020, True), (0x1020, 0x1030, True)]
        assert tables.function_extent(0x1000) == 0x10
        assert tables.function_extent(0x1010) is None and tables.function_extent(0x1020) is None   # fragments
        assert tables.function_extent(0x1004) is None and tables.function_extent(0x5000) is None   # not a start


def test_a_pdata_entry_may_end_exactly_at_the_end_of_the_image(tmp_path):
    _, reader, info = pe_image(tmp_path)
    reader.close()
    end = info['size_of_image']
    tables, reader, _ = pe_image(tmp_path, pdata=runtime_function(0x1000, end), name='edge.dll')
    with reader:
        assert [(f.begin, f.end) for f in tables.runtime_functions()] == [(0x1000, end)]
    tables, reader, _ = pe_image(tmp_path, pdata=runtime_function(0x1000, end + 1), name='past.dll')
    with reader, pytest.raises(pt.PeTableError, match='out of range'):
        tables.runtime_functions()


def test_a_leaf_function_has_no_extent(tmp_path):
    tables, reader, _ = pe_image(tmp_path, pdata=runtime_function(0x1000, 0x1010))
    with reader:
        assert tables.function_extent(0x1040) is None   # code with no .pdata entry: the caller must say PT-RULE-MASK


@pytest.mark.parametrize('pdata,message', [
    (runtime_function(0x1010, 0x1000), 'out of range'), (runtime_function(0x1000, 0x20000000), 'out of range'),
], ids=['end-before-begin', 'past-the-image'])
def test_malformed_pdata_is_an_error_not_a_guess(tmp_path, pdata, message):
    tables, reader, _ = pe_image(tmp_path, pdata=pdata)
    with reader, pytest.raises(pt.PeTableError, match=message):
        tables.runtime_functions()


def test_pdata_of_an_other_architecture_is_not_read(tmp_path):
    tables, reader, _ = pe_image(tmp_path, pdata=runtime_function(0x1000, 0x1010), pe32plus=False)
    with reader:
        assert tables.runtime_functions() == [] and tables.function_extent(0x1000) is None


def test_relocations_types_widths_and_errors(tmp_path):
    reloc = struct.pack('<II', 0x1000, 16) + struct.pack('<4H', 0xA010, 0x3020, 0x5030, 0x0000)
    tables, reader, _ = pe_image(tmp_path, reloc=reloc)
    with reader:
        assert tables.relocations() == ([0x1010, 0x1020, 0x1030], [8, 4, 8])   # DIR64, HIGHLOW, unknown (8 bytes)
        assert any('type 5' in warning for warning in tables.warnings)
        assert tables.relocations() is tables.relocations()
    for bad in (struct.pack('<II', 0x1000, 4), struct.pack('<II', 0x1000, 9) + b'\0' * 8):
        broken, reader, _ = pe_image(tmp_path, reloc=bad, name='bad.dll')
        with reader, pytest.raises(pt.PeTableError, match='relocation'):
            broken.relocations()
    none, reader, _ = pe_image(tmp_path, name='none.dll')
    with reader:
        assert none.relocations() == ([], [])


def test_import_slots_are_the_loaders_iat_addresses(bench):
    older = rf.tables_of(bench, 'capa-api')['older']
    assert older.import_slots() == {0x2000: ('KERNEL32.dll', 'GetComputerNameA'),
                                    0x2008: ('KERNEL32.dll', 'GetModuleHandleA'),
                                    0x2010: ('KERNEL32.dll', 'GetProcAddress'),
                                    0x2018: ('KERNEL32.dll', 'TerminateProcess')}


def test_import_slots_agree_with_the_engines_own_pe_parser(bench):
    yara_x = pytest.importorskip('yara_x', reason='YARA-X is not installed')
    for pair in ('capa-api', 'floss-static', 'diec-toolchain'):
        for side, image in rf.tables_of(bench, pair).items():
            parsed = yara_x.Module('pe').invoke(bench.build(pair, side).data)
            theirs = {f['rva']: (d['library_name'], f['name']) for d in parsed['import_details']
                      for f in d['functions']}
            assert image.import_slots() == theirs and theirs, (pair, side)


def test_import_slots_for_two_dlls_ordinals_and_the_unreadable(tmp_path):
    tables, reader, info = pe_image(tmp_path, imports={'A.dll': ['One', 12], 'B.dll': ['Two']})
    with reader:
        slots = tables.import_slots()
        assert sorted(slots.values()) == [('A.dll', '#12'), ('A.dll', 'One'), ('B.dll', 'Two')]
        assert len(slots) == 3 and all(slot % 8 == 0 for slot in slots)
        info_ = tables.overview.imports
        broken = (dataclasses.replace(info_, truncated=True),
                  dataclasses.replace(info_, dlls=(dataclasses.replace(info_.dlls[0], truncated=True),
                                                   *info_.dlls[1:])))
        for bad in broken:
            assert pt.PeTables(reader, dataclasses.replace(tables.overview, imports=bad)).import_slots() == {}
        placeholder = ImportsInfo((ImportDll('A.dll', ('<unreadable @ 0x1>', 'Real'), 2, False),), 1, 2, False)
        only_real = pt.PeTables(reader, dataclasses.replace(tables.overview, imports=placeholder)).import_slots()
        assert list(only_real.values()) == [('A.dll', 'Real')]
        no_dll = ImportsInfo((ImportDll('<unreadable name @ 0x1>', ('X',), 1, False),), 1, 1, False)
        assert pt.PeTables(reader, dataclasses.replace(tables.overview, imports=no_dll)).import_slots() == {}
    plain, reader, _ = pe_image(tmp_path, name='plain.dll')
    with reader:
        assert plain.import_slots() == {}


def test_import_slots_of_a_32_bit_image_are_four_bytes_apart(tmp_path):
    tables, reader, _ = pe_image(tmp_path, imports={'A.dll': ['One', 'Two', 'Three']}, pe32plus=False)
    with reader:
        slots = sorted(tables.import_slots())
        assert [b - a for a, b in zip(slots, slots[1:], strict=False)] == [4, 4] and len(slots) == 3


def test_an_import_whose_iat_address_is_missing_has_no_slots(tmp_path):
    tables, reader, info = pe_image(tmp_path, imports={'A.dll': ['One'], 'B.dll': ['Two']})
    reader.close()
    data = bytearray((tmp_path / 'img.dll').read_bytes())
    struct.pack_into('<I', data, info['import_desc_off'] + 16, 0)               # FirstThunk of the first descriptor
    (tmp_path / 'patched.dll').write_bytes(bytes(data))
    with VerifiedArtifactReader.open_path(tmp_path / 'patched.dll') as patched:
        assert list(pt.PeTables.open(patched).import_slots().values()) == [('B.dll', 'Two')]


def test_a_read_across_two_sections_is_not_one_function(tmp_path):
    tables, reader, _ = pe_image(tmp_path)
    with reader:
        def info(name, va, raw):
            return dataclasses.replace(tables.overview.sections[0], name=name, virtual_address=va, virtual_size=0x100,
                                       raw_offset=raw, raw_size=0x100)
        apart = dataclasses.replace(tables.overview, sections=(info('.a', 0x1000, 0x400), info('.b', 0x1100, 0x800)))
        two = pt.PeTables(reader, apart)
        assert two.read_backed(0x10f0, 0x10) is not None and two.read_backed(0x1100, 0x10) is not None
        assert two.read_backed(0x10f0, 0x20) is None                           # contiguous RVAs, unrelated file bytes


def test_read_backed_never_returns_zero_fill(tmp_path):
    tables, reader, _ = pe_image(tmp_path, text=bytes(range(256)), bss=True)
    with reader:
        assert tables.read_backed(0x1010, 4) == bytes([16, 17, 18, 19])
        bss = next(s for s in tables.overview.sections if s.name == '.bss')
        assert tables.read_rva(bss.virtual_address, 0x40) == bytes(0x40) and tables.read_backed(
            bss.virtual_address, 0x40) is None                       # zero-filled: the file holds no such bytes
        assert tables.read_backed(0x1000 + 0x100 - 2, 8) is None      # runs off the section's raw data
        assert tables.read_backed(2**32 - 2, 8) is None
        with pytest.raises(pt.PeTableError):
            tables.read_rva(2**32 - 4, 8)


def test_executable_sections_are_the_ones_marked_executable(tmp_path):
    tables, reader, _ = pe_image(tmp_path, text=b'\x90' * 0x20)
    with reader:
        (offset, data), = tables.executable_sections()
        assert (offset, data[:0x20]) == (FILE_AT, b'\x90' * 0x20) and tables.rva_to_offset(0x1004) == FILE_AT + 4


def test_a_file_that_is_not_a_pe_has_no_tables(tmp_path):
    path = tmp_path / 'junk.bin'
    path.write_bytes(b'not a pe file at all' * 10)
    with VerifiedArtifactReader.open_path(path) as reader, pytest.raises(pt.PeTableError):
        pt.PeTables.open(reader)


def test_oversize_directories_are_refused(tmp_path):
    tables, reader, _ = pe_image(tmp_path, pdata=runtime_function(0x1000, 0x1010))
    huge = dataclasses.replace(tables.overview, data_directories=tuple(
        dataclasses.replace(d, size=pt.MAX_TABLE + 1) if d.name == 'Exception' else d
        for d in tables.overview.data_directories))
    with reader, pytest.raises(pt.PeTableError, match='larger'):
        pt.PeTables(reader, huge).runtime_functions()


# --- decoders --------------------------------------------------------------------------------------------------------

INSIDE = hexed('4883ec28', '48c7c1ffffffff', '31d2', 'ff15f8ffffff', '4883c428c3', 'e800000000', '488d0d10000000',
               '833d10000000ff', '7202', 'ebfe', '0f8400000000', 'e900000000', 'ff2500000000', 'ffd0', '4989c1',
               '48b8efcdab8967452301', '8034015a')
R = MaskSpan
EXPECTED_INSIDE = (   # hand-checked against the instruction encodings; ip = 0x1000, targets are RVAs
    DecodedInstruction(0, 4, 'next'), DecodedInstruction(4, 7, 'next'), DecodedInstruction(11, 2, 'next'),
    DecodedInstruction(13, 6, 'indirect-call', (R(2, 4, 'rip-disp'),), 0x100b),
    DecodedInstruction(19, 4, 'next'), DecodedInstruction(23, 1, 'return'),
    DecodedInstruction(24, 5, 'call', (), 0x101d),
    DecodedInstruction(29, 7, 'next', (R(3, 4, 'rip-disp'),), 0x1034),
    DecodedInstruction(36, 7, 'next', (R(2, 4, 'rip-disp'),), 0x103b),   # cmp [rip+d], imm8: the displacement is not last
    DecodedInstruction(43, 2, 'conditional', (), 0x102f), DecodedInstruction(45, 2, 'branch', (), 0x102d),
    DecodedInstruction(47, 6, 'conditional', (), 0x1035), DecodedInstruction(53, 5, 'branch', (), 0x103a),
    DecodedInstruction(58, 6, 'indirect-branch', (R(2, 4, 'rip-disp'),), 0x1040),
    DecodedInstruction(64, 2, 'indirect-call'), DecodedInstruction(66, 3, 'next'),
    DecodedInstruction(69, 10, 'next'), DecodedInstruction(79, 4, 'next'))
# Branches that leave the body: `call +0xff0`, `jmp short +0x7f`, `jne +0x1000`, `jae +0` (inside), `ret`.
OUTSIDE = hexed('e8f00f0000', 'eb7f', '0f8500100000', '7300', 'c3')
EXPECTED_OUTSIDE = (
    DecodedInstruction(0, 5, 'call', (R(1, 4, 'branch-ext'),), 0x1ff5),
    DecodedInstruction(5, 2, 'branch', (R(1, 1, 'branch-ext'),), 0x1086),
    DecodedInstruction(7, 6, 'conditional', (R(2, 4, 'branch-ext'),), 0x200d),
    DecodedInstruction(13, 2, 'conditional', (), 0x100f), DecodedInstruction(15, 1, 'return'))


# The edges of "inside the body": a jump to its first byte stays inside, a jump to the byte after its last leaves it.
EDGES = hexed('eb04', '90', '90', 'ebfa')
EXPECTED_EDGES = (DecodedInstruction(0, 2, 'branch', (R(1, 1, 'branch-ext'),), 0x1006), DecodedInstruction(2, 1, 'next'),
                  DecodedInstruction(3, 1, 'next'), DecodedInstruction(4, 2, 'branch', (), 0x1000))


@pytest.mark.parametrize('code,expected', [(INSIDE, EXPECTED_INSIDE), (OUTSIDE, EXPECTED_OUTSIDE),
                                           (EDGES, EXPECTED_EDGES)], ids=['in-body', 'leaving-the-body', 'edges'])
def test_the_stand_in_decoder_follows_the_mask_source_contract(code, expected):
    assert DECODER.decode(code, TEXT_RVA) == expected


def test_the_stand_in_refuses_what_it_does_not_know():
    for code in (b'\x0f\x0b', b'\x48\x83', b'\x48\x8d\x0d\x01', b'\x62'):   # ud2, cut short x2, EVEX
        with pytest.raises(RuleError) as caught:
            DECODER.decode(code, TEXT_RVA)
        assert caught.value.code == 'PT-RULE-DECODE'


def fixture_text(bench, pair: str, side: str) -> tuple[int, bytes]:
    build = bench.build(pair, side)
    text = next(s for s in build.overview.sections if s.name == '.text')
    return text.virtual_address, build.data[text.raw_offset:text.raw_offset + text.virtual_size]


@pytest.fixture
def iced():
    pytest.importorskip('iced_x86', reason='iced-x86 is not installed (the decoder pin is an integrator step)')
    from patchtrace.rules.adapters.mask_iced import IcedMaskSource
    return IcedMaskSource()


def test_iced_adapter_reports_exactly_the_expected_fields(iced):
    assert iced.name == 'iced-x86' and iced.version
    assert iced.decode(INSIDE, TEXT_RVA) == EXPECTED_INSIDE
    assert iced.decode(OUTSIDE, TEXT_RVA) == EXPECTED_OUTSIDE
    assert iced.decode(EDGES, TEXT_RVA) == EXPECTED_EDGES


def test_iced_adapter_states_the_installed_version_or_the_pin(iced, monkeypatch):
    import importlib.metadata

    from patchtrace.rules.adapters import mask_iced
    assert iced.version == importlib.metadata.version('iced-x86')

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)
    monkeypatch.setattr(mask_iced.metadata, 'version', missing)
    assert iced.version == '1.21.0'                                       # a frozen build without distribution metadata


@pytest.mark.parametrize('pair,side', [('capa-api', 'older'), ('capa-api', 'newer'), ('capa-control', 'newer'),
                                       ('floss-static', 'older'), ('floss-decode', 'older'),
                                       ('diec-toolchain', 'newer')],
                         ids=['capa-older', 'capa-newer', 'control', 'strings', 'decode', 'gnu-layout'])
def test_the_stand_in_equals_iced_on_every_fixture_image(iced, bench, pair, side):
    rva, text = fixture_text(bench, pair, side)
    assert DECODER.decode(text, rva) == iced.decode(text, rva)


def test_iced_adapter_invalid_and_truncated_bytes_are_decode_errors(iced):
    for code in (b'\x48\x83\xec', b'\x06', b'\xff'):
        with pytest.raises(RuleError) as caught:
            iced.decode(code, TEXT_RVA)
        assert (caught.value.code, caught.value.reason) == ('PT-RULE-DECODE', 'invalid-instruction')
    assert iced.decode(b'', TEXT_RVA) == ()


@pytest.mark.parametrize('decoder_name', ['stand-in', 'iced'])
def test_targets_outside_32_bits_are_not_rvas(request, decoder_name):
    decoder = DECODER if decoder_name == 'stand-in' else request.getfixturevalue('iced')
    near = decoder.decode(hexed('488d0d00000000'), 0x10)             # lea rcx,[rip+0] at a tiny rva stays an rva
    assert near[0].target_rva == 0x17
    behind = decoder.decode(hexed('488d0d00f0ffff'), 0x10)           # rip-0x1000 lands below zero: not an address
    assert behind[0].target_rva is None and behind[0].spans == (R(3, 4, 'rip-disp'),)
    last = decoder.decode(hexed('488d0d09000000'), 0xFFFFFFF0)       # the target is exactly 2**32: one past the last RVA
    assert last[0].target_rva is None
    assert decoder.decode(hexed('488d0d08000000'), 0xFFFFFFF0)[0].target_rva == 0xFFFFFFFF


def test_decoder_pin_and_install_agree():
    """Once `iced-x86` is a declared dependency, the tests above must not be skipped in CI."""
    project = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))['project']
    declared = [*project.get('dependencies', []), *(d for group in project.get('optional-dependencies', {}).values()
                                                     for d in group)]
    if not any(d.lower().replace('_', '-').startswith('iced-x86') for d in declared):
        pytest.skip('iced-x86 is not declared in pyproject.toml yet (integrator: pin iced-x86==1.21.0)')
    try:
        import iced_x86  # noqa: F401
    except ImportError:
        if os.environ.get('CI'):
            pytest.fail('iced-x86 is declared in pyproject.toml but is not installed in the QA matrix')
        pytest.skip('iced-x86 is declared but not installed locally')


# --- masks -----------------------------------------------------------------------------------------------------------

# The function bodies of the capa-api images (RVA, size), per side: label to label in tests/test_intel_tools_pe.py.
BODIES = {'older': {'main': (0x1000, 48), 'host': (0x1030, 29), 'term': (0x104d, 24), 'dyn': (0x1065, 38),
                    'log': (0x108b, 3), 'xor': (0x108e, 15)},
          'newer': {'main': (0x1000, 48), 'env': (0x1030, 35), 'host': (0x1053, 29), 'dyn': (0x1070, 38),
                    'log': (0x1096, 38), 'xor': (0x10bc, 15)}}
GOLDEN_PATTERNS = {
    ('older', 'term'): '48 83 EC 28 48 C7 C1 FF FF FF FF 31 D2 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3',
    ('older', 'log'): '31 C0 C3',
    ('older', 'host'): '48 83 EC 28 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 83 C4 28 C3',
    ('older', 'dyn'): ('48 83 EC 28 48 8D 0D ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 89 C1 48 8D 15 ?? ?? ?? ?? FF 15 ?? ?? '
                       '?? ?? 48 83 C4 28 C3'),
    ('older', 'main'): ('48 83 EC 28 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? '
                        'BA 10 00 00 00 E8 ?? ?? ?? ?? 48 83 C4 28 31 C0 C3'),
    ('older', 'xor'): '31 C0 80 34 01 5A 48 FF C0 48 39 D0 72 F4 C3',   # the loop's own `jb` is kept: it stays inside
    ('newer', 'env'): ('48 83 EC 28 48 8D 0D ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 41 B8 10 00 00 00 FF 15 ?? ?? ?? ?? '
                       '48 83 C4 28 C3'),
    ('newer', 'log'): ('48 83 EC 28 48 C7 C1 F5 FF FF FF 48 8D 15 ?? ?? ?? ?? 41 B8 08 00 00 00 45 31 C9 FF 15 ?? ?? '
                       '?? ?? 48 83 C4 28 C3'),
}


def masked_body(bench, side: str, name: str) -> masks.MaskedFunction:
    image = rf.tables_of(bench, 'capa-api')[side]
    rva, size = BODIES[side][name]
    code = image.read_backed(rva, size)
    return masks.mask_function(code, rva, DECODER.decode(code, rva), image.relocations())


@pytest.fixture
def bench(tmp_path):
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.mark.parametrize('key', sorted(GOLDEN_PATTERNS), ids=lambda key: '-'.join(key))
def test_golden_masks_of_the_fixture_functions(bench, key):
    side, name = key
    function = masked_body(bench, side, name)
    assert ' '.join(function.tokens(0, len(function.instructions))) == GOLDEN_PATTERNS[key]
    assert function.size == BODIES[side][name][1]


def test_unchanged_functions_have_equal_masked_patterns_on_both_builds(bench):
    # host, dyn and xor are the same code at other addresses; main differs only in WHICH function it calls (masked)
    for name in ('main', 'host', 'dyn', 'xor'):
        older, newer = masked_body(bench, 'older', name), masked_body(bench, 'newer', name)
        assert older.tokens(0, len(older.instructions)) == newer.tokens(0, len(newer.instructions)), name


def test_a_rebuild_at_another_layout_has_the_same_pattern_exact_bytes_do_not(bench):
    older = rf.tables_of(bench, 'capa-api')['older']
    rebuilt = rf.tables_of(bench, 'capa-control')['newer']          # the same code, 0x40 further on, other IAT offsets
    code_a, code_b = older.read_backed(0x104d, 24), rebuilt.read_backed(0x108d, 24)
    assert code_a != code_b                                            # the displacement bytes differ
    fa = masks.mask_function(code_a, 0x104d, DECODER.decode(code_a, 0x104d), older.relocations())
    fb = masks.mask_function(code_b, 0x108d, DECODER.decode(code_b, 0x108d), rebuilt.relocations())
    assert [i.tokens for i in fa.instructions] == [i.tokens for i in fb.instructions]
    assert fa.kinds(0, len(fa.instructions)) == ('rip-disp',)


def pattern_of(code: bytes) -> list[tuple[str, ...]]:
    return [i.tokens for i in masks.mask_function(code, 0x2000, DECODER.decode(code, 0x2000)).instructions]


@settings(max_examples=60, deadline=None)
@given(st.integers(-2**31, 2**31 - 1), st.integers(0x100, 0x7FFFFF), st.integers(-2**31, 2**31 - 1))
def test_the_values_of_masked_fields_never_change_the_pattern(disp, rel, other_disp):
    """A rebuild moves what the loader and the linker place: RIP displacements and calls out of the function."""
    def body(lea: int, call: int, slot: int) -> bytes:
        return (b'\x48\x8d\x0d' + struct.pack('<i', lea) + b'\xe8' + struct.pack('<i', call) + b'\xff\x15'
                + struct.pack('<i', slot) + b'\xc3')
    assert pattern_of(body(disp, rel, other_disp)) == pattern_of(body(0, 0x1000, 0x2000))
    assert pattern_of(body(0, 0x1000, 0x2000))[1] == ('E8', '??', '??', '??', '??')


def test_immediates_are_kept(bench):
    function = masked_body(bench, 'older', 'term')
    assert function.instructions[1].tokens == ('48', 'C7', 'C1', 'FF', 'FF', 'FF', 'FF') and not function.instructions[
        1].kinds
    changed = bytearray(rf.tables_of(bench, 'capa-api')['older'].read_backed(0x104d, 24))
    changed[7] = 0x00                                                  # the immediate of `mov rcx, -1`
    other = masks.mask_function(bytes(changed), 0x104d, DECODER.decode(bytes(changed), 0x104d))
    assert other.instructions[1].tokens != function.instructions[1].tokens


def test_base_relocations_mask_only_the_bytes_they_cover():
    code = hexed('48b8efcdab8967452301', '4883c428', 'c3')              # mov rax, imm64 | add rsp,0x28 | ret
    decoded = DECODER.decode(code, 0x3000)
    plain = masks.mask_function(code, 0x3000, decoded)
    assert not any(i.kinds for i in plain.instructions)
    covered = masks.mask_function(code, 0x3000, decoded, ([0x3002], [8]))
    assert covered.instructions[0].tokens == ('48', 'B8', *['??'] * 8) and covered.instructions[0].kinds == ('reloc',)
    edges = masks.mask_function(code, 0x3000, decoded, ([0x2FFE, 0x3008], [4, 8]))   # starts before / runs past
    assert edges.instructions[0].tokens == ('??', '??', 'EF', 'CD', 'AB', '89', '67', '45', '??', '??')
    assert edges.instructions[1].tokens == ('??',) * 4 and edges.instructions[2].tokens == ('??',)
    assert masks.mask_function(code, 0x3000, decoded, ([0x3001], [0])).instructions[0].kinds == ()
    far = masks.mask_function(code, 0x3000, decoded, ([0x2000, 0x4000], [8, 8]))
    assert not any(i.kinds for i in far.instructions)


def test_rip_displacements_and_relocations_both_apply():
    code = hexed('488d0d00000000', 'c3')
    decoded = DECODER.decode(code, 0x3000)
    function = masks.mask_function(code, 0x3000, decoded, ([0x3002], [8]))
    assert function.instructions[0].tokens == ('48', '8D', '??', '??', '??', '??', '??') and function.instructions[
        0].kinds == ('reloc', 'rip-disp')


@pytest.mark.parametrize('decoded,reason', [
    ((DecodedInstruction(1, 3, 'next'),), 'decoder-gap'), ((DecodedInstruction(0, 2, 'next'),), 'decoder-short'),
    ((DecodedInstruction(0, 5, 'next'),), 'decoder-gap'),
    ((DecodedInstruction(0, 3, 'next'), DecodedInstruction(2, 1, 'next')), 'decoder-gap'),
    ((DecodedInstruction(1, 1, 'next'), DecodedInstruction(0, 2, 'next')), 'decoder-gap'),   # sizes add up, order does not
    ((DecodedInstruction(0, 0, 'next'),), 'decoder-gap'),
    ((DecodedInstruction(0, 3, 'next', (R(2, 4, 'rip-disp'),)),), 'span-outside'),
    ((DecodedInstruction(0, 3, 'next', (R(1, 0, 'rip-disp'),)),), 'span-outside')],
    ids=['starts-late', 'too-short', 'too-long', 'overlap', 'out-of-order', 'empty-instruction', 'span-outside',
         'empty-span'])
def test_decoded_instructions_must_tile_the_body(decoded, reason):
    with pytest.raises(RuleError) as caught:
        masks.mask_function(b'\x90\x90\x90', 0x1000, decoded)
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-DECODE', reason)


def test_a_pin_needs_a_four_byte_displacement():
    code = hexed('ff15', '0000', '9090')
    short = DecodedInstruction(0, 4, 'indirect-call', (R(2, 2, 'rip-disp'),), 0x2000)   # no real decoder says this
    function = masks.mask_function(code, 0x1000, (short, DecodedInstruction(4, 2, 'next')))
    assert masks.call_pins(function, 0, 2, {0x2000: ('A.dll', 'N')}) == ()


def test_call_pins_name_the_import_a_masked_call_goes_through(bench):
    image = rf.tables_of(bench, 'capa-api')['older']
    function = masked_body(bench, 'older', 'term')
    slots = image.import_slots()
    (pin,) = masks.call_pins(function, 0, len(function.instructions), slots)
    assert (pin.disp_offset, pin.end_offset, pin.dll, pin.name) == (15, 19, 'KERNEL32.dll', 'TerminateProcess')
    # inside a window that starts later the offsets are relative to the window
    (shifted,) = masks.call_pins(function, 2, len(function.instructions), slots)
    assert (shifted.disp_offset, shifted.end_offset) == (15 - 11, 19 - 11)
    assert masks.call_pins(function, 0, 3, slots) == () and masks.call_pins(function, 0, 0, slots) == ()


def test_only_calls_through_named_import_slots_are_pinned():
    # calls through slots 0x2000 (named), 0x2008 (ordinal) and 0x2010 (not an import); a lea of a slot; a jmp through one
    base = 0x1000
    code = (call_slot(base, 0x2000) + call_slot(base + 6, 0x2008) + call_slot(base + 12, 0x2010)
            + b'\x48\x8d\x0d' + struct.pack('<i', 0x2000 - (base + 18 + 7)) + call_slot(base + 25, 0x2018, b'\xff\x25'))
    function = masks.mask_function(code, base, DECODER.decode(code, base))
    slots = {0x2000: ('A.dll', 'Named'), 0x2008: ('A.dll', '#7'), 0x2018: ('A.dll', 'Jumped')}
    assert [i.target_rva for i in function.instructions] == [0x2000, 0x2008, 0x2010, 0x2000, 0x2018]
    assert [(p.name, p.disp_offset) for p in masks.call_pins(function, 0, 5, slots)] == [('Named', 2)]
    many = b''.join(call_slot(base + 6 * i, 0x2000) for i in range(6))
    chain = masks.mask_function(many, base, DECODER.decode(many, base))
    assert len(masks.call_pins(chain, 0, 6, {0x2000: ('A.dll', 'N')}, limit=4)) == 4
    assert len(masks.call_pins(chain, 0, 6, {0x2000: ('A.dll', 'N')})) == DEFAULT_LIMITS.pins_per_feature


# --- byte windows ----------------------------------------------------------------------------------------------------

def mov(k: int) -> bytes:
    """`mov rax, imm32`: 7 bytes, all literal, distinct for every `k` (the bricks of the synthetic bodies)."""
    return b'\x48\xc7\xc0' + struct.pack('<I', k)


def body(*ks: int) -> bytes:
    return b''.join(mov(k) for k in ks)


def lea_to(at: int, target: int) -> bytes:
    """`lea rcx, [rip+disp32]` at RVA `at` that reads RVA `target`."""
    return b'\x48\x8d\x0d' + struct.pack('<i', target - (at + 7))


class FakeImage:
    """A `BuildImage` over a flat code blob at RVA 0x1000 (file offset 0x400); import slots live at RVA 0x2000+."""

    def __init__(self, text: bytes, sha: str, *, extents=None, slots=None, relocs=None, broken=False):
        self.text, self.sha256, self._extents = text, sha, extents or {}
        self._slots, self._relocs, self._broken = slots or {}, relocs or ([], []), broken
        self.reads = 0

    def read_backed(self, rva, length):
        start = rva - TEXT_RVA
        return self.text[start:start + length] if start >= 0 and start + length <= len(self.text) else None

    def function_extent(self, rva):
        if self._broken:
            raise ValueError('bad .pdata')
        return self._extents.get(rva)

    def relocations(self):
        if self._broken:
            raise ValueError('bad .reloc')
        return self._relocs

    def import_slots(self):
        return self._slots

    def rva_to_offset(self, rva):
        if 0 <= rva - TEXT_RVA < len(self.text):
            return FILE_AT + rva - TEXT_RVA
        return 0x800 + rva - 0x2000 if 0x2000 <= rva < 0x3000 else None

    def executable_sections(self):
        self.reads += 1
        yield FILE_AT, self.text


OLDER, NEWER = 'a' * 64, 'b' * 64


def fake_pair(older=None, newer=None, category='modified') -> PairSource:
    return PairSource(project_id='p', revision=1, run_id='r', older_sha256=OLDER, newer_sha256=NEWER, match_id='m',
                      category=category, review='accepted', materiality='material', analyst_confirmed_material=False,
                      older=older, newer=newer)


def ref(rva: int, size: int, extent: str = 'pdata') -> FunctionRef:
    return FunctionRef(rva=rva, size=size, extent=extent)


def tool_for(older_text: bytes, newer_text: bytes, **kw) -> window.BytesWindows:
    return window.BytesWindows(DECODER, {'older': FakeImage(older_text, OLDER, **kw),
                                         'newer': FakeImage(newer_text, NEWER, **kw)})


def gap(n: int = 0x40) -> bytes:
    return b'\xcc' * n


def pattern(*ks: int) -> str:
    return ' '.join(f'{b:02X}' for b in body(*ks))


def test_a_changed_instruction_is_kept_with_one_instruction_of_context_each_side():
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    tool = tool_for(body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7))
    (found,) = tool.windows(pair, 'older').windows
    assert (found.window_rva, found.length, found.literal, found.longest_run) == (0x1007, 21, 21, 21)
    assert found.pattern == pattern(2, 3, 4) and found.mask == () and found.pins == ()
    assert (found.source_hits, found.other_hits, found.separation, found.side) == (1, 0, 'older-only', 'older')
    (newer,) = tool.windows(pair, 'newer').windows
    assert (newer.pattern, newer.separation, newer.side) == (pattern(2, 0x99, 4), 'newer-only', 'newer')


def test_a_change_at_the_edge_has_context_on_one_side_only_and_grows_to_the_checks():
    pair = fake_pair(ref(0x1000, 28), ref(0x1000, 28))
    tool = tool_for(body(1, 2, 3, 4), body(0x99, 2, 3, 4))
    (found,) = tool.windows(pair, 'older').windows
    assert (found.window_rva, found.pattern) == (0x1000, pattern(1, 2, 3))   # 14 literal bytes fail `len`: one more after


def test_growth_alternates_after_then_before_until_the_window_is_unique():
    f_old, f_new = body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7)
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    decoy = body(0x50, 2, 3, 4, 0x51)                         # I2 I3 I4 again, followed by something else
    (found,) = tool_for(f_old + gap() + decoy, f_new + gap() + decoy).windows(pair, 'older').windows
    assert (found.window_rva, found.length, found.source_hits, found.other_hits) == (0x1007, 28, 1, 0)   # I2..I5
    decoy = body(0x51, 2, 3, 4, 5)                            # I2..I5 again, but not preceded by I1
    (found,) = tool_for(f_old + gap() + decoy, f_new + gap() + decoy).windows(pair, 'older').windows
    assert (found.window_rva, found.length, found.source_hits) == (0x1000, 35, 1)                       # I1..I5


def test_a_window_found_in_the_other_build_is_grown_or_rejected():
    f_old, f_new = body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7)
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    (found,) = tool_for(f_old, f_new + gap() + body(2, 3, 4)).windows(pair, 'older').windows   # I2 I3 I4 are there
    assert (found.length, found.other_hits) == (28, 0)                                           # grown past it
    removed = fake_pair(ref(0x1000, 49), None, 'removed')
    result = tool_for(f_old, gap() + f_old).windows(removed, 'older')                           # the whole function is there
    assert result.windows == () and [(g.gate_id, g.state, g.measured) for g in result.failures] == [('sep', 'fail', 1)]


def spy_on_count(monkeypatch) -> list[tuple[str, int]]:
    calls = []
    real = window.BytesWindows.count

    def count(self, side, tokens):
        calls.append((side, len(tokens)))
        return real(self, side, tokens)
    monkeypatch.setattr(window.BytesWindows, 'count', count)
    return calls


def test_the_cap_stops_growth_and_the_failure_names_the_check(monkeypatch):
    ks = list(range(1, 31))                                   # 30 instructions: 210 bytes, the change in the middle
    pair = fake_pair(ref(0x1000, 210), ref(0x1000, 210))
    tool = tool_for(body(*ks) + gap() + body(*ks), body(*ks[:15], 0x99, *ks[16:]))   # every window exists twice
    calls = spy_on_count(monkeypatch)
    result = tool.windows(pair, 'older')
    assert result.windows == () and max(size for _, size in calls) == 126          # 21 bytes grown by 7, under the cap
    assert [(g.gate_id, g.state, g.measured) for g in result.failures] == [('uniq', 'fail', 2)]


def test_a_long_removed_function_gets_the_best_non_overlapping_windows():
    removed = fake_pair(ref(0x1000, 280), None, 'removed')                          # 40 distinct instructions
    result = tool_for(body(*range(1, 41)), body(*range(100, 110))).windows(removed, 'older')
    assert [(w.window_rva, w.length, w.literal) for w in result.windows] == [
        (0x1000, 126, 126), (0x1000 + 126, 126, 126), (0x1000 + 252, 28, 28)]
    assert all(w.source_hits == 1 and w.other_hits == 0 for w in result.windows)
    spans = [(w.window_rva, w.window_rva + w.length) for w in result.windows]
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:], strict=False))


def test_the_evaluation_budget_bounds_the_work_on_a_body_of_look_alikes(monkeypatch):
    removed = fake_pair(ref(0x1000, 700), None, 'removed')
    calls = spy_on_count(monkeypatch)
    result = tool_for(body(*[7] * 100), body(1, 2, 3, 4)).windows(removed, 'older')   # one instruction, 100 times
    assert result.windows == () and 0 < len(calls) <= 2 * window.MAX_EVALUATIONS
    assert (result.failures[0].gate_id, result.failures[0].measured) == ('uniq', DEFAULT_LIMITS.max_matches_per_pattern)


def test_two_close_changes_share_one_window_two_far_ones_get_two():
    pair = fake_pair(ref(0x1000, 84), ref(0x1000, 84))
    old = body(*range(1, 13))
    close = body(1, 2, 0x91, 4, 0x92, 6, 7, 8, 9, 10, 11, 12)               # I3 and I5 changed
    far = body(1, 0x91, 3, 4, 5, 6, 7, 8, 9, 10, 0x92, 12)                  # I2 and I11 changed
    assert [w.window_rva for w in tool_for(old, close).windows(pair, 'older').windows] == [0x1007]
    assert [(w.window_rva, w.length) for w in tool_for(old, far).windows(pair, 'older').windows] == [
        (0x1000, 21), (0x1000 + 63, 21)]


def test_a_pure_rebuild_has_no_changed_range_so_no_window_and_nothing_to_report():
    older = body(1, 2) + lea_to(0x100e, 0x2000) + body(3, 4)
    newer = body(1, 2) + lea_to(0x100e, 0x2140) + body(3, 4)                # only the RIP displacement moved
    pair = fake_pair(ref(0x1000, 35), ref(0x1000, 35))
    result = tool_for(older, newer).windows(pair, 'older')
    assert (result.windows, result.failures) == ((), ()) and older != newer


def test_a_body_too_short_for_a_pattern_names_the_failed_check():
    removed = fake_pair(ref(0x1000, 14), None, 'removed')
    (failure,) = tool_for(body(1, 2), body(9)).windows(removed, 'older').failures
    assert (failure.gate_id, failure.state, failure.measured) == ('len', 'fail', 14)
    assert failure.detail == '14 literal bytes, longest run 14'


def test_pins_and_referenced_offsets_follow_the_window():
    call = b'\xff\x15' + struct.pack('<i', 0x2000 - (0x1015 + 6))
    code = body(1, 2, 3) + call + lea_to(0x101b, 0x2100) + body(4) + b'\xe8' + struct.pack('<i', 0x100)   # a call, too
    removed = fake_pair(ref(0x1000, len(code)), None, 'removed')
    tool = tool_for(code + gap(0x200), body(9), slots={0x2000: ('KERNEL32.dll', 'WriteFile')})
    result = tool.windows(removed, 'older')
    (found,) = result.windows
    assert [(p.disp_offset, p.end_offset, p.dll, p.name) for p in found.pins] == [(23, 27, 'KERNEL32.dll', 'WriteFile')]
    assert found.mask == ('branch-ext', 'rip-disp') and found.pattern.count('??') == 12
    # the slot and the data the RIP-relative operands read; the target of the call out of the body is not "read"
    assert result.referenced_offsets == frozenset({0x800, 0x900})
    assert result.decoder == ('iced-x86', 'standin')


@pytest.mark.parametrize('case', ['leaf', 'huge', 'unbacked', 'moved', 'no-image', 'extent', 'tables', 'garbage',
                                  'direction'])
def test_bytes_that_cannot_be_trusted_are_typed_errors(case):
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    older, newer = body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7)
    tool = tool_for(older, newer)
    expected = {'leaf': ('PT-RULE-MASK', 'no-extent'), 'huge': ('PT-RULE-LIMIT', 'function-size'),
                'unbacked': ('PT-RULE-MASK', 'not-backed'), 'moved': ('PT-RULE-STALE', 'artifact-moved'),
                'no-image': ('PT-RULE-MASK', 'no-image'), 'extent': ('PT-RULE-STALE', 'extent-differs'),
                'tables': ('PT-RULE-MASK', 'table-unreadable'), 'garbage': ('PT-RULE-DECODE', 'standin'),
                'direction': ('PT-RULE-INPUT', 'direction')}[case]
    direction = 'older'
    if case == 'leaf':
        pair = fake_pair(FunctionRef(rva=0x1000, extent='unknown'), ref(0x1000, 49))
    elif case == 'huge':
        pair = fake_pair(ref(0x1000, 64 * 1024 + 1), ref(0x1000, 49))
    elif case == 'unbacked':
        tool = tool_for(older[:20], newer)
    elif case == 'moved':
        tool = window.BytesWindows(DECODER, {'older': FakeImage(older, 'c' * 64), 'newer': FakeImage(newer, NEWER)})
    elif case == 'no-image':
        tool = window.BytesWindows(DECODER, {'older': FakeImage(older, OLDER)})
    elif case == 'extent':
        tool = tool_for(older, newer, extents={0x1000: 21})        # .pdata says 21 bytes, the pair says 49
    elif case == 'tables':
        tool = tool_for(older, newer, broken=True)
    elif case == 'garbage':
        tool = tool_for(b'\x62' * 49, newer)
    elif case == 'direction':
        pair, direction = fake_pair(ref(0x1000, 49), None, 'removed'), 'newer'
    with pytest.raises(RuleError) as caught:
        tool.windows(pair, direction)
    assert (caught.value.code, caught.value.reason) == expected


def test_an_extent_from_the_unified_engine_is_not_checked_against_pdata():
    pair = fake_pair(ref(0x1000, 49, 'unified-ir'), ref(0x1000, 49, 'unified-ir'))
    tool = tool_for(body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7), extents={0x1000: 21})
    assert tool.windows(pair, 'older').windows


def test_hit_counts_are_byte_patterns_with_wildcards_overlap_and_a_cap(monkeypatch):
    def count(text: bytes, *tokens: str) -> int:
        return tool_for(text, b'').count('older', tokens)
    assert count(b'\xaa\xaa\xaa', 'AA', 'AA') == 2                                     # overlapping matches count
    assert count(b'\xaa\x00\xcc\xaa\xff\xcc\xaa\xff\xdd', 'AA', '??', 'CC') == 2       # `??` matches any byte
    assert count(b'a.b axb', '61', '2E', '62') == 1                                    # '2E' is a dot, not "any"
    assert count(b'\xaa\n\xcc', 'AA', '??', 'CC') == 1                                  # ...and "any" includes 0x0A
    assert count(b'\xaa' * 100, 'AA') == DEFAULT_LIMITS.max_matches_per_pattern
    assert count(b'nothing here', 'DE', 'AD') == 0
    tool = tool_for(b'\xaa', b'')
    tool._images['older'].executable_sections = lambda: iter([(0x400, b'\xaa'), (0x800, b'\xbb')])
    assert tool.count('older', ('AA', 'BB')) == 0                                      # no match straddles two sections


def test_a_large_build_is_read_again_instead_of_kept_in_memory(monkeypatch):
    kept = tool_for(b'\xaa\xbb' * 4, b'')
    assert kept.count('older', ('AA', 'BB')) == 4 and kept.count('older', ('BB', 'AA')) == 3
    assert kept._images['older'].reads == 1                                          # read once, counted twice
    monkeypatch.setattr(window, 'CACHE_BYTES', 4)
    large = tool_for(b'\xaa\xbb' * 4, b'')
    assert large.count('older', ('AA', 'BB')) == 4 and large.count('older', ('BB', 'AA')) == 3
    assert large._images['older'].reads >= 3                                         # the same answers, read again each time


def mov5(k: int) -> bytes:
    """`mov eax, imm32`: 5 bytes."""
    return b'\xb8' + struct.pack('<I', k)


def exact_cap_span(base: int) -> bytes:
    """20 distinct instructions, 128 bytes: 14 of 7 bytes and 6 of 5 bytes."""
    return b''.join(mov(base + i) if i % 10 < 7 else mov5(base + i) for i in range(20))


def test_a_changed_range_that_exactly_fills_the_cap_keeps_all_of_itself_and_no_context():
    pair = fake_pair(ref(0x1000, 142), ref(0x1000, 142))
    older = mov(1) + exact_cap_span(100) + mov(2)
    newer = mov(1) + exact_cap_span(200) + mov(2)
    (found,) = tool_for(older, newer).windows(pair, 'older').windows
    assert (found.window_rva, found.length) == (0x1007, 128)    # the context gave way, the change did not


def test_a_sliding_window_may_be_exactly_as_long_as_the_cap():
    removed = fake_pair(ref(0x1000, 163), None, 'removed')
    result = tool_for(exact_cap_span(100) + body(300, 301, 302, 303, 304), body(9)).windows(removed, 'older')
    assert (result.windows[0].window_rva, result.windows[0].length) == (0x1000, 128)


def test_a_short_tail_with_exactly_the_minimum_of_literal_bytes_is_a_window():
    removed = fake_pair(ref(0x1000, 144), None, 'removed')
    tail = b''.join(b'\x48\x83\xc0' + bytes([k]) for k in range(1, 5))               # four `add rax, k`: 16 bytes
    result = tool_for(exact_cap_span(100) + tail, body(9)).windows(removed, 'older')
    assert [(w.window_rva, w.length) for w in result.windows] == [(0x1000, 128), (0x1000 + 128, 16)]


def test_the_failure_reported_is_the_one_of_the_best_attempt():
    ks = list(range(1, 8))
    function = b''.join(mov5(k) for k in ks)                                          # 35 bytes of 5-byte instructions
    changed = b''.join(mov5(k if k != 4 else 0x99) for k in ks)
    pair = fake_pair(ref(0x1000, 35), ref(0x1000, 35))
    result = tool_for(function + gap() + function, changed).windows(pair, 'older')   # the function exists twice
    # the first attempt (15 bytes) is too short, the later ones are long enough but not unique: the last word is the best
    assert [(g.gate_id, g.state, g.measured) for g in result.failures] == [('uniq', 'fail', 2)]


def test_insertions_and_deletions_are_changed_ranges_on_their_own_side_only():
    six, seven = body(1, 2, 3, 5, 6, 7), body(1, 2, 3, 4, 5, 6, 7)
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 42))
    deleted = tool_for(seven, six)                                                    # the older build has I4 extra
    assert [w.pattern for w in deleted.windows(pair, 'older').windows] == [pattern(3, 4, 5)]
    assert deleted.windows(pair, 'newer').windows == ()                               # nothing is new in the newer build
    pair = fake_pair(ref(0x1000, 42), ref(0x1000, 49))
    inserted = tool_for(six, seven)                                                   # the newer build has I4 extra
    assert [w.pattern for w in inserted.windows(pair, 'newer').windows] == [pattern(3, 4, 5)]
    assert inserted.windows(pair, 'older').windows == ()


def test_at_most_three_windows_survive_the_ranking():
    pair = fake_pair(ref(0x1000, 210), ref(0x1000, 210))
    older = body(*range(1, 31))
    newer = body(*[0x99 if k in (3, 9, 15, 21, 27) else k for k in range(1, 31)])     # five changes far apart
    result = tool_for(older, newer).windows(pair, 'older')
    assert [w.window_rva for w in result.windows] == [0x1000 + 7 * 1, 0x1000 + 7 * 7, 0x1000 + 7 * 13]


def test_the_budget_also_bounds_growth_in_one_byte_steps(monkeypatch):
    region = b'\x90' * 100 + b'\xcc' + b'\x90' * 100                                  # the change is one byte
    pair = fake_pair(ref(0x1000, 201), ref(0x1000, 201))
    calls = spy_on_count(monkeypatch)
    tool = tool_for(region + gap() + region, b'\x90' * 201)                          # every window with the change exists twice
    result = tool.windows(pair, 'older')
    assert result.windows == () and len(calls) == 2 * window.MAX_EVALUATIONS
    assert [(g.gate_id, g.state) for g in result.failures] == [('uniq', 'unknown')]    # the budget ran out: unknown, not fail


def test_the_function_size_limit_is_inclusive():
    limits = RuleLimits(function_bytes=512)
    older = body(*range(1, 74)) + b'\x90'                                            # 73 x 7 + 1 = 512 bytes
    newer = body(*range(1, 4)) + body(0x99) + body(*range(5, 74)) + b'\x90'
    images = {'older': FakeImage(older, OLDER), 'newer': FakeImage(newer, NEWER)}
    tool = window.BytesWindows(DECODER, images, limits=limits)
    assert tool.windows(fake_pair(ref(0x1000, 512), ref(0x1000, 512)), 'older').windows
    with pytest.raises(RuleError) as caught:
        tool.windows(fake_pair(ref(0x1000, 513), ref(0x1000, 512)), 'older')
    assert caught.value.reason == 'function-size'


def test_each_body_is_decoded_once_for_both_directions():
    decoded = []

    class Counting(rf.SubsetDecoder):
        def decode(self, code, rva):
            decoded.append(rva)
            return super().decode(code, rva)
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    images = {'older': FakeImage(body(1, 2, 3, 4, 5, 6, 7), OLDER), 'newer': FakeImage(body(1, 2, 0x99, 4, 5, 6, 7), NEWER)}
    tool = window.BytesWindows(Counting(), images)
    assert tool.windows(pair, 'older').windows and tool.windows(pair, 'newer').windows
    assert decoded == [0x1000, 0x1000]                                              # one body per build, not four


def masked_bricks(*ks: int) -> masks.MaskedFunction:
    code = body(*ks)
    return masks.mask_function(code, 0x1000, DECODER.decode(code, 0x1000))


def test_nothing_changed_after_masking_is_no_range_and_a_whole_function_is_all_changed():
    same = masked_bricks(1, 2, 3, 4, 5, 6)
    assert window.diff_opcodes(same, same) == [] and window.changed_ranges(same, same, 'older') == []
    assert window.changed_ranges(same, None, 'newer') == [(0, 6)]                   # removed or added: all of it
    assert window.changed_ranges(masked_bricks(), None, 'older') == []                # ... unless it holds no instruction


def test_what_both_bodies_share_at_the_ends_is_not_compared(monkeypatch):
    compared = []

    class Spy(difflib.SequenceMatcher):
        def __init__(self, isjunk, a, b, **kwargs):
            compared.append((len(a), len(b), kwargs))
            super().__init__(isjunk, a, b, **kwargs)
    monkeypatch.setattr(window.difflib, 'SequenceMatcher', Spy)
    older = masked_bricks(*[7] * 6000, 1, *[7] * 6000)         # 12,001 instructions, 12,000 of them alike: compared whole,
    newer = masked_bricks(*[7] * 6000, 2, *[7] * 6000)         # `difflib` would weigh 144 million pairs (half a minute)
    assert window.diff_opcodes(older, newer) == [('replace', 6000, 6001, 6000, 6001)]
    assert compared == [(1, 1, {'autojunk': False})]          # and no instruction is "junk" for being common (the plan)


def test_the_shared_ends_never_overlap_and_the_indexes_are_those_of_the_bodies():
    one, two = masked_bricks(1, 2), masked_bricks(1, 2, 1, 2)
    assert window.diff_opcodes(one, two) == [('insert', 2, 2, 2, 4)]              # the head takes both: no tail is left
    assert window.diff_opcodes(two, one) == [('delete', 2, 4, 2, 2)]
    assert window.diff_opcodes(masked_bricks(1), masked_bricks(1, 2)) == [('insert', 1, 1, 1, 2)]
    assert window.diff_opcodes(masked_bricks(2), masked_bricks(1, 2)) == [('insert', 0, 0, 0, 1)]   # only the tail is shared
    assert window.diff_opcodes(masked_bricks(9, 1, 3, 8), masked_bricks(9, 2, 3, 8)) == [('replace', 1, 2, 1, 2)]
    assert window.diff_opcodes(masked_bricks(1, 2), masked_bricks(1, 9, 2, 2)) == [('insert', 1, 1, 1, 3)]   # the last 2 is shared


def test_the_range_of_a_side_is_found_whichever_side_it_is():
    shorter, longer = masked_bricks(1, 2, 3), masked_bricks(1, 2, 9, 3)
    assert window.changed_ranges(longer, shorter, 'newer') == [(2, 3)]              # the newer body has I9 extra
    assert window.changed_ranges(shorter, longer, 'older') == []                    # the older body has nothing the newer lacks
    assert window.changed_ranges(shorter, longer, 'newer') == [] and window.changed_ranges(longer, shorter, 'older') == [(2, 3)]


def test_a_middle_over_the_pair_budget_is_one_changed_range(monkeypatch):
    older, newer = masked_bricks(1, 1, 2), masked_bricks(2, 1, 1)                     # 2 x 2 pairs of one kind, 1 x 1 of the other
    compared = [('insert', 0, 0, 0, 1), ('delete', 2, 3, 3, 3)]
    assert window.diff_opcodes(older, newer) == compared
    monkeypatch.setattr(window, 'MAX_DIFF_PAIRS', 5)
    assert window.diff_opcodes(older, newer) == compared                            # exactly at the budget: compared
    monkeypatch.setattr(window, 'MAX_DIFF_PAIRS', 4)
    assert window.diff_opcodes(older, newer) == [('replace', 0, 3, 0, 3)]
    assert window.changed_ranges(older, newer, 'older') == [(0, 3)]               # changed throughout, on either side:
    assert window.changed_ranges(newer, older, 'newer') == [(0, 3)]               # `uniq` and `sep` decide
    shifted_old, shifted_new = masked_bricks(0xA, 1, 1, 2, 0xB), masked_bricks(0xA, 2, 1, 1, 0xB)
    assert window.diff_opcodes(shifted_old, shifted_new) == [('replace', 1, 4, 1, 4)]   # the shared ends stay out of it
    wider = masked_bricks(2, 1, 1, 3)                                              # 5 pairs still: its 3 has no partner
    assert window.diff_opcodes(older, wider) == [('replace', 0, 3, 0, 4)]
    assert window.changed_ranges(wider, older, 'newer') == [(0, 4)]


def test_a_pair_too_costly_to_compare_still_gets_its_windows_from_the_checks(monkeypatch):
    pair = fake_pair(ref(0x1000, 56), ref(0x1000, 56))
    older, newer = body(0x91, 1, 2, 3, 4, 5, 6, 0x92), body(0x93, 1, 2, 3, 4, 5, 6, 0x94)   # both ends changed
    monkeypatch.setattr(window, 'MAX_DIFF_PAIRS', 6)                                 # the six shared instructions: at the budget
    found = tool_for(older, newer).windows(pair, 'older').windows
    assert [(w.window_rva, w.length) for w in found] == [(0x1000, 21), (0x1000 + 35, 21)]   # one window around each change
    monkeypatch.setattr(window, 'MAX_DIFF_PAIRS', 5)                                 # one pair over: not compared
    (whole,) = tool_for(older, newer).windows(pair, 'older').windows
    assert (whole.window_rva, whole.length, whole.source_hits, whole.other_hits) == (0x1000, 56, 1, 0)


def test_both_directions_of_a_pair_compare_the_bodies_once(monkeypatch):
    calls = []
    real = window.diff_opcodes
    monkeypatch.setattr(window, 'diff_opcodes', lambda older, newer: calls.append((older.rva, newer.rva)) or real(older, newer))
    pair = fake_pair(ref(0x1000, 49), ref(0x1000, 49))
    tool = tool_for(body(1, 2, 3, 4, 5, 6, 7), body(1, 2, 0x99, 4, 5, 6, 7))
    assert tool.windows(pair, 'older').windows and tool.windows(pair, 'newer').windows
    assert calls == [(0x1000, 0x1000)]


def test_a_remembered_comparison_belongs_to_its_two_functions(monkeypatch):
    calls = []
    real = window.diff_opcodes
    monkeypatch.setattr(window, 'diff_opcodes', lambda older, newer: calls.append(1) or real(older, newer))
    tool = tool_for(b'', b'')
    older, near = masked_bricks(1, 2, 3), masked_bricks(1, 9, 3)
    code = body(1, 2, 8)
    far = masks.mask_function(code, 0x1100, DECODER.decode(code, 0x1100))              # another function of the newer build
    assert tool._opcodes('older', older, near) == [('replace', 1, 2, 1, 2)]
    assert tool._opcodes('older', older, far) == [('replace', 2, 3, 2, 3)]
    assert tool._opcodes('newer', near, older) == [('replace', 1, 2, 1, 2)]            # seen from the other side: remembered
    assert tool._opcodes('older', older, None) is None and len(calls) == 2
    other = masks.mask_function(body(1, 2, 3, 4), 0x1000, DECODER.decode(body(1, 2, 3, 4), 0x1000))
    assert tool._opcodes('older', other, near) == [('replace', 1, 2, 1, 2), ('delete', 3, 4, 3, 3)] and len(calls) == 3
