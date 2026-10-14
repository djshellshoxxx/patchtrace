"""R4 byte windows: PE table readers, mask policy, iced-x86 adapter and window gates on SYNTHETIC images only."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from rules_fixtures import capa_layout, tabled_image
from test_intel_tools_pe import _CAPA_STRINGS, KERNEL32, Asm, _capa_code, _capa_imports

from patchtrace import optional_deps
from patchtrace.pe_overview.tables import PeTableError, PeTableView
from patchtrace.yarax import window
from patchtrace.yarax.adapters import mask_iced
from patchtrace.yarax.contracts import FunctionRef
from patchtrace.yarax.errors import RulesError
from patchtrace.yarax.masks import DecodedInsn, RelocIndex, mask_instruction
from patchtrace.yarax.ports import MaskedFunction, MaskSource

needs_decoder = pytest.mark.skipif(optional_deps.iced_x86 is None, reason='iced-x86 (rules extra) not installed')

TERM_TOKEN = '48 83 EC 28 48 C7 C1 FF FF FF FF 31 D2 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3'
OLDER_PDATA = ('main', 'host', 'term', 'dyn', 'log')  # `xor` is a leaf loop with no unwind data


class Builds:
    """Writes images into tmp_path and serves them by SHA-256, as the project's artifact store would."""

    def __init__(self, tmp_path: Path):
        self.root, self.paths = tmp_path, {}

    def add(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        self.paths[sha] = self.root / f'{sha[:12]}.exe'
        self.paths[sha].write_bytes(data)
        return sha

    def open(self, sha: str) -> PeTableView:
        return PeTableView(self.paths[sha], sha)

    def source(self) -> mask_iced.IcedMaskSource:
        return mask_iced.IcedMaskSource(self.open)


def ref(layout, label: str, extent: str = 'pdata') -> FunctionRef:
    rva, size = layout.functions[label]
    return FunctionRef(name=label, rva=rva, size=size, extent=extent)


def masked(builds: Builds, layout, label: str) -> MaskedFunction:
    sha = builds.add(layout.image)
    return builds.source().masked_function(sha, 'older', ref(layout, label))


@pytest.fixture
def builds(tmp_path):
    return Builds(tmp_path)


def test_adapter_satisfies_the_mask_port(builds):
    assert isinstance(builds.source(), MaskSource)


# --- PE tables ---------------------------------------------------------------------------------------------------

def test_pdata_extent_and_leaf_without_entry(builds):
    older = tabled_image(_capa_code(False), _capa_imports(False), _CAPA_STRINGS, pdata=OLDER_PDATA)
    sha = builds.add(older.image)
    with builds.open(sha) as view:
        term, xor = older.functions['term'], older.functions['xor']
        assert view.function_extent(term[0]) == (term[0], term[0] + term[1])
        assert view.function_extent(xor[0]) is None
        assert view.function_extent(term[0] + 1) is None, 'only an entry that starts at the RVA counts'
        refs = {n: mask_iced.function_ref(view, older.functions[n][0], n) for n in ('term', 'xor')}
    assert (refs['term'].size, refs['term'].extent) == (24, 'pdata')
    assert (refs['xor'].size, refs['xor'].extent) == (0, 'unknown')


def test_import_slots_name_the_iat_entries(builds):
    layout = capa_layout(False)
    with builds.open(builds.add(layout.image)) as view:
        slots = view.import_slots()
    assert sorted(slots.values()) == sorted((KERNEL32, name) for name in
                                            ('GetComputerNameA', 'GetModuleHandleA', 'GetProcAddress',
                                             'TerminateProcess'))
    assert sorted(slots) == [0x2000, 0x2008, 0x2010, 0x2018]


def test_relocations_are_sorted_with_widths(builds):
    layout = tabled_image(*reloc_case(), relocs=((0x1003, 10), (0x1000 + 0x20, 3)))
    with builds.open(builds.add(layout.image)) as view:
        assert view.relocations() == ([0x1003, 0x1020], [8, 4])


def test_malformed_relocation_block_is_a_table_error(builds):
    layout = tabled_image(*reloc_case(), relocs=((0x1003, 10),))
    data = bytearray(layout.image)
    at = data.index(struct.pack('<II', 0x1000, 12))
    struct.pack_into('<I', data, at + 4, 3)  # block size below the 8-byte header
    with builds.open(builds.add(bytes(data))) as view, pytest.raises(PeTableError):
        view.relocations()


# --- mask policy ---------------------------------------------------------------------------------------------------

def insn(raw: str, **facts) -> DecodedInsn:
    return DecodedInsn(rva=0x1000, raw=bytes.fromhex(raw), **facts)


def test_policy_keeps_immediates_and_in_function_branches():
    jump = insn('72f4', branch_disp=(1, 1), branch_target=0x0FF6)
    mov = insn('41b810000000')
    inside = mask_instruction(jump, (0x0FF0, 0x1100), RelocIndex(), {})
    assert (inside.token, inside.masks) == ('72 F4', ())
    assert mask_instruction(mov, (0x0FF0, 0x1100), RelocIndex(), {}).token == '41 B8 10 00 00 00'


def test_policy_masks_branch_leaving_the_function():
    call = insn('e810000000', branch_disp=(1, 4), branch_target=0x1015)
    out = mask_instruction(call, (0x1000, 0x1010), RelocIndex(), {})
    assert (out.token, out.masks) == ('E8 ?? ?? ?? ??', ('branch-ext',))


def test_policy_masks_relocated_field_and_combines_kinds():
    mov = insn('48b8' + '0102030405060708')
    relocs = RelocIndex([0x1002], [8])
    out = mask_instruction(mov, (0x1000, 0x1100), relocs, {})
    assert (out.token, out.masks) == ('48 B8 ' + ' '.join(['??'] * 8), ('reloc',))
    lea = insn('488d15' + '00010000', rip_disp=(3, 4), rip_target=0x1107)
    both = mask_instruction(lea, (0x1000, 0x1100), RelocIndex([0x1006], [2]), {})
    assert both.masks == ('rip-disp', 'reloc') and both.token == '48 8D 15 ?? ?? ?? ??'


def test_policy_masks_unified_ir_address_references():
    cmp_ = insn('4881f9' + '00000140')
    out = mask_instruction(cmp_, (0x1000, 0x1100), RelocIndex(), {}, addr_refs={0x1003: 4})
    assert (out.token, out.masks) == ('48 81 F9 ?? ?? ?? ??', ('addr-ref',))


def test_pin_only_for_calls_through_an_iat_slot():
    raw = 'ff15' + '00010000'
    call = insn(raw, rip_disp=(2, 4), rip_target=0x2018, is_call=True)
    jump = insn(raw, rip_disp=(2, 4), rip_target=0x2018)
    iat = {0x2018: (KERNEL32, 'TerminateProcess')}
    pin = mask_instruction(call, (0x1000, 0x1100), RelocIndex(), iat).pin
    assert (pin.disp_offset, pin.end_offset, pin.dll, pin.name) == (2, 6, KERNEL32, 'TerminateProcess')
    assert mask_instruction(jump, (0x1000, 0x1100), RelocIndex(), iat).pin is None
    assert mask_instruction(call, (0x1000, 0x1100), RelocIndex(), {}).pin is None


# --- decoder adapter -------------------------------------------------------------------------------------------------

@needs_decoder
def test_term_golden_mask_and_pin(builds):
    term = masked(builds, capa_layout(False), 'term')
    assert [i.token for i in term.instructions] == ['48 83 EC 28', '48 C7 C1 FF FF FF FF', '31 D2',
                                                    'FF 15 ?? ?? ?? ??', '48 83 C4 28', 'C3']
    assert term.mask_source == 'iced-x86'
    built = window.build_window(term, 0, len(term.instructions))
    assert (built.pattern, built.length, built.literal, built.longest_run) == (TERM_TOKEN, 24, 20, 15)
    assert built.masks == ('rip-disp',)
    assert [(p.disp_offset, p.end_offset, p.dll, p.name) for p in built.pins] == [(15, 19, KERNEL32, 'TerminateProcess')]


@needs_decoder
def test_main_masks_call_targets_but_keeps_the_constant(builds):
    main = masked(builds, capa_layout(False), 'main')
    tokens = [i.token for i in main.instructions]
    assert tokens.count('E8 ?? ?? ?? ??') == 5
    assert 'BA 10 00 00 00' in tokens, 'the length immediate is a bound constant and stays'
    assert {i.masks for i in main.instructions if i.token.startswith('E8')} == {('branch-ext',)}


@needs_decoder
def test_loop_branch_inside_function_is_kept(builds):
    xor = masked(builds, capa_layout(False), 'xor')
    assert [i.token for i in xor.instructions][-3:] == ['48 39 D0', '72 F4', 'C3']


@needs_decoder
def test_relocated_immediate_is_masked_from_the_pe_reloc_table(builds):
    layout = tabled_image(*reloc_case(), pdata=('main',), relocs=((0x1006, 10),))
    main = masked(builds, layout, 'main')
    assert main.instructions[1].token == '48 B8 ' + ' '.join(['??'] * 8) and main.instructions[1].masks == ('reloc',)


@needs_decoder
def test_leaf_function_without_pdata_is_pt_rule_mask(builds):
    layout = capa_layout(False)
    sha = builds.add(layout.image)
    with builds.open(sha) as view:
        leaf = mask_iced.function_ref(view, layout.functions['xor'][0], 'xor')
    with pytest.raises(RulesError) as caught:
        builds.source().masked_function(sha, 'older', leaf)
    assert caught.value.code == 'PT-RULE-MASK'
    assert 'leaf' in caught.value.message


@needs_decoder
def test_invalid_instruction_is_pt_rule_decode():
    with pytest.raises(RulesError) as caught:
        mask_iced.decode(b'\x06', 0x1000, 0x140000000)
    assert caught.value.code == 'PT-RULE-DECODE'


@needs_decoder
def test_unreadable_build_is_pt_rule_integrity(tmp_path):
    def unreadable(_sha):
        raise PeTableError('not a parsable PE image')
    with pytest.raises(RulesError) as caught:
        mask_iced.IcedMaskSource(unreadable).masked_function('0' * 64, 'newer', FunctionRef(rva=0x1000, size=8,
                                                                                            extent='pdata'))
    assert caught.value.code == 'PT-RULE-INTEGRITY'


def test_missing_decoder_is_a_clear_unavailable_state(monkeypatch):
    monkeypatch.setattr(optional_deps, 'iced_x86', None)
    assert mask_iced.decoder_state() == ('none', 'none')
    with pytest.raises(RulesError) as caught:
        mask_iced.decode(b'\xc3', 0x1000, 0x140000000)
    assert caught.value.code == 'PT-RULE-UNAVAILABLE' and 'decoder none' in caught.value.message


@needs_decoder
def test_decoder_state_names_the_installed_version():
    name, version = mask_iced.decoder_state()
    assert name == 'iced-x86' and version[0].isdigit()


# --- windows ---------------------------------------------------------------------------------------------------------

def counter(image: bytes):
    return lambda pattern: window.count_hits(pattern, image)


def test_count_hits_handles_wildcards_and_overlap():
    assert window.count_hits('AA ?? AA', b'\xaa\x01\xaa\x02\xaa') == 2
    assert window.count_hits('AA BB', b'\xaa\xcc') == 0


@needs_decoder
def test_removed_function_window_passes_every_gate(builds):
    older, newer = capa_layout(False), capa_layout(True)
    term = masked(builds, older, 'term')
    found = window.propose_windows(term, None, counter(older.image), counter(newer.image))
    assert [w.pattern for w in found.windows] == [TERM_TOKEN]
    only = found.windows[0]
    assert (only.rva, only.source_hits, only.other_hits) == (0x104D, 1, 0)
    feature = window.to_bytes_feature(only, 'older', 'iced-x86')
    assert (feature.separation, feature.mask, len(feature.pins)) == ('older-only', ('rip-disp',), 1)


@needs_decoder
def test_short_window_rejected_with_reason(builds):
    older, newer = capa_layout(False), capa_layout(True)
    log = masked(builds, older, 'log')
    found = window.propose_windows(log, masked(builds, newer, 'log'), counter(older.image), counter(newer.image))
    assert found.windows == ()
    assert [(r.rva, r.gate) for r in found.rejected] == [(0x108B, 'len')]
    assert found.rejected[0].detail == '3 literal bytes, longest run 3, 0 wildcards'


@needs_decoder
def test_modified_function_window_is_anchored_on_the_change(builds):
    older, newer = capa_layout(False), capa_layout(True)
    new_log = masked(builds, newer, 'log')
    found = window.propose_windows(new_log, masked(builds, older, 'log'), counter(newer.image),
                                   counter(older.image))
    best = found.windows[0]
    # the trailing `ret` equals the old function's `ret`, so the change span ends before it
    assert (best.length, best.literal, best.longest_run, best.masks) == (37, 29, 14, ('rip-disp',))
    assert [p.name for p in best.pins] == ['WriteFile']
    assert best.rva == newer.functions['log'][0]


@needs_decoder
def test_added_function_window(builds):
    older, newer = capa_layout(False), capa_layout(True)
    env = masked(builds, newer, 'env')
    best = window.propose_windows(env, None, counter(newer.image), counter(older.image)).windows[0]
    assert (best.length, best.literal, best.longest_run) == (35, 23, 8)
    assert (best.source_hits, best.other_hits) == (1, 0)
    assert [p.name for p in best.pins] == ['GetEnvironmentVariableA']


@needs_decoder
def test_window_that_also_appears_in_the_other_build_fails_sep(builds):
    older = capa_layout(False)
    term = masked(builds, older, 'term')
    found = window.propose_windows(term, None, counter(older.image), counter(older.image))
    assert found.windows == () and found.rejected[0].gate == 'sep'


@needs_decoder
def test_non_unique_window_fails_uniq(builds):
    older = capa_layout(False)
    term = masked(builds, older, 'term')
    twice = older.image + older.image
    found = window.propose_windows(term, None, counter(twice), counter(b''))
    assert found.windows == () and found.rejected[0].gate == 'uniq'
    assert found.rejected[0].detail == '2 hits in its own build'


@needs_decoder
def test_context_growth_is_capped_and_stays_inside_the_function(builds):
    older = capa_layout(False)
    main = masked(builds, older, 'main')
    found = window.propose_windows(main, None, counter(older.image), counter(b''))
    assert all(w.length <= 128 and w.start >= 0 and w.end <= len(main.instructions) for w in found.windows)


def reloc_case():
    """Image whose `main` loads a 64-bit absolute address (the field a base relocation would cover)."""
    def emit(asm: Asm, rd):
        asm.label('main')
        asm.prologue()
        asm.raw(b'\x48\xb8' + struct.pack('<Q', 0x140002000))  # mov rax, imm64
        asm.epilogue()
    return emit, {KERNEL32: ['ExitProcess']}, {'buffer': b'\0' * 16}
