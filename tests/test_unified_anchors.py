"""SPEC-31 S3 MAT-ANCHOR (05 s2.5, review R-08): a semantic delta of the bytes group is `material` only when a channel of
ANOTHER data group shows the SAME change. Constants, offsets, operators, data labels and strings are anchored by the
canonical pseudo-code C6 (Ghidriff text, or S3b later); a constant-only edit without it stays `review`.
Synthetic decompiler text (imitating Ghidra's style): not live evidence."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import run_facts
from unified_s0_fixtures import func, match

from patchtrace.unified.contracts import Delta
from patchtrace.unified.facts.anchors import AnchorInputs, anchor_for
from patchtrace.unified.facts.irchannels import IrPair
from patchtrace.unified.facts.operands import CallTarget, DeltaInfo
from patchtrace.unified.facts.pseudo import Canon


def with_code(old_code, new_code, **names):
    return [match('m-f', 'modified', [func('f', 0x1000, code=old_code)], [func('f', 0x1000, code=new_code)],
                  types=['SymbolsHash'])]


def verdict_of(tmp_path, old, new, old_code=None, new_code=None, *, shift=0, bindiff=None):
    matches = with_code(old_code, new_code) if old_code is not None else []
    r = run_facts(tmp_path, image(old), image(new, shift=shift), matches=matches, bindiff=bindiff)
    return r.facts('f')


CMP_OLD = [('cmp_ri', 'ECX', 0x100, True), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
CMP_NEW = [('cmp_ri', 'ECX', 0x200, True), *CMP_OLD[1:]]


def test_constant_only_patch_is_review_ranked_first_until_a_decompiler_shows_it(tmp_path):
    facts = verdict_of(tmp_path, CMP_OLD, CMP_NEW)
    assert facts.verdict == 'review' and facts.second_channel is None
    assert facts.deltas[0].cls == 'constant' and dict(facts.channels)['C6'] == 'unavailable'


def test_constant_only_patch_promoted_only_with_anchored_c6(tmp_path):
    old = 'int f(int a) { if (a > 0x100) { return 1; } return 0; }'
    new = 'int f(int a) { if (a > 0x200) { return 1; } return 0; }'
    facts = verdict_of(tmp_path, CMP_OLD, CMP_NEW, old, new)
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')


def test_an_unrelated_c6_difference_never_promotes(tmp_path):
    """The decompiler shows 0x100 -> 0x300, the instruction changed 0x100 -> 0x200: not the same change."""
    old = 'int f(int a) { if (a > 0x100) { return 1; } return 0; }'
    other = 'int f(int a) { if (a > 0x300) { return 1; } return 0; }'
    facts = verdict_of(tmp_path, CMP_OLD, CMP_NEW, old, other)
    assert facts.verdict == 'review' and dict(facts.channels)['C6'] == 'differs'


def test_the_literal_may_be_spelled_in_decimal_or_hex_in_the_decompiler(tmp_path):
    old = 'int f(int a) { if (a > 256) { return 1; } return 0; }'
    new = 'int f(int a) { if (a > 0x200) { return 1; } return 0; }'
    assert verdict_of(tmp_path, CMP_OLD, CMP_NEW, old, new).verdict == 'material'


def test_a_struct_offset_is_anchored_by_the_offset_literal(tmp_path):
    old, new = [('load_m', 'EAX', 'RBX', 0x10), ('ret',)], [('load_m', 'EAX', 'RBX', 0x14), ('ret',)]
    facts = verdict_of(tmp_path, old, new, 'int f(long p) { return *(int *)(p + 0x10); }',
                       'int f(long p) { return *(int *)(p + 0x14); }')
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')
    named = verdict_of(tmp_path, old, new, 'int f(S *p) { return p->field_0x10; }', 'int f(S *p) { return p->field_0x14; }')
    assert named.verdict == 'material'


def test_a_changed_branch_condition_is_anchored_by_the_changed_operator(tmp_path):
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'NC', 'done'), ('mov_ri', 'EAX', 1), ('label', 'done'), ('ret',)]
    facts = verdict_of(tmp_path, old, new, 'int f(int a) { if (a > 5) { return 1; } return 0; }',
                       'int f(int a) { if (a >= 5) { return 1; } return 0; }')
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')
    same = verdict_of(tmp_path, old, new, 'int f(int a) { if (a > 5) { return 1; } return 0; }',
                      'int f(int a) { if (a > 5) { return 1; } return 0; }')
    assert same.verdict == 'review'                              # the decompiler shows no operator change


def test_a_swapped_global_is_anchored_by_the_mapped_data_labels(tmp_path):
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('label', 'done'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_b'), ('label', 'done'), ('ret',)]
    facts = verdict_of(tmp_path, old, new, 'void f() { x = DAT_180003000; }', 'void f() { x = DAT_180003040; }')
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')
    assert [d.cls for d in facts.deltas] == ['data-ref']


def test_a_moved_global_keeps_the_pseudo_code_equal_and_the_row_cosmetic(tmp_path):
    items = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('label', 'done'), ('ret',)]
    facts = verdict_of(tmp_path, items, items, 'void f() { x = DAT_180003000; }', 'void f() { x = DAT_180003040; }',
                       shift=0x40)
    assert (facts.verdict, facts.proof) == ('cosmetic', 'COS-ADDR/1') and dict(facts.channels)['C6'] == 'equal'


def test_a_changed_string_is_anchored_by_the_changed_literal(tmp_path):
    old = [('lea_g', 'RDX', 0x2000, 'hello world'), ('ret',)]
    new = [('lea_g', 'RDX', 0x2000, 'hello there'), ('ret',)]
    facts = verdict_of(tmp_path, old, new, 'void f() { puts("hello world"); }', 'void f() { puts("hello there"); }')
    assert [d.cls for d in facts.deltas if d.cls == 'string'] == ['string']
    assert (facts.verdict, facts.second_channel) == ('material', 'C6')
    assert verdict_of(tmp_path, old, new).verdict == 'review'


def test_bindiff_flag_c_anchors_a_callee_the_decompiler_does_not_show(tmp_path):
    old = [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    new = [('mov_ri', 'EAX', 1), ('call', 'other'), ('ret',)]
    facts = verdict_of(tmp_path, old, new, bindiff={(0x1000, 0x1000): ('C',)})
    assert facts.verdict == 'material' and facts.second_channel == 'C4'           # C4 is the nearer second channel


# --- the rule table on its own -----------------------------------------------------------------------------------------------

def canon(**fields):
    base = dict(tokens=(), calls=(), numbers=(), strings=(), relational=(), logical=(), mapped=frozenset(), unmapped=0)
    return Canon(**{**base, **fields})


def pair(**overrides):
    base = dict(states={}, deltas=(), targets=(0, 0, 0), eh='absent', positional_cfg=False, layout_ok=False,
                mask_unlocated=False, leftovers=((), ()), limits_hit=(), flags=(), counts_differ=True)
    return IrPair(**{**base, **overrides})


def inputs(states, **kw):
    fields = dict(states=states, pair=pair(), canon_old=None, canon_new=None, bindiff_flags=None,
                  identity=lambda side, target: None, data_token=lambda side, rva: None)
    return AnchorInputs(**{**fields, **kw})


def d(cls, channel='C2'):
    return Delta(cls=cls, channel=channel, older_rva=1, newer_rva=1)


def test_a_block_with_a_store_or_call_is_anchored_by_the_cfg_counts_or_flag_g_only():
    info = DeltaInfo(effect=True)
    assert anchor_for(d('block-added'), info, inputs({'C3': 'differs'})) == 'C3'
    assert anchor_for(d('block-added'), info, inputs({'C3': 'differs'}, pair=pair(counts_differ=False))) is None
    assert anchor_for(d('block-added'), info, inputs({'C3': 'equal', 'C8': 'differs'}, bindiff_flags=('G',))) == 'C8'
    assert anchor_for(d('block-added'), DeltaInfo(effect=False), inputs({'C3': 'differs'})) is None


def test_a_callee_is_anchored_by_c4_only_when_both_ends_are_unmatched_callees():
    replaced = DeltaInfo(tokens=(CallTarget('fn', 1), CallTarget('fn', 2)))
    both = pair(leftovers=((CallTarget('fn', 1),), (CallTarget('fn', 2),)))
    assert anchor_for(d('callee'), replaced, inputs({'C4': 'differs'}, pair=both)) == 'C4'
    only_old = pair(leftovers=((CallTarget('fn', 1),), ()))
    assert anchor_for(d('callee'), replaced, inputs({'C4': 'differs'}, pair=only_old)) is None
    assert anchor_for(d('callee', 'C4'), replaced, inputs({'C4': 'differs'}, pair=both)) is None   # its own channel


def test_a_callee_is_anchored_by_the_decompiler_through_its_name_or_row_token():
    info = DeltaInfo(tokens=(None, CallTarget('imp', 'ntdll.dll!report')))
    seen = inputs({'C6': 'differs'}, canon_old=canon(calls=('a',)), canon_new=canon(calls=('a', 'report')),
                  identity=lambda side, target: 'report' if target and target.kind == 'imp' else None)
    assert anchor_for(d('call-added', 'C4'), info, seen) == 'C6'
    blind = inputs({'C6': 'differs'}, canon_old=canon(calls=('a',)), canon_new=canon(calls=('a',)),
                   identity=seen.identity)
    assert anchor_for(d('call-added', 'C4'), info, blind) is None


@pytest.mark.parametrize('cls', ['frame', 'register-only', 'cfg', 'unknown', 'eh', 'address-only'])
def test_other_classes_are_never_anchored(cls):
    assert anchor_for(d(cls), DeltaInfo(values=(1, 2)), inputs({'C6': 'differs', 'C4': 'differs'},
                                                              canon_old=canon(numbers=('#1',)),
                                                              canon_new=canon(numbers=('#2',)))) is None
