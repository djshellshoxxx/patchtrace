"""SPEC-31 S0b facts (05 s2.4-s2.6, s6): canon/1, the S0 channels C4n/C5t/C6/C8 and the verdict rules.
Synthetic decompiler text only; Ghidra's real output style is imitated, never captured, so this is not live evidence."""
from __future__ import annotations

from unified_s0_fixtures import NEW_SHA, OLD_SHA, addr_map, func, match, va

from patchtrace.unified import keys
from patchtrace.unified.contracts import ChangeFacts
from patchtrace.unified.facts import channels, pseudo, verdict
from patchtrace.unified.facts.channels import FactsContext, PairMap
from patchtrace.unified.fusion.arbiter import Decided
from patchtrace.unified.limits import DEFAULT_LIMITS


def labels(pairs=()):
    """A PairMap with the given (older rva, newer rva) pairs mapped through tier-A matched rows."""
    return PairMap.from_pairs(OLD_SHA, NEW_SHA, pairs)


def canon(code, side='older', pairs=()):
    return pseudo.canonicalize(code, side, labels(pairs), addr_map(), 'va', DEFAULT_LIMITS)


# --- canon/1 ---------------------------------------------------------------------------------------------------------

def test_canon_keeps_constants_and_operators():
    base = canon('int f(int a) { if (a > 0x100) { return 1; } return 0; }')
    assert canon('int f(int a) { if (a > 256) { return 1; } return 0; }').tokens == base.tokens  # 0x100 = 256
    assert canon('int f(int a) { if (a >= 0x100) { return 1; } return 0; }').tokens != base.tokens
    assert canon('int f(int a) { if (a > 0x101) { return 1; } return 0; }').tokens != base.tokens
    assert canon('int f(int a) { if (a > 0x100) { return 2; } return 0; }').tokens != base.tokens
    assert base.relational == ('>',) and set(base.numbers) == {'#256', '#1', '#0'} and not base.strings


def test_canon_ignores_comments_and_whitespace_but_not_strings():
    a = canon('void f() {\n  /* WARNING: x */ puts("a//b"); // trailing\n}')
    b = canon('void   f(){puts( "a//b" );}')
    assert a.tokens == b.tokens and a.strings == ('"a//b"',)
    assert canon('void f(){puts("a//c");}').tokens != b.tokens


def test_canon_alpha_renames_locals_parameters_and_temporaries():
    a = canon('long f(long param_1) { long lVar1; uint uVar2; lVar1 = param_1 + local_18; return lVar1; }')
    b = canon('long f(long param_7) { long iVar9; uint uVar3; iVar9 = param_7 + local_30; return iVar9; }')
    assert a.tokens == b.tokens and not a.unmapped and not b.unmapped
    swapped = canon('long f(long param_1) { long lVar1; uint uVar2; lVar1 = local_18 + param_1; return lVar1; }')
    assert swapped.tokens != a.tokens  # a different data flow is still different after renaming


def test_canon_keeps_real_names_and_call_names():
    a = canon('void f() { ExAllocatePool2(0x40, 8, 0x67726154); }')
    assert 'ExAllocatePool2' in a.tokens and a.calls == ('ExAllocatePool2',)
    assert canon('void f() { ExAllocatePool(0x40, 8, 0x67726154); }').tokens != a.tokens


def test_canon_does_not_count_the_signature_as_a_call():
    a = canon('int read_item(int a) { return helper(a); }')
    assert a.calls == ('helper',)


def test_function_labels_map_through_matched_rows_on_both_sides():
    pairs = [(0x1200, 0x1300), (0x1000, 0x1080)]
    old = canon(f'void FUN_{va(0x1000)}() {{ FUN_{va(0x1200)}(); }}', 'older', pairs)
    new = canon(f'void FUN_{va(0x1080)}() {{ FUN_{va(0x1300)}(); }}', 'newer', pairs)
    assert old.tokens == new.tokens and old.unmapped == new.unmapped == 0 and len(old.mapped) == 2
    other = canon(f'void FUN_{va(0x1080)}() {{ FUN_{va(0x1400)}(); }}', 'newer', pairs)
    assert other.tokens != old.tokens and other.unmapped == 1  # an unmapped callee is counted and never hidden


def test_swapped_global_is_hidden_by_renaming_but_counted_as_unmapped():
    """R-02: DAT_a -> DAT_b alpha-renames to the same token; only the unmapped count forbids COS-PSEUDO."""
    a = canon(f'void f() {{ DAT_{va(0x1800)} = 1; }}')
    b = canon(f'void f() {{ DAT_{va(0x1900)} = 1; }}', 'newer')
    assert a.tokens == b.tokens and a.unmapped == 1 and b.unmapped == 1


def test_local_code_labels_are_renamed_and_not_counted_as_unmapped():
    a = canon(f'void f() {{ goto LAB_{va(0x1010)}; LAB_{va(0x1010)}: return; }}')
    b = canon(f'void f() {{ goto LAB_{va(0x1090)}; LAB_{va(0x1090)}: return; }}', 'newer')
    assert a.tokens == b.tokens and a.unmapped == 0


def test_canon_handles_hostile_text_without_raising():
    hostile = 'void f() { "\x00\ud800 unterminated; /* open comment ' + 'x' * 5000 + ' \u202e\u0000 }\n' * 50
    result = canon(hostile)
    assert result.tokens and isinstance(result.unmapped, int)


def test_canon_char_and_float_literals():
    assert canon("void f() { c = 'A'; }").numbers == ('#65',)
    assert canon('void f() { x = 1.5; }').numbers == ('f:1.5',)


# --- channels and verdicts -------------------------------------------------------------------------------------------

def decided(o, n, decision='matched', tier='A'):
    from patchtrace.unified.contracts import Atom, Support
    atom = Atom(source='ghidriff', step='SymbolsHash', tier=tier, cardinality='1:1', cls='E-NAME', older_rva=o,
                newer_rva=n)
    mapped = decision == 'matched' and tier in ('A', 'M')
    return Decided(older=(o,), newer=(n,), decision=decision, support=(Support(component='K1', tier=tier,
                                                                              atom_index=0),),
                   contest=None, atoms=(atom,), hints=(), pair=(o, n), mapped=mapped)


def context(matches, rows, bindiff=None):
    return FactsContext.build(older_sha256=OLD_SHA, newer_sha256=NEW_SHA, addr=addr_map(), matches=matches,
                              rows=rows, bindiff_flags=bindiff or {}, limits=DEFAULT_LIMITS)


def judged(ctx, row):
    evidence = ctx.collect(row)
    return verdict.judge(keys.row_id(OLD_SHA, NEW_SHA, row.older, row.newer), row.decision, evidence)


def pair_match(old_code, new_code, o=0x1000, n=0x1080, old_calls=(), new_calls=(), types=('SymbolsHash',),
               diff_types=(), name='f', category='modified', old_omitted=False):
    return match(f'm-{o:x}', category, [func(name, o, code=old_code, callees=old_calls, diff_types=diff_types,
                                             omitted=old_omitted)],
                 [func(name, n, code=new_code, callees=new_calls, diff_types=diff_types)], types=types)


def test_identical_code_modulo_renaming_is_cosmetic_with_the_decompiler_relative_proof():
    m = pair_match('int f(int a) { int uVar1; uVar1 = a + 1; return uVar1; }',
                   'int f(int a) { int iVar7; iVar7 = a + 1; return iVar7; }')
    row = decided(0x1000, 0x1080)
    result = judged(context([m], [row]), row)
    facts = result.facts
    assert isinstance(facts, ChangeFacts)
    assert (facts.verdict, facts.proof) == ('cosmetic', 'COS-PSEUDO/1')
    assert dict(facts.channels) == {'C0': 'unavailable', 'C1': 'unavailable', 'C2': 'unavailable',
                                    'C3': 'unavailable', 'C4': 'equal', 'C5': 'equal', 'C6': 'equal',
                                    'C7': 'unavailable', 'C8': 'unavailable'}
    assert facts.targets == (0, 0, 0) and facts.eh == 'unavailable' and facts.deltas == ()


def test_s0_never_issues_unchanged_or_the_ir_proofs():
    m = pair_match('int f() { return 1; }', 'int f() { return 1; }')
    row = decided(0x1000, 0x1080)
    assert judged(context([m], [row]), row).facts.proof == 'COS-PSEUDO/1'  # the only proof available without IR
    unchanged_pair = decided(0x1600, 0x1700)  # in Ghidriff's address_matches only: no code at all
    facts = judged(context([m], [unchanged_pair]), unchanged_pair).facts
    assert facts.verdict == 'unknown' and facts.proof is None


def test_unavailable_data_is_never_cosmetic_by_absence():
    m = pair_match(None, 'int f() { return 1; }')
    row = decided(0x1000, 0x1080)
    result = judged(context([m], [row]), row)
    assert result.facts.verdict == 'review' and dict(result.facts.channels)['C6'] == 'unavailable'


def test_code_over_the_cap_is_unavailable_and_recorded():
    m = pair_match(None, 'int f() { return 1; }', old_omitted=True)
    row = decided(0x1000, 0x1080)
    facts = judged(context([m], [row]), row).facts
    assert 'pseudo-cap' in facts.limits_hit and facts.verdict == 'review'


def test_constant_only_patch_is_review_ranked_first_not_material():
    m = pair_match('int f(int a) { return a < 0x100; }', 'int f(int a) { return a < 0x200; }')
    row = decided(0x1000, 0x1080)
    facts = judged(context([m], [row]), row).facts
    assert facts.verdict == 'review' and facts.second_channel is None
    assert [(d.cls, d.channel, d.old, d.new) for d in facts.deltas] == [('constant', 'C5', '0x100', '0x200')]
    assert dict(facts.channels)['C5'] == 'differs' and dict(facts.channels)['C6'] == 'differs'


def test_unmatched_callee_is_material_candidate_with_an_anchored_second_channel():
    old = 'void f() { helper(1); }'
    new = 'void f() { helper(1); report_invalid_index(2); }'
    m = pair_match(old, new, old_calls=['helper'], new_calls=['helper', 'report_invalid_index'])
    row = decided(0x1000, 0x1080)
    facts = judged(context([m], [row]), row).facts
    assert facts.verdict == 'material' and facts.second_channel == 'C6'
    assert [(d.cls, d.channel, d.new) for d in facts.deltas if d.cls == 'call-added'] == [
        ('call-added', 'C4', 'report_invalid_index')]
    assert dict(facts.channels)['C4'] == 'differs'


def test_material_needs_anchored_second_channel():
    """A callee list that differs while the decompiled calls do not (and an unrelated C6 change) is not promoted."""
    old = 'int f(int a) { return helper(a) < 0x10; }'
    new = 'int f(int a) { return helper(a) < 0x20; }'
    m = pair_match(old, new, old_calls=['helper'], new_calls=['helper', 'other_callee'])
    row = decided(0x1000, 0x1080)
    facts = judged(context([m], [row]), row).facts
    assert facts.verdict == 'review' and facts.second_channel is None
    assert {d.cls for d in facts.deltas} >= {'call-added', 'constant'}


def test_bindiff_flag_c_anchors_a_callee_delta_when_the_decompiled_calls_agree_with_nothing():
    m = pair_match(None, None, old_calls=['a_old'], new_calls=['b_new'])
    row = decided(0x1000, 0x1080)
    without = judged(context([m], [row]), row).facts
    assert without.verdict == 'review'
    anchored = judged(context([m], [row], {(0x1000, 0x1080): ('C',)}), row).facts
    assert (anchored.verdict, anchored.second_channel) == ('material', 'C8')
    assert dict(anchored.channels)['C8'] == 'differs'
    assert [d.cls for d in anchored.deltas] == ['callee']


def test_bindiff_flags_set_the_c8_channel_and_j_alone_is_a_hint():
    m = pair_match('void f() {}', 'void f() {}')
    row = decided(0x1000, 0x1080)
    assert dict(judged(context([m], [row], {(0x1000, 0x1080): ('J',)}), row).facts.channels)['C8'] == 'equal'
    assert dict(judged(context([m], [row], {(0x1000, 0x1080): ('G',)}), row).facts.channels)['C8'] == 'differs'
    assert dict(judged(context([m], [row]), row).facts.channels)['C8'] == 'unavailable'


def test_unmapped_target_blocks_cosmetic():
    m = pair_match(f'void f() {{ DAT_{va(0x1800)} = 1; }}', f'void f() {{ DAT_{va(0x1900)} = 1; }}')
    row = decided(0x1000, 0x1080)
    result = judged(context([m], [row]), row)
    assert result.facts.verdict == 'review' and result.facts.proof is None and result.facts.targets[1] == 2
    assert 'address-only' in result.classes and dict(result.facts.channels)['C6'] == 'equal'


def test_mapped_function_labels_do_not_block_cosmetic():
    old = f'void FUN_{va(0x1000)}() {{ FUN_{va(0x1200)}(); }}'
    new = f'void FUN_{va(0x1080)}() {{ FUN_{va(0x1300)}(); }}'
    m = pair_match(old, new, old_calls=[f'FUN_{va(0x1200)}'], new_calls=[f'FUN_{va(0x1300)}'])
    rows = [decided(0x1000, 0x1080), decided(0x1200, 0x1300)]
    facts = judged(context([m], rows), rows[0]).facts
    assert (facts.verdict, facts.proof) == ('cosmetic', 'COS-PSEUDO/1') and facts.targets == (2, 0, 0)


def test_a_callee_rebound_to_another_mapped_row_is_a_conflict_and_a_semantic_delta():
    old = f'void FUN_{va(0x1000)}() {{ FUN_{va(0x1200)}(); }}'
    new = f'void FUN_{va(0x1080)}() {{ FUN_{va(0x1500)}(); }}'
    m = pair_match(old, new, old_calls=[f'FUN_{va(0x1200)}'], new_calls=[f'FUN_{va(0x1500)}'])
    rows = [decided(0x1000, 0x1080), decided(0x1200, 0x1300), decided(0x1400, 0x1500)]
    facts = judged(context([m], rows), rows[0]).facts
    assert facts.verdict == 'material' and facts.targets[2] == 1
    assert [d.cls for d in facts.deltas if d.channel == 'C4'] == ['callee']


def test_tentative_rows_never_map_their_own_labels():
    code_old, code_new = f'void FUN_{va(0x1000)}() {{}}', f'void FUN_{va(0x1080)}() {{}}'
    m = pair_match(code_old, code_new)
    row = decided(0x1000, 0x1080, decision='tentative', tier='B')
    assert not row.mapped
    assert judged(context([m], [row]), row).facts.verdict == 'review'  # U-06: unproven pair, own labels unmapped


def test_diff_types_alone_never_cosmetic():
    m = pair_match(None, None, diff_types=['address'])
    row = decided(0x1000, 0x1080)
    result = judged(context([m], [row]), row)
    assert result.facts.verdict == 'review' and result.facts.proof is None
    assert result.classes == ('address-only',) and result.hints == ('ghidriff-diff-types:address',)
    code_change = pair_match(None, None, diff_types=['code', 'address'])
    both = judged(context([code_change], [row]), row)
    assert both.classes == () and both.hints == ('ghidriff-diff-types:address,code',)


def test_manual_modified_pairs_count_as_a_change_signal():
    manual = match('mm', 'modified', [func('f', 0x1000)], [func('f', 0x1080)], types=['manual'], manual=True)
    row = decided(0x1000, 0x1080)
    assert judged(context([manual], [row]), row).facts.verdict == 'review'


def test_pairs_without_ghidriff_records_use_only_what_exists():
    row = decided(0x1600, 0x1700)
    facts = judged(context([], [row], {(0x1600, 0x1700): ()}), row).facts
    assert dict(facts.channels)['C8'] == 'equal' and facts.verdict == 'unknown'


def test_code_from_two_different_matches_can_still_form_a_pair():
    removed = match('r1', 'removed', older=[func('old_name', 0x1000, code='void f() { a(); }', callees=['a'])])
    added = match('a1', 'added', newer=[func('new_name', 0x1080, code='void f() { a(); }', callees=['a'])])
    row = decided(0x1000, 0x1080)
    facts = judged(context([removed, added], [row]), row).facts
    assert facts.verdict == 'cosmetic'  # BinDiff/manual paired an added and a deleted function: the code is there


def test_deltas_are_capped_and_counted():
    old = 'void f() { ' + ' '.join(f'g{i}(0x{i + 100:x});' for i in range(40)) + ' }'
    new = 'void f() { ' + ' '.join(f'h{i}(0x{i + 900:x});' for i in range(40)) + ' }'
    m = pair_match(old, new, old_calls=[f'g{i}' for i in range(40)], new_calls=[f'h{i}' for i in range(40)])
    row = decided(0x1000, 0x1080)
    facts = judged(context([m], [row]), row).facts
    assert len(facts.deltas) == DEFAULT_LIMITS.l28_deltas_per_pair and facts.deltas_omitted == 80 - 64
    assert facts.deltas[0].cls == 'callee'  # severity order: calls first


def test_facts_depend_on_the_row_only_through_the_chosen_pair():
    m = pair_match('int f() { return 1; }', 'int f() { return 2; }')
    contested = decided(0x1000, 0x1080, decision='contested')
    assert judged(context([m], [contested]), contested).facts.verdict == 'review'


def test_channels_module_has_no_ir_channels():
    assert not hasattr(channels, 'C0') and set(channels.S0_CHANNELS) == {'C4', 'C5', 'C6', 'C8'}
