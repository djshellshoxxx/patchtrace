"""SPEC-31 S3 operand-delta classifier C2 (05 s2.2) and the IR channel assembly around it: classes per operand kind,
unmatched instructions, the consistency counters, the C4/C5 bookkeeping and the caps. Hand-assembled x86-64."""
from __future__ import annotations

import dataclasses

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import build_pair, function, run_facts

from patchtrace.unified.facts.align import align
from patchtrace.unified.facts.datamap import TargetMap
from patchtrace.unified.facts.fnview import load_view
from patchtrace.unified.facts.irchannels import IrFacts, IrSides
from patchtrace.unified.facts.operands import operand_deltas
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted

SYM = {'helper': 0x1200, 'other': 0x1300, 'g_a': 0x3000}
HELPERS = [function(0x1200, [('mov_ri', 'EAX', 1), ('ret',)], name='helper'),
           function(0x1300, [('mov_ri', 'EAX', 2), ('ret',)], name='other')]


def deltas_of(tmp_path, old_items, new_items):
    old, new = build_pair(tmp_path, [function(0x1000, old_items, name='f', sym=SYM), *HELPERS],
                          [function(0x1000, new_items, name='f', sym=SYM), *HELPERS])
    targets = TargetMap(old, new, [(0x1200, 0x1200), (0x1300, 0x1300)])
    view_old = load_view(old, 'older', old.functions.rva_to_fid[0x1000])
    view_new = load_view(new, 'newer', new.functions.rva_to_fid[0x1000])
    result = operand_deltas(view_old, view_new, align(view_old, view_new), targets, (0x1000, 0x1000))
    return [(d.cls, d.old, d.new) for d, _ in result.deltas], result.cons.as_tuple()


def test_every_operand_kind_has_its_class(tmp_path):
    old = [('sub_ri', 'EAX', 4), ('load_m', 'EDX', 'RBX', 0x10), ('mov_rr', 'EAX', 'ECX'), ('store_s', 0x20, 'EAX'), ('ret',)]
    new = [('sub_ri', 'EAX', 8), ('load_m', 'EDX', 'RBX', 0x18), ('mov_rr', 'EAX', 'EDX'), ('store_s', 0x28, 'EAX'), ('ret',)]
    found, _cons = deltas_of(tmp_path, old, new)
    assert sorted(cls for cls, _o, _n in found) == ['constant', 'frame', 'register-only', 'struct-offset']


def test_a_base_register_change_inside_a_memory_operand_is_register_only(tmp_path):
    found, _ = deltas_of(tmp_path, [('load_m', 'EAX', 'RBX', 8), ('ret',)], [('load_m', 'EAX', 'RSI', 8), ('ret',)])
    assert [cls for cls, _o, _n in found] == ['register-only']


def test_unmatched_instructions_are_calls_or_unknown(tmp_path):
    old = [('mov_ri', 'EAX', 1), ('xor_rr', 'ECX', 'ECX'), ('ret',)]
    new = [('mov_ri', 'EAX', 1), ('call', 'helper'), ('ret',)]
    found, _ = deltas_of(tmp_path, old, new)
    assert sorted(cls for cls, _o, _n in found) == ['call-added', 'unknown']
    assert ('call-added', None, 'CALL 0x180001200') in found


def test_the_consistency_counters_count_every_address_operand(tmp_path):
    old = [('call', 'helper'), ('load_g', 'EAX', 'g_a'), ('call', 'other'), ('ret',)]
    new = [('call', 'other'), ('load_g', 'EAX', 'g_a'), ('call', 'other'), ('ret',)]
    found, cons = deltas_of(tmp_path, old, new)
    assert cons == (1, 1, 1)                      # the second call maps, g_a has no evidence, the first call conflicts
    assert [cls for cls, _o, _n in found] == ['callee']


def test_a_deleted_call_is_a_removal_and_a_replaced_call_pairs_its_ends(tmp_path):
    found, _ = deltas_of(tmp_path, [('call', 'helper'), ('ret',)], [('ret',)])
    assert [cls for cls, _o, _n in found] == ['call-removed']
    found, _ = deltas_of(tmp_path, [('call', 'helper'), ('ret',)], [('call', 'other'), ('ret',)])
    assert [cls for cls, _o, _n in found] == ['callee']


def test_c4_and_c5_state_the_multisets(tmp_path):
    r = run_facts(tmp_path, image([('call', 'helper'), ('mov_ri', 'EAX', 5), ('ret',)]),
                  image([('mov_ri', 'EAX', 5), ('call', 'helper'), ('ret',)]))
    channels = dict(r.facts('f').channels)
    assert channels['C4'] == channels['C5'] == 'equal'          # a reordered call and the same constants
    r = run_facts(tmp_path, image([('call', 'helper'), ('ret',)]), image([('call', 'helper'), ('call', 'helper'), ('ret',)]))
    assert dict(r.facts('f').channels)['C4'] == 'differs'       # one more call of the same callee


def test_c3_compares_the_block_body_multiset_and_ignores_address_shifts(tmp_path):
    plain = [('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('load_g', 'EAX', 'g_a'), ('add_ri', 'EAX', 3), ('label', 'done'),
             ('ret',)]
    edited = [*plain[:3], ('add_ri', 'EAX', 4), *plain[4:]]
    assert dict(run_facts(tmp_path, image(plain), image(plain, shift=0x40)).facts('f').channels)['C3'] == 'equal'
    assert dict(run_facts(tmp_path, image(plain), image(edited)).facts('f').channels)['C3'] == 'differs'   # same counts


def test_identical_artifacts_still_see_two_different_targets_as_a_conflict(tmp_path):
    """`identical` maps every address to ITSELF: an operand that points elsewhere is not the same call."""
    r = run_facts(tmp_path, image([('call', 'helper'), ('ret',)]), image([('call', 'other'), ('ret',)]), identical=True)
    facts = r.facts('f')
    assert 'callee' in {d.cls for d in facts.deltas} and facts.targets[2] >= 1 and facts.verdict != 'unchanged'


def test_a_reference_that_is_code_on_one_side_and_data_on_the_other_is_a_conflict(tmp_path):
    """The same instruction shape now points into the code section: no mapping can make that the same datum."""
    r = run_facts(tmp_path, image([('lea_g', 'RAX', 'g_a'), ('ret',)]), image([('lea_g', 'RAX', 'helper'), ('ret',)]))
    facts = r.facts('f')
    assert facts.targets[2] >= 1 and 'data-ref' in {d.cls for d in facts.deltas} and facts.verdict in ('material', 'review')


def test_an_import_stub_and_a_call_through_the_import_table_are_the_same_callee(tmp_path):
    stub = function(0x1200, [('jmp_iat', 0x2100, 'kernel32.dll!Sleep')], name='Sleep', kind='thunk',
                    imp={'dll': 'KERNEL32.DLL', 'name': 'Sleep', 'ordinal': None})
    old = [function(0x1000, [('call', 'Sleep'), ('ret',)], name='f', sym={'Sleep': 0x1200}), stub]
    new = [function(0x1000, [('call_iat', 0x2100, 'kernel32.dll!Sleep'), ('ret',)], name='f'), stub]
    r = run_facts(tmp_path, old, new)
    facts = r.facts('f')
    assert dict(facts.channels)['C4'] == 'equal' and facts.targets[2] == 0 and facts.verdict != 'material'


def test_wrapper_with_logic_not_collapsed(tmp_path):
    """F5: only a pure jump thunk collapses to its target; a wrapper with logic is a function of its own."""
    target = function(0x1400, [('mov_ri', 'EAX', 1), ('mov_ri', 'ECX', 2), ('ret',)], name='target')
    thunk = function(0x1200, [('jmp', 0x1400)], name='thunk', kind='thunk', thunk_target=0x1400)
    wrapper = function(0x1200, [('mov_ri', 'EDX', 9), ('call', 0x1400), ('ret',)], name='thunk')
    caller_thunk = function(0x1000, [('call', 0x1200), ('ret',)], name='f')
    caller_direct = function(0x1000, [('call', 0x1400), ('ret',)], name='f')
    through_thunk = run_facts(tmp_path, [caller_thunk, thunk, target], [caller_direct, target])
    assert dict(through_thunk.facts('f').channels)['C4'] == 'equal' and through_thunk.facts('f').targets[2] == 0
    through_wrapper = run_facts(tmp_path, [caller_thunk, wrapper, target], [caller_direct, target])
    assert dict(through_wrapper.facts('f').channels)['C4'] == 'differs'
    assert through_wrapper.facts('f').verdict in ('material', 'review')


def test_tiny_change_is_review_not_hidden(tmp_path):
    r = run_facts(tmp_path, image([('mov_ri', 'EAX', 1), ('ret',)]), image([('mov_ri', 'EAX', 2), ('ret',)]))
    assert r.facts('f').verdict == 'review' and 'tiny' in r['f'].flags


def test_hub_call_change_still_reported(tmp_path):
    """F15: hubs (fan-in above L-17) are excluded from propagation only, never from facts."""
    callers = [function(0x1600 + 0x10 * k, [('call', 'helper'), ('ret',)], name=f'c{k}', sym=SYM) for k in range(70)]

    def hub_image(items):
        return sorted([*image(items), *callers], key=lambda fn: fn['rva'])
    r = run_facts(tmp_path, hub_image([('call', 'helper'), ('ret',)]), hub_image([('call', 'other'), ('ret',)]))
    assert 'callee' in {d.cls for d in r.facts('f').deltas} and r.facts('f').verdict in ('material', 'review')
    assert r.verdict('c0') == ('unchanged', 'UNCH/1')                 # the 70 untouched callers stay unchanged


def test_row_flags_carry_the_function_facts(tmp_path):
    r = run_facts(tmp_path, image([('mov_ri', 'EAX', 1), ('ret',)]), image([('mov_ri', 'EAX', 1), ('ret',)]))
    assert r['f'].flags == ('tiny',)
    big = [('mov_ri', 'EAX', n) for n in range(8)] + [('ret',)]
    assert run_facts(tmp_path, image(big), image(big))['f'].flags == ()


def test_a_pair_missing_from_the_ir_keeps_its_s0_facts_and_says_so(tmp_path):
    fns = image([('ret',)])
    old, new = build_pair(tmp_path, fns, fns)
    ghost = IrFacts(IrSides(old, new), []).analyze(0x1000, 0x7000)
    assert ghost is None


def test_the_budget_is_honoured_while_a_pair_is_analysed(tmp_path):
    fns = image([('mov_ri', 'EAX', n) for n in range(40)] + [('ret',)])
    old, new = build_pair(tmp_path, fns, fns)
    budget = Budget(check_every=1)
    budget.cancel = type('Set', (), {'is_set': staticmethod(lambda: True)})()
    with pytest.raises(BudgetExhausted):
        IrFacts(IrSides(old, new), [(0x1000, 0x1000)], budget=budget).analyze(0x1000, 0x1000)


def test_the_alignment_cap_ends_in_review_and_says_so(tmp_path):
    items = [('mov_ri', 'EAX', n) for n in range(12)] + [('ret',)]
    edited = [*items[:5], ('mov_ri', 'EAX', 99), *items[6:]]
    tight = dataclasses.replace(DEFAULT_LIMITS, l27_align_instructions=5)
    old, new = build_pair(tmp_path, image(items), image(edited))
    facts = IrFacts(IrSides(old, new), [(0x1000, 0x1000)], limits=tight).analyze(0x1000, 0x1000)
    assert 'align-cap' in facts.limits_hit
    r = run_facts(tmp_path, image(items), image(edited))
    assert 'align-cap' not in r.facts('f').limits_hit            # the cap is only a limit when it is reached
    capped = run_facts(tmp_path, image(items), image(edited), limits=tight)
    assert capped.verdict('f') == ('review', None) and 'align-cap' in capped.facts('f').limits_hit
    # equal masked bytes align positionally in linear time: the cap never applies to them (05 s2.3, first rule)
    same = run_facts(tmp_path, image(items), image(items), identical=True, limits=tight)
    assert same.verdict('f') == ('unchanged', 'UNCH/1') and same.facts('f').limits_hit == ()


def test_text_and_names_of_a_hostile_function_stay_inside_the_delta_limits(tmp_path):
    evil = function(0x1000, [('mov_ri', 'EAX', 1), ('ret',)], name='f‮\x00')
    other = function(0x1000, [('mov_ri', 'EAX', 2), ('ret',)], name='f‮\x00')
    evil['text'][0] = 'MOV EAX,\x1b[31m' + 'A' * 230
    other['text'][0] = 'MOV EAX,‮' + 'B' * 230
    old, new = build_pair(tmp_path, [evil], [other])
    pair = IrFacts(IrSides(old, new), [(0x1000, 0x1000)]).analyze(0x1000, 0x1000)
    texts = [d.old for d, _ in pair.deltas] + [d.new for d, _ in pair.deltas]
    assert texts and all(t is not None and len(t) <= 120 and '\x1b' not in t and '‮' not in t for t in texts)
