"""SPEC-31 S3 audit (card fct): target consistency (05 s2.7, DATA-MAP/1) on degenerate and hostile targets.

A target the IR could not resolve (an operand whose address lies outside the image has no value) is no evidence of
anything: it is never `mapped`, so it can never support UNCH/1, COS-ADDR/1 or COS-LAYOUT/1. Hand-assembled x86-64
through the real ingest; synthetic, never live Ghidra evidence."""
from __future__ import annotations

import dataclasses
import hashlib
import threading

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import OPT_ADDR_CODE, build_pair, function, run_facts

from patchtrace.unified.facts.datamap import UNMAPPED, TargetMap
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted

SAFE = ('material', 'review')


def leaving_the_image(fns, index):
    """Instruction `index` of `f` keeps its bytes but its address operand has no in-image target (`['addr', None]`,
    no reference), exactly what the extractor writes for a branch outside the image."""
    for fn in fns:
        if fn['name'] == 'f':
            fn['insns'][index][4] = [[OPT_ADDR_CODE, '00ff', [['addr', None]], []]]
    return fns


@pytest.mark.parametrize('pairs', [(), ((0x1200, 0x1200),)], ids=['no-rows', 'rows'])
def test_an_unresolved_function_target_is_never_mapped(tmp_path, pairs):
    helper = [function(0x1200, [('mov_ri', 'EAX', 1), ('ret',)], name='helper')]
    older, newer = build_pair(tmp_path, helper, helper)
    targets = TargetMap(older, newer, list(pairs))
    assert targets.function_state(None, None) == UNMAPPED
    assert targets.function_state(0x1200, None) == UNMAPPED and targets.function_state(None, 0x1200) == UNMAPPED


def majority_moved_elsewhere():
    """f and u1 read g_a in the older image and X in the newer one; u2..u4 (the majority) read Y instead, so f and u1
    are the dissenters (a swap to another datum, the R-01 hole) whatever the order the votes arrive in."""
    old_sym, new_sym = {'g_a': 0x3000}, {'X': 0x3040, 'Y': 0x3080}
    old = [function(0x1000, [('load_g', 'EAX', 'g_a'), ('ret',)], name='f', sym=old_sym)]
    new = [function(0x1000, [('load_g', 'EAX', 'X'), ('ret',)], name='f', sym=new_sym)]
    for number, (rva, target) in enumerate(((0x1400, 'X'), (0x1440, 'Y'), (0x1480, 'Y'), (0x14c0, 'Y')), start=1):
        old.append(function(rva, [('load_g', 'ECX', 'g_a'), ('ret',)], name=f'u{number}', sym=old_sym))
        new.append(function(rva, [('load_g', 'ECX', target), ('ret',)], name=f'u{number}', sym=new_sym))
    return old, new


def test_a_capped_vote_table_never_turns_a_dissenter_into_a_proof(tmp_path):
    """L-40: a vote pair beyond the cap is dropped. With room for one pair, (g_a, X) of f and u1 is kept and (g_a, Y)
    of the majority is not; a majority over the kept votes must not map what the full table calls a conflict, and the
    cap is reported on the rows."""
    old, new = majority_moved_elsewhere()
    full = run_facts(tmp_path, old, new)
    assert [full.verdict(name)[0] for name in ('f', 'u1')] == ['review', 'review']
    assert {d.cls for d in full.facts('f').deltas} == {'data-ref'}
    assert full.verdict('u2') == ('cosmetic', 'COS-ADDR/1') and full.facts('u2').limits_hit == ()
    capped = run_facts(tmp_path, old, new, limits=dataclasses.replace(DEFAULT_LIMITS, l40_data_pairs=1))
    for name in ('f', 'u1', 'u2', 'u3', 'u4'):
        facts = capped.facts(name)
        assert facts.verdict in SAFE and facts.proof is None, (name, facts.verdict, facts.proof)
        assert 'datamap-cap' in facts.limits_hit


def test_the_string_index_scan_honours_cancel(tmp_path):
    """Rule (a) builds a per-side index of every defined string by decoding the instructions of every function that
    references one: O(image), so it must tick the run's budget like the vote collection (cooperative cancel, 04 I7)."""
    lines = [function(0x1400 + 0x40 * k, [('lea_g', 'RCX', 's', 'hello'), ('ret',)], name=f'u{k}', sym={'s': 0x2040})
             for k in range(3)]
    older, newer = build_pair(tmp_path, lines, lines)
    cancel = threading.Event()
    targets = TargetMap(older, newer, [(0x1400, 0x1400)], budget=Budget(cancel=cancel, check_every=1))
    cancel.set()
    sha = hashlib.sha256(b'hello').hexdigest()
    with pytest.raises(BudgetExhausted) as caught:
        targets.data_state(0x2040, 0x2040, shas=(sha, sha))
    assert caught.value.code == 'PT-UNIFIED-CANCEL'


def test_two_branches_to_different_unresolved_targets_are_never_cosmetic(tmp_path):
    old = leaving_the_image(image([('mov_ri', 'EAX', 1), ('jmp', 0x1F00)]), 1)
    new = leaving_the_image(image([('mov_ri', 'EAX', 1), ('jmp', 0x1F80)]), 1)
    facts = run_facts(tmp_path, old, new).facts('f')
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)
    assert facts.targets[1] >= 1         # counted as an unmapped address pair (class address-only), never mapped
