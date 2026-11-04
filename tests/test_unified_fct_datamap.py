"""SPEC-31 S3 audit (card fct): target consistency (05 s2.7, DATA-MAP/1) on degenerate and hostile targets.

A target the IR could not resolve (an operand whose address lies outside the image has no value) is no evidence of
anything: it is never `mapped`, so it can never support UNCH/1, COS-ADDR/1 or COS-LAYOUT/1. Hand-assembled x86-64
through the real ingest; synthetic, never live Ghidra evidence."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import OPT_ADDR_CODE, build_pair, function, run_facts

from patchtrace.unified.facts.datamap import UNMAPPED, TargetMap

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


def test_two_branches_to_different_unresolved_targets_are_never_cosmetic(tmp_path):
    old = leaving_the_image(image([('mov_ri', 'EAX', 1), ('jmp', 0x1F00)]), 1)
    new = leaving_the_image(image([('mov_ri', 'EAX', 1), ('jmp', 0x1F80)]), 1)
    facts = run_facts(tmp_path, old, new).facts('f')
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)
    assert facts.targets[1] >= 1         # counted as an unmapped address pair (class address-only), never mapped
