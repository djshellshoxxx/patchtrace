"""SPEC-31 S3 audit (card fct): COS-LAYOUT/1 over terminating branches that LEAVE the function (05 s2.5, review R-04).

A conditional jump to another function's entry (a conditional tail call) is a block terminator whose taken edge is a
function target and whose not-taken edge is an ordinary fall-through edge. The polarity of that branch and its
fall-through successor are as semantic as those of any other branch: a flipped condition, a signedness or bound change
or a fall-through into another block is never a layout change. Hand-assembled x86-64 through the real ingest; the
functions are matched by name with tier-A rows. Synthetic: nothing here is live Ghidra evidence."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import SYM, image
from unified_facts_builder import run_facts, sites

SAFE = ('material', 'review')


def tail_called(items, *, index=1, target='helper', **kwargs):
    """`image(items)` where instruction `index` of `f` is a direct jump to `target` that Ghidra records as a call row of
    kind `jump` (a jump leaving the function, 03 s12.3) and keeps out of the block successors."""
    fns = image(items, **kwargs)
    for fn in fns:
        if fn['name'] == 'f':
            fn['calls'] = sorted([*fn['calls'], [sites(fn)[index], SYM[target], None, 'jump']])
    return fns


def judged(tmp_path, old, new, **kwargs):
    return run_facts(tmp_path, tail_called(old), tail_called(new, **kwargs)).facts('f')


def guard(cc):
    return [('cmp_ri', 'ECX', 6), ('jcc', cc, 'helper'), ('mov_ri', 'EAX', 1), ('ret',)]


@pytest.mark.parametrize('old_cc,new_cc', [('Z', 'NZ'), ('L', 'C'), ('L', 'LE'), ('NZ', 'Z')],
                         ids=['flip', 'signedness', 'bound', 'flip-back'])
def test_condition_change_of_a_conditional_tail_call_is_never_cosmetic(tmp_path, old_cc, new_cc):
    facts = judged(tmp_path, guard(old_cc), guard(new_cc))
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)
    assert 'condition' in {d.cls for d in facts.deltas}


def test_fall_through_of_a_conditional_tail_call_into_another_block_is_never_cosmetic(tmp_path):
    """The bodies of the two return blocks swap places: every block keeps its unique body key, but the not-taken path
    of the tail call now returns 2 instead of 1."""
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'Z', 'helper'), ('mov_ri', 'EAX', 1), ('ret',), ('mov_ri', 'EAX', 2), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'Z', 'helper'), ('mov_ri', 'EAX', 2), ('ret',), ('mov_ri', 'EAX', 1), ('ret',)]
    facts = judged(tmp_path, old, new)
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)
    assert 'cfg' in {d.cls for d in facts.deltas}


def test_a_tail_call_that_becomes_conditional_is_never_cosmetic(tmp_path):
    old = [('cmp_ri', 'ECX', 6), ('tail_call', 'helper'), ('mov_ri', 'EAX', 1), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'Z', 'helper'), ('mov_ri', 'EAX', 1), ('ret',)]
    facts = run_facts(tmp_path, image(old), tail_called(new)).facts('f')
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)


@pytest.mark.parametrize('shape', ['jmp', 'jcc'], ids=['jmp', 'jcc'])
def test_a_retargeted_tail_jump_is_reported_once_and_anchored_like_a_call(tmp_path, shape):
    """`jmp helper` -> `jmp other` (a direct jump leaving the function) is the same callee change as `call helper` ->
    `call other`: one `callee` delta that C4 anchors (05 s2.5 MAT-ANCHOR), not a C2 delta without call identities plus
    a second C4 delta for the same change."""
    branch = ('jmp',) if shape == 'jmp' else ('jcc', 'Z')
    tail = [('cmp_ri', 'ECX', 6), (*branch, 'helper'), ('mov_ri', 'EAX', 1), ('ret',)]
    retargeted = [('cmp_ri', 'ECX', 6), (*branch, 'other'), ('mov_ri', 'EAX', 1), ('ret',)]
    facts = run_facts(tmp_path, tail_called(tail), tail_called(retargeted, target='other')).facts('f')
    assert [(d.cls, d.channel) for d in facts.deltas] == [('callee', 'C2')]
    assert (facts.verdict, facts.second_channel) == ('material', 'C4')


def test_an_unchanged_conditional_tail_call_keeps_its_proofs(tmp_path):
    """Controls: the same function at a moved RVA, and with an inner branch inverted and its successors swapped behind
    the tail call, keep UNCH/1 and COS-LAYOUT/1 (the fix must not turn layout noise into review rows)."""
    assert run_facts(tmp_path, tail_called(guard('Z')), tail_called(guard('Z'), f_rva=0x1100)).verdict('f') == \
        ('unchanged', 'UNCH/1')
    old = [('cmp_ri', 'ECX', 6), ('jcc', 'Z', 'helper'), ('cmp_ri', 'ECX', 1), ('jcc', 'Z', 'then'), ('mov_ri', 'EAX', 2),
           ('jmp', 'end'), ('label', 'then'), ('mov_ri', 'EAX', 3), ('label', 'end'), ('ret',)]
    new = [('cmp_ri', 'ECX', 6), ('jcc', 'Z', 'helper'), ('cmp_ri', 'ECX', 1), ('jcc', 'NZ', 'else'), ('mov_ri', 'EAX', 3),
           ('jmp', 'end'), ('label', 'else'), ('mov_ri', 'EAX', 2), ('label', 'end'), ('ret',)]
    assert run_facts(tmp_path, tail_called(old), tail_called(new)).verdict('f') == ('cosmetic', 'COS-LAYOUT/1')
