"""SPEC-31 S3 audit (card fct): the operand-delta classifier C2 (05 s2.2) on shapes the block logic does not own.

A conditional jump is normally a block terminator compared by the CFG edge logic (`layout.py`). Two real shapes put it
inside a block body, where the alignment pairs it as a same-family substitution: a conditional tail call that Ghidra's
flow override records as CONDITIONAL_CALL_TERMINATOR (not a direct branch), and a function without a block list (one
synthesized block). Its condition change must still be a `condition` delta, never a silent substitution.
Hand-assembled x86-64 through the real ingest; synthetic, never live Ghidra evidence."""
from __future__ import annotations

import pytest
from test_unified_ir_facts import image
from unified_facts_builder import run_facts

SAFE = ('material', 'review')


def without_blocks(fns):
    for fn in fns:
        if fn['name'] == 'f':
            fn['blocks'] = []
    return fns


def call_terminator(fns):
    for fn in fns:
        if fn['name'] == 'f':
            fn['insns'][1][5] = 'CONDITIONAL_CALL_TERMINATOR'
    return fns


CASES = {
    'no-block-list': ([('cmp_ri', 'ECX', 6), ('jcc', '{cc}', 'out'), ('mov_ri', 'EAX', 1), ('label', 'out'), ('ret',)],
                      without_blocks),
    'call-terminator': ([('cmp_ri', 'ECX', 6), ('jcc', '{cc}', 'helper'), ('mov_ri', 'EAX', 1), ('ret',)],
                        call_terminator),
}


def items(shape, cc):
    return [tuple(cc if part == '{cc}' else part for part in item) for item in CASES[shape][0]]


@pytest.mark.parametrize('shape', sorted(CASES), ids=sorted(CASES))
@pytest.mark.parametrize('old_cc,new_cc', [('Z', 'NZ'), ('L', 'C'), ('L', 'LE')], ids=['flip', 'signedness', 'bound'])
def test_condition_change_of_a_jcc_inside_a_block_body_is_a_condition_delta(tmp_path, shape, old_cc, new_cc):
    edit = CASES[shape][1]
    facts = run_facts(tmp_path, edit(image(items(shape, old_cc))), edit(image(items(shape, new_cc)))).facts('f')
    assert facts.verdict in SAFE and facts.proof is None, (facts.verdict, facts.proof)
    assert 'condition' in {d.cls for d in facts.deltas}
    assert dict(facts.channels)['C2'] == 'differs'


@pytest.mark.parametrize('shape', sorted(CASES), ids=sorted(CASES))
def test_an_unchanged_jcc_inside_a_block_body_adds_no_delta(tmp_path, shape):
    edit = CASES[shape][1]
    facts = run_facts(tmp_path, edit(image(items(shape, 'Z'))), edit(image(items(shape, 'Z'), f_rva=0x1100))).facts('f')
    assert facts.verdict == 'unchanged' and facts.deltas == ()
