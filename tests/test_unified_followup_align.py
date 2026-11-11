"""p17: the instruction/block alignment is orientation-symmetric (SPEC-31 05 s2.3, A-31). `align(newer, older)` is the
mirror of `align(older, newer)` and verdicts, proofs and delta classes do not depend on which side is older.
Synthetic hand-assembled functions only (tests/unified_facts_builder.py), derandomised hypothesis, no live evidence."""
from __future__ import annotations

from collections import Counter

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from unified_facts_builder import build_pair, function, run_facts

from patchtrace.unified.facts import align as aligner
from patchtrace.unified.facts.fnview import load_view

SETTINGS = settings(max_examples=300, deadline=None, derandomize=True, database=None,
                    suppress_health_check=[HealthCheck.too_slow])
E2E_SETTINGS = settings(max_examples=60, deadline=None, derandomize=True, database=None,
                        suppress_health_check=[HealthCheck.too_slow])
SYM = {'g_a': 0x3000, 'helper': 0x1F00}
STRIDE = 0x200
PAIRS_PER_EXAMPLE = 5
INVERSES = {'Z': 'NZ', 'NZ': 'Z', 'C': 'NC', 'NC': 'C', 'L': 'GE', 'GE': 'L', 'S': 'NS', 'NS': 'S', 'BE': 'A', 'A': 'BE'}

OPS = (('mov_ri', 'EAX', 1), ('mov_ri', 'EAX', 2), ('mov_ri', 'ECX', 1), ('add_ri', 'EAX', 1), ('add_ri', 'ECX', 1),
       ('cmp_ri', 'EAX', 0), ('xor_rr', 'EAX', 'ECX'), ('nop',), ('call', 'helper'))
CCS = tuple(INVERSES)


def mirror(a: aligner.Alignment) -> aligner.Alignment:
    """The alignment seen from the other side: every (old, new) pair swapped."""
    def sw(pairs):
        return tuple(sorted((j, i) for i, j in pairs))
    return aligner.Alignment(
        pairs=sw(a.pairs), replaced=sw(a.replaced), old_only=a.new_only, new_only=a.old_only, block_pairs=sw(a.block_pairs),
        old_blocks_only=a.new_blocks_only, new_blocks_only=a.old_blocks_only,
        terminators={(bn, bo): (tn, to) for (bo, bn), (to, tn) in a.terminators.items()}, by_key=a.by_key,
        capped=a.capped)


# --- random functions -----------------------------------------------------------------------------------------------------

@st.composite
def block_st(draw):
    body = draw(st.lists(st.sampled_from(OPS), min_size=0, max_size=5))
    term = draw(st.sampled_from(('fall', 'fall', 'ret', 'jmp', 'jcc', 'jcc')))
    return {'body': body, 'term': term, 'cc': draw(st.sampled_from(CCS)), 'target': draw(st.integers(0, 3))}


spec_st = st.lists(block_st(), min_size=1, max_size=4)


def items_of(spec: list[dict]) -> list:
    """Hand-assembled items of a block spec; every block holds at least one instruction, the last one ends the function."""
    out: list = []
    for number, block in enumerate(spec):
        out.append(('label', f'b{number}'))
        body, term = list(block['body']), block['term']
        if number == len(spec) - 1 and term in ('fall', 'jcc'):
            term = 'ret'
        if not body and term == 'fall':
            body = [('xor_rr', 'EAX', 'ECX')]
        out.extend(body)
        if term == 'ret':
            out.append(('ret',))
        elif term == 'jmp':
            out.append(('jmp', f'b{block["target"] % len(spec)}'))
        elif term == 'jcc':
            out.append(('jcc', block['cc'], f'b{block["target"] % len(spec)}'))
    return out


def mutate(spec: list[dict], rnd) -> list[dict]:
    """A near-copy: invert a condition, duplicate a block body, drop/insert an instruction, swap two blocks' bodies."""
    new = [dict(b, body=list(b['body'])) for b in spec]
    for _ in range(rnd.randint(0, 3)):
        block = rnd.choice(new)
        action = rnd.choice(('invert', 'dup', 'drop', 'insert', 'same-body', 'swap-target'))
        if action == 'invert':
            block['cc'] = INVERSES[block['cc']]
        elif action == 'dup' and len(new) < 4:
            new.insert(rnd.randrange(len(new) + 1), dict(block, body=list(block['body'])))
        elif action == 'drop' and block['body']:
            block['body'].pop(rnd.randrange(len(block['body'])))
        elif action == 'insert' and len(block['body']) < 6:
            block['body'].insert(rnd.randrange(len(block['body']) + 1), rnd.choice(OPS))
        elif action == 'same-body':
            other = rnd.choice(new)
            block['body'] = list(other['body'])
        else:
            block['target'] = rnd.randrange(4)
    return new


@st.composite
def pair_st(draw):
    old = draw(spec_st)
    mode = draw(st.sampled_from(('mutate', 'mutate', 'independent', 'same')))
    if mode == 'independent':
        return old, draw(spec_st)
    if mode == 'same':
        return old, [dict(b, body=list(b['body'])) for b in old]
    return old, mutate(old, draw(st.randoms(use_true_random=False)))


def build_views(tmp_path, specs):
    old_fns = [function(0x1000 + STRIDE * k, items_of(o), name=f'f{k}', sym=SYM) for k, (o, _n) in enumerate(specs)]
    new_fns = [function(0x1000 + STRIDE * k, items_of(n), name=f'f{k}', sym=SYM) for k, (_o, n) in enumerate(specs)]
    old, new = build_pair(tmp_path, old_fns, new_fns)
    return [(load_view(old, 'older', old.functions.rva_to_fid[0x1000 + STRIDE * k]),
             load_view(new, 'newer', new.functions.rva_to_fid[0x1000 + STRIDE * k])) for k in range(len(specs))]


@SETTINGS
@given(st.lists(pair_st(), min_size=PAIRS_PER_EXAMPLE, max_size=PAIRS_PER_EXAMPLE))
def test_p17_alignment_of_swapped_sides_is_the_mirror(tmp_path_factory, specs):
    for old_view, new_view in build_views(tmp_path_factory.mktemp('p17'), specs):
        forward, backward = aligner.align(old_view, new_view), aligner.align(new_view, old_view)
        assert mirror(forward) == backward, (forward, backward)


@E2E_SETTINGS
@given(st.lists(pair_st(), min_size=3, max_size=3))
def test_p17_verdict_proof_and_deltas_do_not_depend_on_the_orientation(tmp_path_factory, specs):
    flip = {'block-added': 'block-removed', 'block-removed': 'block-added', 'call-added': 'call-removed',
            'call-removed': 'call-added'}
    old = [function(0x1000 + STRIDE * k, items_of(o), name=f'f{k}', sym=SYM) for k, (o, _n) in enumerate(specs)]
    new = [function(0x1000 + STRIDE * k, items_of(n), name=f'f{k}', sym=SYM) for k, (_o, n) in enumerate(specs)]
    forward = run_facts(tmp_path_factory.mktemp('fw'), old, new)
    backward = run_facts(tmp_path_factory.mktemp('bw'), new, old)
    for k in range(len(specs)):
        name = f'f{k}'
        f, b = forward.facts(name), backward.facts(name)
        assert (f.verdict, f.proof) == (b.verdict, b.proof), (name, specs[k])
        assert Counter((flip.get(d.cls, d.cls), d.channel) for d in f.deltas) == \
            Counter((d.cls, d.channel) for d in b.deltas), (name, specs[k])
        assert dict(f.channels) == dict(b.channels), (name, specs[k])


# --- one hand-built regression per asymmetry --------------------------------------------------------------------------

def pair_views(tmp_path, old_items, new_items):
    old, new = build_pair(tmp_path, [function(0x1000, old_items, sym=SYM)], [function(0x1000, new_items, sym=SYM)])
    return load_view(old, 'older', old.functions.rva_to_fid[0x1000]), load_view(new, 'newer', new.functions.rva_to_fid[0x1000])


def test_p17_queue_order_pairs_unpaired_successors_the_same_way_from_both_sides(tmp_path):
    """Rule: `pair_blocks` queue order. Two key-paired blocks A and B both jump to the same old block X while the new
    side sends them to two different new blocks P and Q; X pairs with whichever parent is processed first. Seeding the
    BFS by the OLD ordinal made that the old-lower block, so the mirrored call chose the other parent."""
    old_items = [('label', 'e'), ('cmp_ri', 'EAX', 0), ('jcc', 'Z', 'b'),
                 ('label', 'a'), ('mov_ri', 'ECX', 1), ('mov_ri', 'ECX', 11), ('jmp', 'x'),
                 ('label', 'b'), ('mov_ri', 'EBX', 2), ('add_ri', 'EBX', 22), ('jmp', 'x'),
                 ('label', 'x'), ('mov_ri', 'EDX', 9), ('ret',)]
    new_items = [('label', 'e'), ('cmp_ri', 'EAX', 0), ('jcc', 'Z', 'a'),
                 ('label', 'b'), ('mov_ri', 'EBX', 2), ('add_ri', 'EBX', 22), ('jmp', 'q'),
                 ('label', 'a'), ('mov_ri', 'ECX', 1), ('mov_ri', 'ECX', 11), ('jmp', 'p'),
                 ('label', 'p'), ('mov_ri', 'EDX', 7), ('ret',),
                 ('label', 'q'), ('mov_ri', 'EDX', 8), ('ret',)]
    old_view, new_view = pair_views(tmp_path, old_items, new_items)
    forward, backward = aligner.align(old_view, new_view), aligner.align(new_view, old_view)
    assert mirror(forward) == backward
    assert len(forward.block_pairs) == 4       # entry, A, B and exactly one of (X, P), (X, Q)


def test_p17_lcs_tie_picks_the_same_matching_from_both_sides():
    """Rule: LCS tie. `ab` vs `ba` has two equal-length matchings ((0,1) or (1,0)); the old fill took the old-side-first
    one, so the mirrored call chose the other."""
    a, b = list('ab'), list('ba')
    forward = aligner.lcs_pairs(a, b)
    assert sorted((j, i) for i, j in forward) == aligner.lcs_pairs(b, a)
    a, b = list('xAyBz'), list('BAxyz')
    assert sorted((j, i) for i, j in aligner.lcs_pairs(a, b)) == aligner.lcs_pairs(b, a)


def test_p17_patience_tie_picks_the_same_chain_from_both_sides():
    """Rule: patience tie. Two unique items in opposite order form two chains of length one; the chain must not depend
    on which side is `a`."""
    a, b = ['p', 'q'], ['q', 'p']
    assert sorted((j, i) for i, j in aligner.patience_anchors(a, b)) == aligner.patience_anchors(b, a)


@pytest.mark.parametrize('a, b', [(list('ab'), list('ba')), (list('abc'), list('cab')), (list('abcd'), list('badc'))])
def test_p17_diff_tokens_is_mirror_consistent(a, b):
    """Rule: the whole token diff (anchors + LCS fill) mirrors."""
    forward = aligner.diff_tokens(a, b, a, b)
    backward = aligner.diff_tokens(b, a, b, a)
    assert (sorted((j, i) for i, j in forward[0]), forward[1]) == (backward[0], backward[1])


def test_p17_substitution_scan_mirrors(tmp_path):
    """Rule: substitution scan. Runs of unequal length between two anchors are paired from the run start on both sides
    (family-wise), the leftovers are the tails; swapping the sides swaps the leftovers."""
    old_items = [('mov_ri', 'EAX', 1), ('cmp_ri', 'EAX', 0), ('xor_rr', 'EAX', 'ECX'), ('mov_ri', 'ECX', 3), ('ret',)]
    new_items = [('mov_ri', 'EAX', 1), ('cmp_ri', 'EAX', 0), ('add_ri', 'EAX', 1), ('xor_rr', 'EAX', 'ECX'),
                 ('mov_ri', 'ECX', 3), ('ret',)]
    old_view, new_view = pair_views(tmp_path, old_items, new_items)
    assert mirror(aligner.align(old_view, new_view)) == aligner.align(new_view, old_view)


def test_p17_layout_edge_check_counts_an_unpaired_successor_on_either_side(tmp_path):
    """Rule: COS-LAYOUT/1 edge mapping (`layout._same_edges`). The old fall-through successor is key-paired with a block
    that is NOT the new fall-through successor, and the new fall-through successor has no partner: counted only from the
    old side that is a conflict, from the new side an unmapped target. Both orientations must give the same state."""
    from patchtrace.unified.facts.datamap import TargetMap
    from patchtrace.unified.facts.layout import compare_cfg
    old_items = [('cmp_ri', 'EAX', 0), ('jcc', 'Z', 'a'), ('mov_ri', 'ECX', 2), ('ret',),
                 ('label', 'a'), ('mov_ri', 'EDX', 1), ('ret',)]
    new_items = [('cmp_ri', 'EAX', 0), ('jcc', 'Z', 'a'), ('mov_ri', 'EBX', 5), ('ret',),
                 ('label', 'a'), ('mov_ri', 'EDX', 1), ('ret',), ('mov_ri', 'ECX', 2), ('ret',)]
    old, new = build_pair(tmp_path, [function(0x1000, old_items, sym=SYM)], [function(0x1000, new_items, sym=SYM)])
    view_old, view_new = (load_view(old, 'older', old.functions.rva_to_fid[0x1000]),
                          load_view(new, 'newer', new.functions.rva_to_fid[0x1000]))
    forward = compare_cfg(view_old, view_new, aligner.align(view_old, view_new), TargetMap(old, new, [(0x1000, 0x1000)]))
    backward = compare_cfg(view_new, view_old, aligner.align(view_new, view_old), TargetMap(new, old, [(0x1000, 0x1000)]))
    assert forward.cons.as_tuple() == backward.cons.as_tuple()
    assert forward.layout_ok == backward.layout_ok is False
