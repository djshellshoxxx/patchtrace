"""The residual passes P16-P19 (SPEC-31 04 s6.2-s6.4): reference vectors, block votes, layout gaps, assignment.

Every scenario runs the residual passes ALONE (`passes=residual_passes(...)`), with tier-M anchors standing in for the
matches the earlier passes would have made, so each assertion isolates one rule. SYNTHETIC IR only.
"""
from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, make_body, pairs_by_tag, random_world  # noqa: E402
from unified_residual_support import BodyMnemonics, edited, make_state  # noqa: E402

from patchtrace.unified.ladder.blocking import Blocked, references  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.ladder.residual import (  # noqa: E402
    NANO,
    _assign,
    _decide,
    confident,
    cosine_micro,
    incidences,
    nats_nano,
    residual_passes,
)
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402


def run(older, newer, anchors=(), *, limits=DEFAULT_LIMITS, budget=None, sources=True):
    table = residual_passes(BodyMnemonics(older), BodyMnemonics(newer)) if sources else residual_passes()
    return run_ladder(older, newer, anchors=[(older.fid(a), newer.fid(b)) for a, b in anchors], passes=table,
                      limits=limits, budget=budget)


def found(corr, older, newer, pass_id=None):
    return {tags: p for tags, p in pairs_by_tag(corr, older, newer).items()
            if p.pass_id != 'P00' and (pass_id is None or p.pass_id == pass_id)}


def seed_of(tag):
    return 500 + sum(ord(c) for c in tag)


# ---- exact arithmetic ----------------------------------------------------------------------------------------------------------

def test_nats_are_exact_integers_independent_of_libm():
    assert nats_nano(1, 2) == 693_147_181                    # ln 2
    assert nats_nano(1, 3) == 1_098_612_289                  # ln 3
    assert nats_nano(2, 6) == nats_nano(1, 3)
    assert nats_nano(5, 5) == 0 and nats_nano(9, 5) == 0       # a feature in every reference carries no information
    assert nats_nano(1, 10 ** 6) == 13_815_510_558           # ln 10^6


def test_cosine_is_floored_micro_units_with_exact_threshold_edges():
    assert cosine_micro(1, 1, 1) == 1_000_000
    assert cosine_micro(3, 4, 9) == 500_000
    assert cosine_micro(19, 20, 20) == 950_000                # exactly 0.95: meets the L-20 bar
    assert cosine_micro(18_999, 20_000, 20_000) == 949_950    # just below it
    assert cosine_micro(0, 5, 5) == 0 and cosine_micro(5, 0, 5) == 0


def test_confidence_needs_exactly_one_nat_of_shared_evidence():
    assert confident(NANO, DEFAULT_LIMITS) and not confident(NANO - 1, DEFAULT_LIMITS)      # dot x 10 >= 10.0


def decide(scores, limits=DEFAULT_LIMITS):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(3):
            ir.add(f'f{i}', seed=i)
    state = make_state(older, newer, limits=limits)
    return _decide(state, scores, lambda letter, fid: ({('i', 'shared'): 1}, 1))


@pytest.mark.parametrize(('scores', 'accepted', 'ambiguous'), [
    ({(0, 0): (950_000, NANO)}, [(0, 0)], []),                                              # exactly the 0.95 bar
    ({(0, 0): (949_999, NANO)}, [], []),                                                    # one micro-unit below
    ({(0, 0): (1_000_000, NANO - 1)}, [], []),                                              # confidence just short
    ({(0, 0): (1_000_000, NANO), (0, 1): (950_000, NANO)}, [(0, 0)], []),                   # margin exactly 0.05
    ({(0, 0): (1_000_000, NANO), (0, 1): (950_001, NANO)}, [], [(0, 0)]),                   # 0.04999: ambiguous
    ({(0, 0): (1_000_000, NANO), (1, 0): (950_000, NANO)}, [(0, 0)], [(1, 0)]),             # the loser of a column
    ({(0, 0): (1_000_000, NANO), (1, 0): (950_001, NANO)}, [], [(0, 0), (1, 0)]),           # reverse margin 0.04999
], ids=['at-cosine-bar', 'below-cosine-bar', 'below-confidence', 'margin-at-0.05', 'margin-under', 'column-loser',
        'reverse-margin-under'])
def test_the_acceptance_bars_are_exact(scores, accepted, ambiguous):
    decisions, unclear = decide(scores)
    assert [(x, y) for x, y, _tier, _anchors in decisions] == accepted
    assert unclear == ambiguous


def test_a_function_whose_best_partner_prefers_another_is_not_paired_with_it():
    """The mutual-best test matters as soon as the cosine bar sits below 1 - margin (here 0.5)."""
    low = dataclasses.replace(DEFAULT_LIMITS, l20_cosine_min_milli=500)
    decisions, unclear = decide({(0, 0): (800_000, NANO), (1, 0): (1_000_000, NANO)}, limits=low)
    assert [(x, y) for x, y, _tier, _anchors in decisions] == [(1, 0)] and unclear == [(0, 0)]


# ---- P16 reference vectors ---------------------------------------------------------------------------------------------------------

def reference_world(n=3, *, calls_older=(), calls_newer=(), imports=(), strings=(), n_insn=12):
    """`n` matched leaf neighbours N1..Nn and one function X per side that calls all of them (plus extras)."""
    older, newer = SyntheticIr(), SyntheticIr()
    tags = [f'N{i}' for i in range(1, n + 1)]
    for tag in tags:
        older.add(tag, seed=seed_of(tag))
        newer.add(tag, seed=seed_of(tag))
    calls = (*tags, *(f'imp:{key}' for key in imports))
    older.add('X', seed=1, n_insn=n_insn, strings=strings, calls=calls + tuple(calls_older))
    newer.add('X', seed=2, n_insn=n_insn, strings=strings, calls=calls + tuple(calls_newer))
    return older, newer, [(tag, tag) for tag in tags]


def test_refvector_shared_matched_neighbours_pair_at_tier_c():
    older, newer, anchors = reference_world()
    corr = run(older, newer, anchors)
    pair = found(corr, older, newer)[('X', 'X')]
    assert (pair.pass_id, pair.step, pair.tier, pair.cls, pair.family) == (
        'P16', 'P16-ref-vector', 'C', 'E-RESID', 'F-PT-STRUCT')          # one feature type: matched neighbours only
    # provenance: the shared matched neighbour pairs that carry the evidence (at most 4, sorted)
    assert pair.anchors == tuple(sorted((older.fid(t), newer.fid(t)) for t, _ in anchors))
    assert corr.status == 'complete'


def test_refvector_two_feature_types_give_tier_b():
    older, newer, anchors = reference_world(imports=('lib!f',))
    pair = found(run(older, newer, anchors), older, newer)[('X', 'X')]
    assert pair.tier == 'B' and pair.pass_id == 'P16'


def test_refvector_rare_strings_and_matched_neighbours_give_tier_b():
    older, newer, anchors = reference_world(strings=('only-here-text',))
    assert found(run(older, newer, anchors), older, newer)[('X', 'X')].tier == 'B'


def thunk_world(**kwargs):
    older, newer, anchors = reference_world(**kwargs)
    for ir in (older, newer):
        ir.add('T', kind='thunk', thunk_target='X')
    return older, newer, anchors


def test_a_tier_b_pair_seeds_propagation_a_tier_c_pair_does_not():
    """The thunk of X pairs only once X itself is an accepted pair: tier B is accepted at once, tier C is soft."""
    older, newer, anchors = thunk_world(imports=('lib!f',))
    assert ('T', 'T') in found(run(older, newer, anchors), older, newer)
    older, newer, anchors = thunk_world()
    corr = run(older, newer, anchors)
    assert ('X', 'X') in found(corr, older, newer) and ('T', 'T') not in found(corr, older, newer)


def test_refvector_tie_between_two_candidates_drops_both_and_hints():
    older, newer, anchors = reference_world()
    newer.add('Y', seed=3, calls=('N1', 'N2', 'N3'))                     # a twin of the newer X
    corr = run(older, newer, anchors)
    assert not found(corr, older, newer)
    assert corr.stat('ambiguous:P16') >= 1
    assert 'residual-ambiguous' in {h for item in corr.older_only for h in item.hints}


def test_refvector_mutual_best_with_margin():
    older, newer, anchors = reference_world()
    newer.add('Y', seed=3, calls=('N1', 'N2'))                           # cosine ~0.8 against the older X
    assert set(found(run(older, newer, anchors), older, newer)) == {('X', 'X')}


def test_refvector_margin_is_checked_from_the_other_direction_too():
    older, newer, anchors = reference_world()
    older.add('W', seed=4, calls=('N1', 'N2', 'N3'))                      # a second older function, identical features
    assert not found(run(older, newer, anchors), older, newer)          # the newer X has two equally good partners


def test_refvector_unmatched_references_lower_the_cosine():
    older, newer, anchors = reference_world(calls_older=('U1', 'U2'))
    older.add('U1', seed=8)
    older.add('U2', seed=9)
    # two references of the older X point at functions without a pair: cosine ~0.84 < 0.95
    assert not found(run(older, newer, anchors), older, newer)


def test_refvector_needs_the_evidence_mass_of_one_nat():
    """Identical vectors (cosine 1.0) whose only shared feature is an import called by everyone carry no evidence."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(30):
            ir.add(f'f{i}', seed=100 + i, n_insn=30, calls=('imp:lib!common',))
        ir.add('rare-user', seed=900, n_insn=30, calls=('imp:lib!other',))
    base = make_body(7, 60)
    older.add('X', body=base, n_bb=6, calls=('imp:lib!common',))
    newer.add('X', body=edited(base, extra=1), n_bb=7, calls=('imp:lib!common',))
    corr = run(older, newer)
    assert ('X', 'X') not in found(corr, older, newer, 'P16')


def test_refvector_never_pairs_tiny_functions():
    older, newer, anchors = reference_world(n_insn=4)                    # <= L-10 instructions: I6
    assert not found(run(older, newer, anchors), older, newer)


# ---- P17 basic-block votes ------------------------------------------------------------------------------------------------------

def blocks(*seeds, n=5):
    return tuple(make_body(s, n) for s in seeds)


def block_world(older_blocks, newer_blocks):
    older, newer = SyntheticIr(), SyntheticIr()
    for tag, seeds in older_blocks.items():
        older.add(tag, blocks=blocks(*seeds))
    for tag, seeds in newer_blocks.items():
        newer.add(tag, blocks=blocks(*seeds))
    return older, newer


def test_bb_vote_two_distinct_rare_blocks_pair_at_tier_c():
    older, newer = block_world({'X': (1, 2, 3)}, {'Y': (1, 2, 4)})
    pair = found(run(older, newer), older, newer)[('X', 'Y')]
    assert (pair.pass_id, pair.step, pair.tier, pair.cls, pair.votes) == ('P17', 'P17-bb-vote', 'C', 'E-RESID', 2)


def test_bb_vote_a_single_shared_block_is_not_enough():
    older, newer = block_world({'X': (1, 2, 3)}, {'Y': (1, 5, 6)})
    assert not found(run(older, newer), older, newer)


def test_bb_vote_blocks_that_repeat_among_unmatched_functions_do_not_vote():
    older, newer = block_world({'X': (1, 2, 3), 'X2': (1, 2, 9)}, {'Y': (1, 2, 4)})
    assert not found(run(older, newer), older, newer)                       # blocks 1 and 2 occur in two older functions


def test_bb_vote_split_votes_have_no_majority():
    older, newer = block_world({'X': (1, 2, 3, 4)}, {'Y1': (1, 2, 8), 'Y2': (3, 4, 9)})
    assert not found(run(older, newer), older, newer)                       # 2 + 2 votes


def test_bb_vote_the_pair_must_be_the_majority_for_both_functions():
    older, newer = block_world({'X': (1, 2, 8), 'X2': (3, 4, 5)}, {'Y': (1, 2, 3, 4, 5, 9)})
    corr = run(older, newer)
    assert set(found(corr, older, newer)) == {('X2', 'Y')}                      # Y: 3 votes for X2 beat 2 for X
    assert found(corr, older, newer)[('X2', 'Y')].votes == 3


def run_pass(pass_id, older, newer, anchors=(), limits=DEFAULT_LIMITS):
    """One residual pass on a fresh state; returns the state so the soft candidates can be inspected."""
    state = make_state(older, newer, anchors, limits=limits)
    spec = next(s for s in residual_passes(BodyMnemonics(older), BodyMnemonics(newer)) if s.id == pass_id)
    spec.run(state, 1)
    return state


def test_bb_vote_split_votes_leave_no_soft_candidate_at_all():
    """Not only the final pairs: the strict majority itself (2n > votes), not merely the later conflict rule."""
    older, newer = block_world({'X': (1, 2, 3, 4)}, {'Y1': (1, 2, 8), 'Y2': (3, 4, 9)})
    assert run_pass('P17', older, newer).soft == {}
    older, newer = block_world({'X': (1, 2, 3)}, {'Y': (1, 2, 4)})
    assert set(run_pass('P17', older, newer).soft) == {(older.fid('X'), newer.fid('Y'))}


def test_bb_vote_ignores_blocks_of_matched_functions():
    older, newer = block_world({'X': (1, 2, 3), 'M': (7, 8, 9)}, {'Y': (1, 2, 4), 'M': (7, 8, 9)})
    corr = run(older, newer, anchors=[('M', 'M')])
    assert set(found(corr, older, newer)) == {('X', 'Y')}
    state = run_pass('P17', older, newer, anchors=[('M', 'M')])
    assert set(state.soft) == {(older.fid('X'), newer.fid('Y'))}          # the matched pair never even votes


# ---- P18 layout gaps -----------------------------------------------------------------------------------------------------------

def gap_world(older_tags, newer_tags):
    older, newer = SyntheticIr(), SyntheticIr()
    for tag in older_tags:
        older.add(tag, seed=seed_of(tag))
    for tag in newer_tags:
        newer.add(tag, seed=seed_of(tag) + 7)
    return older, newer


ANCHORS = [('A1', 'A1'), ('A2', 'A2')]


def test_layout_gap_singleton_between_monotone_anchors():
    older, newer = gap_world(['A1', 'X', 'A2'], ['A1', 'Y', 'A2'])
    pair = found(run(older, newer, ANCHORS), older, newer)[('X', 'Y')]
    assert (pair.pass_id, pair.step, pair.tier, pair.cls) == ('P18', 'P18-layout-gap', 'C', 'E-LAYOUT')
    assert pair.anchors == ((older.fid('A1'), newer.fid('A1')), (older.fid('A2'), newer.fid('A2')))


def test_layout_gap_needs_monotone_anchor_order():
    older, newer = gap_world(['A1', 'X', 'A2'], ['A2', 'Y', 'A1'])
    assert not found(run(older, newer, ANCHORS), older, newer)


@pytest.mark.parametrize('newer_tags', [['A1', 'Y1', 'Y2', 'A2'], ['A1', 'A2']], ids=['two-newer', 'no-newer'])
def test_layout_gap_needs_exactly_one_function_per_side(newer_tags):
    older, newer = gap_world(['A1', 'X', 'A2'], newer_tags)
    assert not found(run(older, newer, ANCHORS), older, newer)


@pytest.mark.parametrize(('newer_insns', 'expected'), [(40, False), (20, True)], ids=['ratio-3.3', 'ratio-1.7'])
def test_layout_gap_size_ratio_guard(newer_insns, expected):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, n_insn in ((older, 12), (newer, newer_insns)):
        ir.add('A1', seed=1)
        ir.add('X', seed=2 + n_insn, n_insn=n_insn)
        ir.add('A2', seed=3)
    assert (('X', 'X') in found(run(older, newer, ANCHORS), older, newer)) is expected


def test_layout_gap_function_matched_elsewhere_is_not_a_gap():
    older, newer = gap_world(['A1', 'X', 'A2', 'Z'], ['A1', 'Y', 'A2'])
    corr = run(older, newer, anchors=[*ANCHORS, ('Z', 'Y')])               # Y already pairs with the later Z
    assert ('X', 'Y') not in found(corr, older, newer)


def test_layout_gap_proposes_nothing_for_a_function_matched_elsewhere():
    older, newer = gap_world(['A1', 'X', 'A2', 'Z'], ['A1', 'Y', 'A2'])
    state = run_pass('P18', older, newer, anchors=[*ANCHORS, ('Z', 'Y')])
    assert state.soft == {}                              # not merely dropped at the end: never proposed


def test_layout_gap_skips_hubs():
    older, newer = gap_world(['A1', 'X', 'A2'], ['A1', 'Y', 'A2'])
    for ir in (older, newer):
        for i in range(3):
            ir.add(f'C{i}', seed=70 + i, calls=('X',) if ir is older else ('Y',))     # three callers of the gap function
    hub = dataclasses.replace(DEFAULT_LIMITS, l17_hub_fan_in=2)
    assert run_pass('P18', older, newer, anchors=ANCHORS, limits=hub).soft == {}
    assert len(run_pass('P18', older, newer, anchors=ANCHORS).soft) == 1               # a plain function would pair


def test_layout_gap_skips_icf_suspects():
    """An alias-bearing function whose names map to two functions on the other side says N:M, not a 1:1 slot."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('A1', seed=1)
    older.add('fold', seed=2, name='Alpha', name_src='IMPORTED', aliases=('Beta',))
    older.add('A2', seed=3)
    newer.add('A1', seed=11)
    newer.add('one', seed=12, name='Alpha', name_src='IMPORTED')
    newer.add('A2', seed=13)
    newer.add('two', seed=14, name='Beta', name_src='IMPORTED')
    state = run_pass('P18', older, newer, anchors=ANCHORS)
    assert state.icf_a[older.fid('fold')] and state.soft == {}


def test_layout_gap_skips_thunks():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('A1', seed=1)
        ir.add('T', kind='thunk', thunk_target='A1')
        ir.add('A2', seed=3)
    corr = run(older, newer, ANCHORS)
    assert not found(corr, older, newer, 'P18')       # (propagation's own thunk-target rule still pairs the thunks)


def test_layout_gap_size_is_the_l26_limit():
    older, newer = gap_world(['A1', 'X1', 'X2', 'A2'], ['A1', 'Y1', 'Y2', 'A2'])
    assert not found(run(older, newer, ANCHORS), older, newer)                       # default L-26 = 1
    two = dataclasses.replace(DEFAULT_LIMITS, l26_gap_functions=2)
    assert set(found(run(older, newer, ANCHORS, limits=two), older, newer)) == {('X1', 'Y1'), ('X2', 'Y2')}


# ---- P19 assignment with rejection -----------------------------------------------------------------------------------------------

def string_world(shared, own=2, *, extra_newer=(), similar_bodies=False):
    """X and Y share `shared` rare strings and have `own` private ones; the size buckets agree, so the token Jaccard is
    (shared + 2) / (shared + own + 4) while no mnemonic stream is read. With a source, unrelated bodies add four
    unshared MinHash tokens each (a lower Jaccard), so `similar_bodies` gives X and Y a close pair of bodies."""
    older, newer = SyntheticIr(), SyntheticIr()
    common = tuple(f'common-text-{i}' for i in range(shared))
    if similar_bodies:
        base = make_body(3, 60)
        body_x, body_y = {'body': base}, {'body': edited(base, extra=1)}
    else:
        body_x, body_y = {'seed': 1}, {'seed': 2}
    older.add('X', n_bb=6, strings=(*common, *(f'old-only-{i}' for i in range(own))), **body_x)
    newer.add('Y', n_bb=6, strings=(*common, *(f'new-only-{i}' for i in range(own))), **body_y)
    for tag, strings in extra_newer:
        newer.add(tag, seed=seed_of(tag), n_bb=6, strings=strings)
    return older, newer


def test_assignment_similar_functions_pair_at_tier_c():
    older, newer = string_world(8)                  # 10 shared of 14 distinct tokens: 0.714 >= floor 0.6
    pair = found(run(older, newer, sources=False), older, newer, 'P19')[('X', 'Y')]
    assert (pair.pass_id, pair.step, pair.tier, pair.cls, pair.family) == (
        'P19', 'P19-assignment', 'C', 'E-RESID', 'F-PT-STRUCT')


def test_a_similarity_exactly_at_the_floor_is_assigned():
    older, newer = string_world(4)                  # 6 shared of 10 distinct tokens: exactly 0.6 = the L-24 floor
    assert ('X', 'Y') in found(run(older, newer, sources=False), older, newer, 'P19')


def test_lap_reject_cost_leaves_function_unmatched_at_the_pass_level():
    older, newer = string_world(3)                  # 5 shared of 9 distinct tokens: 0.556 < floor
    corr = run(older, newer, sources=False)
    assert not found(corr, older, newer)
    assert corr.stat('evaluated:P19') >= 1          # it was a candidate and was evaluated, then rejected


def test_assignment_margin_to_the_best_alternative_must_reach_0_05():
    twin = tuple(f'common-text-{i}' for i in range(8)) + ('other-text-1', 'other-text-2')
    older, newer = string_world(8, extra_newer=[('Y2', twin)])
    corr = run(older, newer, sources=False)
    assert not found(corr, older, newer)                                 # Y and Y2 are equally close to X
    assert corr.stat('ambiguous:P19') >= 1
    assert 'residual-ambiguous' in {h for item in corr.older_only for h in item.hints}


def test_assignment_buckets_above_l24_abstain_and_are_counted():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, prefix in ((older, 'x'), (newer, 'y')):
        for i in range(3):
            ir.add(f'{prefix}{i}', seed=seed_of(prefix) + i, n_bb=6,
                   strings=(*(f'common-text-{k}' for k in range(8)), f'own-{prefix}{i}'))
    small = dataclasses.replace(DEFAULT_LIMITS, l24_assign_bucket_cap=2)
    corr = run(older, newer, limits=small, sources=False)
    assert not found(corr, older, newer, 'P19')
    assert dict(corr.limits_hit)['assign-bucket-cap'] == 1
    assert found(run(older, newer, sources=False), older, newer, 'P19') == {}      # 3x3 all equal: tied, no margin


def test_assignment_buckets_exactly_at_l24_are_solved_and_a_wide_side_alone_abstains():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir, prefix in ((older, 'x'), (newer, 'y')):
        for i in range(3):
            ir.add(f'{prefix}{i}', seed=seed_of(prefix) + i, n_bb=6,
                   strings=(*(f'common-text-{k}' for k in range(8)), f'own-{prefix}{i}'))
    exact = dataclasses.replace(DEFAULT_LIMITS, l24_assign_bucket_cap=3)
    corr = run(older, newer, limits=exact, sources=False)
    assert corr.stat('lap-buckets') == 1 and 'assign-bucket-cap' not in dict(corr.limits_hit)
    wide_older, wide_newer = string_world(
        8, extra_newer=[(f'Y{i}', tuple(f'common-text-{k}' for k in range(8))) for i in (2, 3)])
    narrow = dataclasses.replace(DEFAULT_LIMITS, l24_assign_bucket_cap=2)              # 1 older row, 3 newer columns
    assert dict(run(wide_older, wide_newer, limits=narrow, sources=False).limits_hit)['assign-bucket-cap'] == 1


def assignment_outcome(similarity, older_lists, newer_lists):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        for i in range(3):
            ir.add(f'f{i}', seed=i)
    state = make_state(older, newer)
    blocked = Blocked(older_lists, newer_lists, len(similarity), 0, 0, {}, {})
    return _assign(state, blocked, similarity)


@pytest.mark.parametrize(('rival', 'accepted'), [(700, True), (701, False)], ids=['margin-0.05', 'margin-0.049'])
def test_the_assignment_margin_is_exact_for_the_older_function(rival, accepted):
    outcome = assignment_outcome({(0, 0): 750, (0, 1): rival}, {0: (0, 1)}, {0: (0,), 1: (0,)})
    assert outcome.accepted == ([(0, 0)] if accepted else []) and outcome.ambiguous == ([] if accepted else [(0, 0)])


@pytest.mark.parametrize(('rival', 'accepted'), [(700, True), (701, False)], ids=['margin-0.05', 'margin-0.049'])
def test_the_assignment_margin_is_exact_for_the_newer_function(rival, accepted):
    outcome = assignment_outcome({(0, 0): 750, (1, 0): rival}, {0: (0,), 1: (0,)}, {0: (0, 1)})
    assert outcome.accepted == ([(0, 0)] if accepted else []) and outcome.ambiguous == ([] if accepted else [(0, 0)])


def test_a_p19_opinion_is_soft_like_every_other_tier_c_result():
    """P19 says X-Y (rare strings), P17 says X-Z (blocks): the two weak, disagreeing opinions cancel."""
    older, newer = SyntheticIr(), SyntheticIr()
    common = tuple(f'common-text-{i}' for i in range(8))
    older.add('X', blocks=blocks(1, 2, 3), strings=(*common, 'old-only-0', 'old-only-1'))
    newer.add('Y', seed=77, n_insn=15, n_bb=3, strings=(*common, 'new-only-0', 'new-only-1'))   # no block of X or Z
    newer.add('Z', blocks=blocks(1, 2, 4))
    corr = run(older, newer, sources=False)
    assert not found(corr, older, newer) and corr.stat('soft-conflicts') == 2


def test_assignment_time_cap_abstains_and_is_recorded():
    older, newer = string_world(8)
    readings = iter(range(0, 10 ** 9, 10 ** 6))                           # every clock reading is 10^6 s later
    corr = run(older, newer, budget=Budget(clock=lambda: next(readings)), sources=False)
    assert not found(corr, older, newer, 'P19')
    assert dict(corr.limits_hit)['assign-time-cap'] == 1
    assert corr.status == 'complete'


def test_the_lap_clock_starts_after_blocking_not_before():
    """L-24 caps the LAP time (30 s), not the time spent reading instructions: a slow source must not trip it."""
    now = [0.0]

    class SlowSource(BodyMnemonics):
        def mnemonics(self, fid):
            now[0] += 100.0                                    # every function read costs 100 "seconds"
            return super().mnemonics(fid)

    older, newer = string_world(8, similar_bodies=True)
    only_p19 = [spec for spec in residual_passes(SlowSource(older), SlowSource(newer)) if spec.id == 'P19']
    corr = run_ladder(older, newer, passes=only_p19, budget=Budget(clock=lambda: now[0]))
    assert now[0] >= 200.0                                      # blocking really read both sides, slowly
    assert ('X', 'Y') in found(corr, older, newer, 'P19') and 'assign-time-cap' not in dict(corr.limits_hit)


def test_assignment_works_with_and_without_a_mnemonic_source():
    older, newer = string_world(8, similar_bodies=True)
    assert ('X', 'Y') in found(run(older, newer, sources=False), older, newer)
    assert ('X', 'Y') in found(run(older, newer, sources=True), older, newer)


def test_unrelated_bodies_lower_the_similarity_when_a_mnemonic_source_exists():
    """Equal strings but unrelated instruction streams: the unshared MinHash tokens pull the Jaccard under the floor."""
    older, newer = string_world(8)
    assert ('X', 'Y') in found(run(older, newer, sources=False), older, newer)
    assert ('X', 'Y') not in found(run(older, newer, sources=True), older, newer)


def test_assignment_uses_minhash_bands_as_tokens():
    older, newer = SyntheticIr(), SyntheticIr()
    body = make_body(5, 70)
    older.add('X', body=body, n_bb=6)
    newer.add('Y', body=edited(body, extra=1), n_bb=7)
    assert ('X', 'Y') in found(run(older, newer, sources=True), older, newer, 'P19')
    assert not found(run(older, newer, sources=False), older, newer)            # without bands there is nothing to go on


# ---- tier C competition and invariants ------------------------------------------------------------------------------------------------

def layout_and_blocks_world(y_block_seeds, z_block_seeds=None):
    """X sits between the anchors A1 and A2 (layout evidence for the newer function in the same slot, Y) and shares
    basic blocks with whichever newer function carries blocks 1 and 2 (block evidence)."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('A1', seed=1)
    older.add('X', blocks=blocks(1, 2, 3))
    older.add('A2', seed=3)
    newer.add('A1', seed=11)
    newer.add('Y', blocks=blocks(*y_block_seeds))
    newer.add('A2', seed=13)
    if z_block_seeds:
        newer.add('Z', blocks=blocks(*z_block_seeds))
    return older, newer


def test_two_residual_opinions_about_one_function_cancel_each_other():
    """P18 says X-Y (the slot), P17 says X-Z (the blocks): two weak, disagreeing opinions leave X unmatched."""
    older, newer = layout_and_blocks_world((7, 8, 9), z_block_seeds=(1, 2, 4))
    corr = run(older, newer, anchors=ANCHORS)
    assert not found(corr, older, newer)
    assert corr.stat('soft-conflicts') == 2
    assert 'candidate-conflict' in {h for item in corr.older_only + corr.newer_only for h in item.hints}


def test_two_residual_opinions_that_agree_become_one_pair():
    older, newer = layout_and_blocks_world((1, 2, 4))
    pair = found(run(older, newer, anchors=ANCHORS), older, newer)[('X', 'Y')]
    assert pair.pass_id == 'P17'                              # the first opinion keeps the provenance
    assert pair.anchors == ((older.fid('A1'), newer.fid('A1')), (older.fid('A2'), newer.fid('A2')))   # P18's merged in


def test_incidences_agree_with_a_brute_force_count_of_every_functions_references():
    for seed in range(8):
        older, newer = random_world(seed, 40)
        common = [s.tag for s in older.specs if any(t.tag == s.tag for t in newer.specs)]
        st = make_state(older, newer, [(tag, tag) for tag in common[::3]])
        for letter in ('a', 'b'):
            side = st.a if letter == 'a' else st.b
            brute = 0
            for fid in range(side.n):
                refs = references(st, letter, fid, hubs=True)
                brute += len(refs.pairs) + len(refs.imports) + len(refs.strings)
            assert incidences(st, letter) == brute


class Countdown:
    def __init__(self, limit):
        self.limit, self.polls = limit, 0

    def is_set(self):
        self.polls += 1
        return self.polls > self.limit


def test_a_spent_budget_inside_the_stage_never_leaves_half_a_pass():
    older, newer, anchors = reference_world(imports=('lib!f',))
    full = run(older, newer, anchors)
    assert ('X', 'X') in found(full, older, newer, 'P16')
    seen_partial = False
    for limit in range(0, 80):
        cut = run(older, newer, anchors, budget=Budget(cancel=Countdown(limit), check_every=1))
        if cut.status == 'complete':
            assert cut.digest() == full.digest()
            continue
        seen_partial = True
        # P16 either completed (and its pair is there) or was rolled back (and nothing of it is)
        assert ('P16' in cut.passes_completed) == (('X', 'X') in found(cut, older, newer, 'P16'))
    assert seen_partial
