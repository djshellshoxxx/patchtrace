"""Propagation, hubs, thunks, implied-match votes and P15 (SPEC-31 04 s5, s5.1, s9). SYNTHETIC IR only."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import SyntheticIr, pairs_by_tag, tag_pairs  # noqa: E402

from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.ladder.passes import PASSES  # noqa: E402
from patchtrace.unified.ladder.propagate import _neighbour_set, dirty_anchors  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.ladder.state import State  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402

WEAK = {'h2': 3, 'h3': 4, 'hm': 5, 'hms': 6}      # shared weak keys: exact keys must differ to force a weak match


def leftovers(corr, ir, side='older'):
    items = corr.older_only if side == 'older' else corr.newer_only
    return {ir.tag_of(i.fid): i for i in items}


# ---- neighbour cascade -------------------------------------------------------------------------------------------------------

def test_neighbour_cascade_disambiguates_globally_ambiguous_duplicates():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('c1', seed=1, calls=('dup_a',))
        ir.add('c2', seed=2, calls=('dup_b',))
        ir.add('dup_a', seed=77)          # byte-identical twins: ambiguous for every global pass
        ir.add('dup_b', seed=77)
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert {('dup_a', 'dup_a'), ('dup_b', 'dup_b')} <= set(pairs)
    pair = pairs[('dup_a', 'dup_a')]
    assert pair.pass_id == 'P04' and pair.tier == 'A'
    assert [(older.tag_of(a), newer.tag_of(b)) for a, b in pair.anchors] == [('c1', 'c1')]
    assert pair.cls == 'E-CALL' and pair.family == 'F-PT-STRUCT'          # propagated: shares D_callgraph with Ghidriff
    atom = [a for a in corr.atoms() if a.older_rva == older.rva_of('dup_a')][0]
    assert atom.source == 'pt-ladder' and dict(atom.native)['anchor'].count('>') == 1
    assert not corr.groups


def test_callers_direction_is_used_too():
    """The anchor is a matched callee; its callers are disambiguated against an identical function elsewhere."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('lib', seed=900)
        ir.add('user', seed=77, calls=('lib',))
        ir.add('twin', seed=77)                      # byte-identical to `user`, calls nothing: ambiguous globally
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    user = pairs[('user', 'user')]
    assert (user.pass_id, user.tier) == ('P04', 'A')
    assert [older.tag_of(a) for a, _ in user.anchors] == ['lib']


def test_single_vote_pairs_call_site_twins_as_tier_c():
    """Two identical callees of one anchor are paired by call-site position, but only as a tier-C candidate."""
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('shared', seed=13, calls=('leaf1', 'leaf2'))
        ir.add('leaf1', seed=88)
        ir.add('leaf2', seed=88)
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert {(k, p.pass_id, p.tier, p.votes) for k, p in pairs.items() if k[0].startswith('leaf')} == {
        (('leaf1', 'leaf1'), 'PV', 'C', 1), (('leaf2', 'leaf2'), 'PV', 'C', 1)}


def test_dirty_anchor_requeued_when_a_sibling_gets_matched():
    """Wave 1 pairs x2 exactly; the anchor must be revisited so that x3 becomes unique among its neighbours."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('caller', seed=1, name='CallerName', calls=('x2', 'x3'))
    newer.add('caller', seed=1, name='CallerName', calls=('y2', 'y3'))
    older.add('x2', seed=20, keys={**WEAK, 'n_bb': 6, 'n_edge': 7})
    newer.add('y2', seed=20, keys={**WEAK, 'n_bb': 6, 'n_edge': 7})
    older.add('x3', seed=30, keys={**WEAK, 'h0': 301, 'h1': 302, 'n_bb': 8, 'n_edge': 9, 'md_td': 1, 'md_bu': 2})
    newer.add('y3', seed=31, keys={**WEAK, 'h0': 311, 'h1': 312, 'n_bb': 9, 'n_edge': 10, 'md_td': 3, 'md_bu': 4})
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert pairs[('caller', 'caller')].pass_id == 'P03'
    assert pairs[('x2', 'y2')].pass_id == 'P04'
    late = pairs[('x3', 'y3')]
    assert (late.pass_id, late.tier, late.chain) == ('P06', 'B', ('P07', 'P08', 'P09'))   # four agreeing weak keys
    assert [older.tag_of(a) for a, _ in late.anchors] == ['caller']
    # the same pair is NOT found when only one weak key agrees: C is soft and decided at the end
    older2, newer2 = SyntheticIr(), SyntheticIr()
    older2.add('caller', seed=1, name='CallerName', calls=('x3',))
    newer2.add('caller', seed=1, name='CallerName', calls=('y3',))
    older2.add('x3', seed=30, keys={'h2': 3, 'n_bb': 8, 'n_edge': 9})
    newer2.add('y3', seed=31, keys={'h2': 3, 'n_bb': 9, 'n_edge': 10})
    older2.add('decoy_o', seed=200, keys={'h2': 3})      # makes h2=3 ambiguous globally, unique only among neighbours
    newer2.add('decoy_n', seed=201, keys={'h2': 3})
    solo_c = run_ladder(older2, newer2)
    (only_pair,) = [p for p in solo_c.pairs if p.pass_id != 'P03']
    assert (only_pair.pass_id, only_pair.tier) == ('P06', 'C')


def test_dirty_anchors_helper_returns_only_matched_neighbour_pairs():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('a', seed=1, calls=('x',))
        ir.add('x', seed=2)
    st = State(SideData.from_ir(older), SideData.from_ir(newer), DEFAULT_LIMITS, Budget(), PASSES)
    st.accept(0, 0, pass_id='P04', step='s', tier='A', family='f', cls='c', rnd=1)
    assert dirty_anchors(st, 1, 1) == {(0, 0)}
    assert dirty_anchors(st, 0, 0) == set()


def test_propagation_hub_excluded():
    older, newer = SyntheticIr(), SyntheticIr()
    fan = DEFAULT_LIMITS.l17_hub_fan_in + 1
    for ir in (older, newer):
        ir.add('solo_caller', seed=1, calls=('h2',))
        for i in range(fan):
            ir.add(f'c{i}', seed=100 + i, calls=('h1',))       # h1 has a fan-in above L-17: a hub
        ir.add('h1', seed=77)
        ir.add('h2', seed=77)                                  # identical twin with a single caller
    corr = run_ladder(older, newer)
    pairs = tag_pairs(corr, older, newer)
    assert ('h2', 'h2') in pairs                               # found through its single caller
    assert ('h1', 'h1') not in pairs                           # the hub is never a neighbour candidate
    assert older.fid('h1') in corr.older_hubs and newer.fid('h1') in corr.newer_hubs
    assert 'h1' in leftovers(corr, older)


def test_neighbour_truncation_is_deterministic_and_recorded():
    older, newer = SyntheticIr(), SyntheticIr()
    count = DEFAULT_LIMITS.l18_neighbour_cap + 36
    for ir in (older, newer):
        ir.add('top', seed=1, calls=tuple(f'k{i:03d}' for i in range(count)))
        for i in range(count):
            ir.add(f'k{i:03d}', seed=500, n_insn=4)            # tiny identical callees: never matched, stay neighbours
    first, second = run_ladder(older, newer), run_ladder(older, newer)
    assert dict(first.limits_hit)['neighbour-cap'] == 2          # once per side
    assert first.digest() == second.digest()
    st = State(SideData.from_ir(older), SideData.from_ir(newer), DEFAULT_LIMITS, Budget(), PASSES)
    kept = _neighbour_set(st, 'a', older.fid('top'), 'callees')
    assert kept == sorted(older.fid(f'k{i:03d}') for i in range(count))[:DEFAULT_LIMITS.l18_neighbour_cap]


def test_local_conflict_drops_both_candidates():
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('a1', seed=1, calls=('x',))
    older.add('a2', seed=2, calls=('x',))
    older.add('x', seed=77)
    newer.add('a1', seed=1, calls=('y',))
    newer.add('a2', seed=2, calls=('z',))
    newer.add('y', seed=77)
    newer.add('z', seed=77)
    corr = run_ladder(older, newer)
    pairs = tag_pairs(corr, older, newer)
    assert pairs == {('a1', 'a1'), ('a2', 'a2')}               # x/y/z: contradictory local evidence -> no pair
    assert corr.stat('local-conflicts') >= 2
    assert [(older.tag_of(f) for f in g.older_fids) and g.kind for g in corr.groups] == ['duplicate']
    assert [newer.tag_of(f) for f in corr.groups[0].newer_fids] == ['y', 'z']


# ---- thunks --------------------------------------------------------------------------------------------------------------------

def test_two_thunks_of_one_target_are_ambiguous_and_stay_unmatched():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('target', seed=8)
        ir.add('j1', kind='thunk', thunk_target='target')
        ir.add('j2', kind='thunk', thunk_target='target')
    corr = run_ladder(older, newer)
    assert tag_pairs(corr, older, newer) == {('target', 'target')}
    assert {i.reason for i in corr.older_only} == {'thunk-unresolved'}


def test_thunk_pair_inherits_the_tier_of_its_target():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('lib', kind='external', import_key='k32!Open')
        ir.add('iat', kind='thunk', thunk_target='lib')
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert pairs[('lib', 'lib')].pass_id == 'P01'
    thunk = pairs[('iat', 'iat')]
    assert (thunk.pass_id, thunk.tier, thunk.step) == ('PT', 'A', 'PT-thunk-target')


# ---- implied matches ------------------------------------------------------------------------------------------------------------

def votes_only():
    """Only P04 (no propagation keys): isolates the call-site votes from every key-based neighbour match."""
    import dataclasses

    from patchtrace.unified.ladder.passes import PASS_BY_ID
    return [dataclasses.replace(PASS_BY_ID['P04'], neighbour=False)]


def _vote_world(older_calls, newer_calls, extra_older=(), extra_newer=()):
    """Anchors a<i>/b<i> (distinct bodies, matched exactly) calling unmatched, mutually different callees."""
    older, newer = SyntheticIr(), SyntheticIr()
    for i, (oc, nc) in enumerate(zip(older_calls, newer_calls, strict=True), start=1):
        older.add(f'a{i}', seed=i, calls=oc)
        newer.add(f'a{i}', seed=i, calls=nc)
    for tag, seed in extra_older:
        older.add(tag, seed=seed)
    for tag, seed in extra_newer:
        newer.add(tag, seed=seed)
    return older, newer


def test_implied_two_votes_zero_conflicts_tier_b():
    older, newer = _vote_world([('x',), ('x',)], [('y',), ('y',)], [('x', 501)], [('y', 502)])
    corr = run_ladder(older, newer, passes=votes_only())
    pair = pairs_by_tag(corr, older, newer)[('x', 'y')]
    assert (pair.pass_id, pair.step, pair.tier, pair.votes) == ('PV', 'PV-implied-match', 'B', 2)
    assert pair.cls == 'E-CALL' and len(pair.anchors) == 2
    assert dict(corr.atoms()[-1].native).get('votes') in {None, '2'}


def test_implied_one_vote_is_a_tier_c_candidate_decided_at_the_end():
    older, newer = _vote_world([('x',)], [('y',)], [('x', 501)], [('y', 502)])
    corr = run_ladder(older, newer, passes=votes_only())
    pair = pairs_by_tag(corr, older, newer)[('x', 'y')]
    assert (pair.pass_id, pair.tier, pair.votes) == ('PV', 'C', 1)


def test_implied_vote_threshold_follows_limit_l19():
    from patchtrace.unified.limits import UnifiedLimits
    older, newer = _vote_world([('x',), ('x',)], [('y',), ('y',)], [('x', 501)], [('y', 502)])
    two = pairs_by_tag(run_ladder(older, newer, passes=votes_only()), older, newer)[('x', 'y')]
    three = pairs_by_tag(run_ladder(older, newer, passes=votes_only(), limits=UnifiedLimits(l19_implied_min_votes=3)),
                         older, newer)[('x', 'y')]
    assert (two.tier, two.votes) == ('B', 2) and (three.tier, three.votes) == ('C', 2)     # still below the bar
    one_a, one_b = _vote_world([('x',)], [('y',)], [('x', 501)], [('y', 502)])
    lone = pairs_by_tag(run_ladder(one_a, one_b, passes=votes_only(), limits=UnifiedLimits(l19_implied_min_votes=1)),
                        one_a, one_b)[('x', 'y')]
    assert (lone.tier, lone.votes) == ('B', 1)


def test_implied_conflict_produces_no_pair():
    older, newer = _vote_world([('x',), ('x',)], [('y',), ('z',)], [('x', 501)], [('y', 502), ('z', 503)])
    corr = run_ladder(older, newer, passes=votes_only())
    assert not {p for p in tag_pairs(corr, older, newer) if p[0] == 'x'}
    assert 'implied-conflict' in leftovers(corr, older)['x'].hints
    assert 'implied-conflict' in leftovers(corr, newer, 'newer')['y'].hints


def test_implied_conflict_on_newer_endpoint_blocks_pair():
    older, newer = _vote_world([('x',), ('w',)], [('y',), ('y',)], [('x', 501), ('w', 502)], [('y', 503)])
    corr = run_ladder(older, newer, passes=votes_only())
    assert not {p for p in tag_pairs(corr, older, newer) if p[1] == 'y'}
    assert 'implied-conflict' in leftovers(corr, newer, 'newer')['y'].hints


def test_implied_decision_independent_of_anchor_order():
    digests = set()
    for order in (None, 1, 2, 3, 4):
        older, newer = _vote_world([('x', 'm'), ('x', 'm'), ('n',)], [('y', 'm2'), ('y', 'm2'), ('n2',)],
                                   [('x', 501), ('m', 504), ('n', 506)], [('y', 502), ('m2', 505), ('n2', 507)])
        older.row_order = newer.row_order = order
        digests.add(run_ladder(older, newer).digest())
    assert len(digests) == 1


def test_implied_gap_with_unequal_length_casts_no_vote():
    older, newer = _vote_world([('x', 'lib')], [('y', 'z', 'lib')], [('x', 501)], [('y', 502), ('z', 503)])
    for ir in (older, newer):
        ir.add('lib', seed=900)
        ir.specs.insert(0, ir.specs.pop())                 # keep insertion order irrelevant
    corr = run_ladder(older, newer, passes=votes_only())
    assert not {p for p in tag_pairs(corr, older, newer) if p[0] == 'x'}
    assert corr.stat('callsite-gap-skipped') >= 1


def test_implied_alignment_splits_on_unique_matched_callee():
    older, newer = _vote_world([('x1', 'lib', 'x2')], [('y1', 'lib', 'y2')],
                               [('x1', 501), ('x2', 502)], [('y1', 503), ('y2', 504)])
    for ir in (older, newer):
        ir.add('lib', seed=900)
    corr = run_ladder(older, newer, passes=votes_only())
    assert {('x1', 'y1'), ('x2', 'y2')} <= tag_pairs(corr, older, newer)


def test_implied_votes_ignore_hubs():
    """An unmatched hub callee is neutral at its call-site position: it casts no vote, the next position still does."""
    older, newer = SyntheticIr(), SyntheticIr()
    fan = DEFAULT_LIMITS.l17_hub_fan_in + 1
    for ir, offset in ((older, 0), (newer, 1)):
        ir.add('a1', seed=1, calls=('hub', 'other'))
        for i in range(fan):
            ir.add(f'c{i}', seed=100 + i, calls=('hub',))
        ir.add('hub', seed=501 + offset)
        ir.add('other', seed=601 + offset)
    corr = run_ladder(older, newer, passes=votes_only())
    tags = tag_pairs(corr, older, newer)
    assert ('other', 'other') in tags and ('hub', 'hub') not in tags
    assert pairs_by_tag(corr, older, newer)[('other', 'other')].pass_id == 'PV'


def test_weak_vote_never_blocks_a_later_exact_match():
    """A single vote at T0 must not stop the byte-identical successor from being paired at T1."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('caller', seed=1, name='CallerName', calls=('x',))
    newer.add('caller', seed=1, name='CallerName', calls=('wrong',))
    older.add('x', seed=40)
    newer.add('wrong', seed=41)             # the call site votes x -> wrong ...
    newer.add('x2', seed=40)                # ... but x has an exact, unique successor elsewhere
    corr = run_ladder(older, newer)
    assert tag_pairs(corr, older, newer) >= {('x', 'x2'), ('caller', 'caller')}
    assert ('x', 'wrong') not in tag_pairs(corr, older, newer)


# ---- P15 rehash-exact ---------------------------------------------------------------------------------------------------------

def _wrapper_world(callee_seeds=(11, 12), tweak=None):
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('w1', seed=5, calls=('f1', 'f2'))        # identical shapes, different callee ORDER
        ir.add('w2', seed=5, calls=('f2', 'f1'))
        ir.add('f1', seed=callee_seeds[0])
        ir.add('f2', seed=callee_seeds[1])
    if tweak:
        tweak(older, newer)
    return older, newer


def test_rehash_exact_matches_function_with_moved_callee():
    older, newer = _wrapper_world()
    newer.specs[2].rva = 0x9000                              # f1 moved: the call targets shift, the shapes stay equal
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert {('w1', 'w1'), ('w2', 'w2')} <= set(pairs)
    for key in (('w1', 'w1'), ('w2', 'w2')):
        assert (pairs[key].pass_id, pairs[key].tier) == ('P15', 'A')       # both substituted pairs are tier A
    assert pairs[('w1', 'w1')].step == 'P15-rehash-exact'


def test_rehash_tier_is_b_when_a_substituted_pair_is_not_exact():
    def tweak(older, newer):
        for ir, base in ((older, 0), (newer, 100)):
            ir.specs[2].keys = {'h0': base + 1, 'h1': base + 2, 'h2': 9, 'h3': 9, 'hm': 9, 'hms': 9, 'n_bb': 6,
                                'n_edge': 7, 'md_td': 5, 'md_bu': 6}        # f1 can only match by a B-tier pass
    older, newer = _wrapper_world(tweak=tweak)
    corr = run_ladder(older, newer)
    pairs = pairs_by_tag(corr, older, newer)
    assert pairs[('f1', 'f1')].tier == 'B'
    assert (pairs[('w1', 'w1')].pass_id, pairs[('w1', 'w1')].tier) == ('P15', 'B')


def test_rehash_skips_functions_with_unmatched_callees():
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('w1', seed=5, calls=('f1', 'u1'))
        ir.add('w2', seed=5, calls=('f1', 'u2'))
        ir.add('f1', seed=11)
        ir.add('u1', seed=21 if ir is older else 31)             # callees that never match anything
        ir.add('u2', seed=22 if ir is older else 32)
    corr = run_ladder(older, newer)
    assert not any(p.pass_id == 'P15' for p in corr.pairs)


def test_external_callee_counts_as_its_import_in_sets_and_votes():
    """A call to an external function carries the import key: P13 sees it, and two different imports at aligned
    call sites never get an implied match between the (unmatched) externals."""
    older, newer = SyntheticIr(), SyntheticIr()
    older.add('open_a', kind='external', import_key='k32!OpenA')
    older.add('caller', seed=1, calls=('open_a', 'imp:k32!Close'))
    newer.add('open_b', kind='external', import_key='k32!OpenB')            # a different import at the same position
    newer.add('caller', seed=1, calls=('open_b', 'imp:k32!Close'))
    corr = run_ladder(older, newer, passes=votes_only())
    assert ('open_a', 'open_b') not in tag_pairs(corr, older, newer)
    a = SideData.from_ir(older)
    assert a.sites[older.fid('caller')][0][1] == 'k32!OpenA'               # the site names the import
    two_a, two_b = SyntheticIr(), SyntheticIr()
    two_a.add('lib', kind='external', import_key='k32!A')
    two_a.add('f', seed=1, calls=('lib', 'imp:k32!B'))
    two_b.add('lib2', kind='external', import_key='k32!A')
    two_b.add('f', seed=2, calls=('imp:k32!B', 'lib2'))                      # same SET of imports, other order
    corr2 = run_ladder(two_a, two_b, passes=solo_p13())
    assert ('f', 'f') in tag_pairs(corr2, two_a, two_b)


def solo_p13():
    import dataclasses

    from patchtrace.unified.ladder.passes import PASS_BY_ID
    return [dataclasses.replace(PASS_BY_ID['P13'], neighbour=False, stage=0)]
