"""LBL-10 evalcore statistics: hand-computed goldens, synergy-1 numbers, invariants."""
from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tools.calibration.evalcore import boot, power, rank


def _rank_of(flagged: list[str], target: str) -> float | None:
    """Rank of `target` in an already-ordered list (strictly increasing keys, no ties)."""
    return rank.rank_map({name: i for i, name in enumerate(flagged)}).get(target)


# ---- midranks ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('keys, expected', [
    ([10, 20, 30], [1, 2, 3]),
    ([1, 2, 2, 3], [1, 2.5, 2.5, 4]),
    ([5, 5, 5], [2, 2, 2]),
    ([3, 1, 3, 1], [3.5, 1.5, 3.5, 1.5]),
    ([], []),
], ids=['distinct', 'pair-tie', 'all-tied', 'two-ties-unsorted', 'empty'])
def test_midranks_golden(keys, expected):
    assert rank.midranks(keys) == expected


def test_midrank_hit_boundary():
    r = rank.midranks([1, 2, 2, 3])[1]
    assert (rank.hit_at_k(r, 2), rank.hit_at_k(r, 3)) == (0, 1)


# ---- rank metrics -----------------------------------------------------------------------------------------

def test_hit_rr_none_is_zero():
    assert (rank.hit_at_k(None, 20), rank.reciprocal_rank(None)) == (0, 0.0)
    assert rank.ndcg_at_k([(None, 2)]) == 0.0


@pytest.mark.parametrize('r, k, expected', [(1, 1, 1), (2, 1, 0), (3, 3, 1), (3.5, 3, 0), (10, 10, 1), (11, 10, 0)],
                         ids=['r1k1', 'r2k1', 'r3k3', 'r3.5k3', 'r10k10', 'r11k10'])
def test_hit_at_k_golden(r, k, expected):
    assert rank.hit_at_k(r, k) == expected


def test_ndcg_two_relevant_golden():
    # DCG = 3/log2(2) + 1/log2(4) = 3.5 ; ideal = 3 + 1/log2(3)
    got = rank.ndcg_at_k([(1, 2), (3, 1)])
    assert got == pytest.approx(3.5 / (3 + 1 / math.log2(3)), abs=1e-12)


def test_ndcg_cutoff_and_unfound_ideal():
    # second relevant item unflagged: ideal still counts it
    got = rank.ndcg_at_k([(1, 2), (None, 1)])
    assert got == pytest.approx(3 / (3 + 1 / math.log2(3)), abs=1e-12)
    assert rank.ndcg_at_k([(11, 2)], k=10) == 0.0


def test_ndcg_no_relevant_is_undefined():
    assert rank.ndcg_at_k([]) is None


def test_summarise_golden():
    s = rank.summarise([1, 4, None, 2.5], pool_sizes=[5, 7, 3, 9])
    assert s['pairs'] == 4 and s['found_in_pool'] == 3
    assert s['pool_median'] == 6
    assert s['hit_at'][1] == 0.25 and s['hit_at'][3] == 0.5 and s['hit_at'][5] == 0.75
    assert s['mrr'] == pytest.approx((1 + 0.25 + 0 + 0.4) / 4)
    assert s['mean_rank'] == pytest.approx((1 + 4 + 2.5) / 3)
    assert s['tie_rule'] == 'midrank'


# ---- synergy-1 (plan s5) ----------------------------------------------------------------------------------

# flagged lists most suspicious first; Ghidriff / rz-diff keys are the fixed native similarities
SYNERGY = {
    'ghidriff': ({'f09': 0.71, 'f05': 0.74, 'f11': 0.80, 'f07': 0.86, 'f03': 0.93}, 4, 0, 0, 0.25, 0.4307),
    'rz-diff': ({'f05': 0.62, 'f11': 0.66, 'f07': 0.69, 'f09': 0.75, 'f03': 0.97, 'f01': 0.99}, 3, 0, 1, 1 / 3, 0.5),
    'unified': ({'f10': 0, 'f07': 1, 'f02': 2}, 2, 0, 1, 0.5, 0.6309),
    'capa': ({'f02': 0, 'f07': 1}, 2, 0, 1, 0.5, 0.6309),
    'combined': ({'f07': 0, 'f10': 1, 'f02': 2}, 1, 1, 1, 1.0, 1.0),
}


@pytest.mark.parametrize('source', list(SYNERGY), ids=list(SYNERGY))
def test_synergy_ranks_are_hand_computed(source):
    flagged, r, h1, h3, rr, ndcg = SYNERGY[source]
    got = rank.pair_metrics(rank.rank_map(flagged)['f07'])
    assert got['rank'] == r
    assert (got['hit@1'], got['hit@3']) == (h1, h3)
    assert got['rr'] == pytest.approx(rr, abs=1e-12)
    assert round(got['ndcg'], 4) == ndcg


def test_combined_beats_each_channel_alone():
    ndcgs = {s: rank.pair_metrics(rank.rank_map(v[0])['f07'])['ndcg'] for s, v in SYNERGY.items()}
    assert all(ndcgs['combined'] > v for s, v in ndcgs.items() if s != 'combined')


def test_synergy_one_lineage_is_anti_conservative():
    obs = {'p1': ('L1', 1.0)}
    iv = boot.lineage_bootstrap(obs, 200)
    assert iv.anti_conservative and iv.point == 1.0 and (iv.lo, iv.hi) == (1.0, 1.0)
    assert boot.non_inferior(iv, -0.02) is None and not boot.headline_ok(1)


# ---- bootstrap --------------------------------------------------------------------------------------------

def _obs(n_lineages: int, per: int = 2, f=lambda g, j: float((g + j) % 2)) -> dict:
    return {f'p{g}-{j}': (f'L{g:02d}', f(g, j)) for g in range(n_lineages) for j in range(per)}


@pytest.mark.parametrize('n, flag', [(29, True), (30, False), (37, False)], ids=['29', '30', '37'])
def test_anti_conservative_threshold(n, flag):
    iv = boot.lineage_bootstrap(_obs(n), 50)
    assert iv.anti_conservative is flag
    assert power.anti_conservative(n) is flag and boot.headline_ok(n) is (not flag)


def test_bootstrap_deterministic_and_seed_sensitive():
    o = _obs(12, f=lambda g, j: float(g % 3 == 0))
    assert boot.lineage_bootstrap(o, 300, 's') == boot.lineage_bootstrap(o, 300, 's')
    seen: dict[str, list] = {'s': [], 't': []}
    for name in seen:
        boot.lineage_bootstrap(o, 50, name, reducer=lambda v, n=name: seen[n].append(sum(v)) or boot.mean_reducer(v))
    assert seen['s'] != seen['t']


def test_bootstrap_constant_values_collapse():
    iv = boot.lineage_bootstrap(_obs(8, f=lambda g, j: 0.5), 100)
    assert (iv.point, iv.lo, iv.hi, iv.undefined) == (0.5, 0.5, 0.5, 0)


def test_bootstrap_interval_brackets_point_and_is_ordered():
    iv = boot.lineage_bootstrap(_obs(40, f=lambda g, j: float(g % 3 == 0)), 500)
    assert iv.lo <= iv.point <= iv.hi and iv.lo < iv.hi


def test_paired_delta_constant_shift_has_zero_width():
    a = _obs(10, f=lambda g, j: 0.7)
    b = _obs(10, f=lambda g, j: 0.5)
    iv = boot.paired_delta_bootstrap(a, b, 100)
    assert iv.point == pytest.approx(0.2) and iv.lo == pytest.approx(0.2) and iv.hi == pytest.approx(0.2)


def test_paired_delta_identical_arms_is_zero_and_antisymmetric():
    o = _obs(10)
    z = boot.paired_delta_bootstrap(o, o, 100)
    assert (z.point, z.lo, z.hi) == (0.0, 0.0, 0.0)
    a = _obs(10, f=lambda g, j: float(g % 2))
    b = _obs(10, f=lambda g, j: float(g % 3 == 0))
    ab, ba = boot.paired_delta_bootstrap(a, b, 300), boot.paired_delta_bootstrap(b, a, 300)
    assert ab.point == pytest.approx(-ba.point)
    assert ab.lo == pytest.approx(-ba.hi) and ab.hi == pytest.approx(-ba.lo)


def test_paired_delta_reuses_draws_so_beats_independent_intervals():
    # arm B = arm A + small constant: the paired delta CI is tight while each arm's own CI is wide
    a = _obs(20, f=lambda g, j: float(g % 2))
    b = {k: (g, v + 0.05) for k, (g, v) in a.items()}
    d = boot.paired_delta_bootstrap(b, a, 400)
    own = boot.lineage_bootstrap(a, 400)
    assert d.hi - d.lo < (own.hi - own.lo) / 100


def test_paired_delta_rejects_mismatched_arms():
    a = _obs(3)
    with pytest.raises(ValueError):
        boot.paired_delta_bootstrap(a, {k: v for k, v in list(a.items())[:-1]}, 10)
    with pytest.raises(ValueError):
        boot.paired_delta_bootstrap(a, {k: ('Lx', v) for k, (_, v) in a.items()}, 10)


@pytest.mark.parametrize('lo, margin, anti, expected', [
    (-0.01, -0.02, False, True), (-0.03, -0.02, False, False), (-0.02, -0.02, False, False),
    (0.5, -0.02, True, None), (None, -0.02, False, None)], ids=['above', 'below', 'equal', 'anti', 'undefined'])
def test_non_inferior(lo, margin, anti, expected):
    assert boot.non_inferior(boot.Interval(0.0, lo, 1.0, 0, anti), margin) is expected


# ---- power ------------------------------------------------------------------------------------------------

def test_power_goldens():
    z = 1.959963984540054 + 0.8416212335729143
    assert power.min_detectable_delta(36, 0.3) == pytest.approx(z * 0.3 / 6, rel=1e-12)
    assert power.lineages_needed(0.1, 0.3) == math.ceil((z * 3) ** 2) == 71
    assert power.power_for_delta(0.0, 36, 0.3) == pytest.approx(0.025, abs=1e-12)  # = alpha/2 upper tail
    assert power.power_for_delta(power.min_detectable_delta(50, 0.2), 50, 0.2) == pytest.approx(0.8, abs=1e-6)


def test_noninferiority_lineages_and_sd():
    z1 = 1.6448536269514722 + 0.8416212335729143
    assert power.noninferiority_lineages(-0.02, 0.0, 0.1) == math.ceil((z1 * 0.1 / 0.02) ** 2)
    assert power.lineage_sd([1.0]) is None
    assert power.lineage_sd([0.0, 2.0]) == pytest.approx(math.sqrt(2))
    with pytest.raises(ValueError):
        power.lineages_needed(0, 1)


# ---- hypothesis invariants --------------------------------------------------------------------------------

@given(st.lists(st.tuples(st.text(min_size=1, max_size=3), st.integers(0, 5)), min_size=1, max_size=15,
                unique_by=lambda t: t[0]), st.randoms(use_true_random=False))
def test_tie_permutation_invariance(entries, rnd):
    shuffled = list(entries)
    rnd.shuffle(shuffled)
    assert rank.rank_map(dict(entries)) == rank.rank_map(dict(shuffled))


@given(st.lists(st.integers(0, 6), min_size=1, max_size=20))
def test_midranks_sum_is_triangular(keys):
    n = len(keys)
    assert math.fsum(rank.midranks(keys)) == pytest.approx(n * (n + 1) / 2)


@given(st.floats(1, 40), st.floats(0, 40), st.integers(1, 20))
def test_metrics_monotone_in_rank(r1, extra, k):
    r2 = r1 + extra  # r2 is worse (larger)
    assert rank.hit_at_k(r1, k) >= rank.hit_at_k(r2, k)
    assert rank.reciprocal_rank(r1) >= rank.reciprocal_rank(r2)
    assert rank.ndcg_at_k([(r1, 2)]) >= rank.ndcg_at_k([(r2, 2)]) - 1e-15


@given(st.lists(st.sampled_from([None, 1.0, 2.0, 3.5, 12.0]), min_size=1, max_size=12), st.integers(0, 11))
def test_summary_monotone_in_hits(ranks, i):
    i %= len(ranks)
    better = list(ranks)
    better[i] = 1.0
    a, b = rank.summarise(ranks), rank.summarise(better)
    assert all(b['hit_at'][k] >= a['hit_at'][k] for k in rank.HIT_KS)
    assert b['mrr'] >= a['mrr']


@given(st.integers(2, 8), st.integers(0, 10**6))
def test_bootstrap_determinism_property(n, seed):
    o = _obs(n)
    assert boot.lineage_bootstrap(o, 20, seed) == boot.lineage_bootstrap(o, 20, seed)
