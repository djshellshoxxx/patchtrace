"""G-U5 performance of the L1 ladder at 10k and 60k synthetic functions (SPEC-31 04 s9, 08 s1/s6, L-35).

Gate (08 s6): L-35 with 5x wall-clock slack on CI plus exact operation-count gates. The workload is the generator of
tests/unified_ir_builder.py: power-law call graph, 35 % address-shifted, 3 % edited, 0.5 % duplicates, 1 % added,
1 % removed functions, 20 % named. SYNTHETIC: it measures the algorithm's cost, not Ghidra or real binaries; the
precision/recall numbers printed here are properties of the generator, not accuracy claims.
Wall-clock numbers of the local run are recorded in docs/qa.md; Windows numbers come from the Windows CI runner.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import generate_pair  # noqa: E402

from patchtrace.unified.ladder.engine import run_ladder_data  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402

SLACK = 5            # 08 s6: CI wall-clock slack


def run_scale(n: int):
    pair = generate_pair(n, seed=1)
    t0 = time.perf_counter()
    older, newer = SideData.from_ir(pair.older), SideData.from_ir(pair.newer)
    t1 = time.perf_counter()
    budget = Budget()
    corr = run_ladder_data(older, newer, budget=budget)
    t2 = time.perf_counter()
    got = {corr.older_rva[p.older_fid]: corr.newer_rva[p.newer_fid] for p in corr.pairs}
    right = sum(1 for k, v in got.items() if pair.truth.get(k) == v)
    wrong = sum(1 for k, v in got.items() if k in pair.truth and pair.truth[k] != v)
    spurious = sum(1 for k in got if k not in pair.truth)
    print(f'G-U5 n={n}: sides {t1 - t0:.2f}s ladder {t2 - t1:.2f}s ticks={budget.used} pairs={len(corr.pairs)} '
          f'right={right}/{len(pair.truth)} wrong={wrong} spurious={spurious} '
          f'passes={ {k[9:]: v for k, v in corr.stats if k.startswith("accepted:")} }')
    return corr, pair, t1 - t0, t2 - t1, budget.used, (right, wrong, spurious)


@pytest.fixture(scope='module')
def scale_10k():
    return run_scale(10_000)


@pytest.fixture(scope='module')
def scale_60k():
    return run_scale(60_000)


def test_ladder_10k_under_budget(scale_10k):
    corr, pair, t_sides, t_ladder, ticks, (right, wrong, spurious) = scale_10k
    assert corr.status == 'complete' and set(dict(corr.limits_hit)) <= {'neighbour-cap'}
    assert t_ladder <= DEFAULT_LIMITS.l35_ladder_10k_s * SLACK
    assert t_sides + t_ladder <= DEFAULT_LIMITS.l35_ladder_10k_s * SLACK
    assert wrong == 0 and spurious == 0 and right >= 0.99 * len(pair.truth)


def test_ladder_60k_synthetic_under_budget(scale_60k):
    corr, pair, t_sides, t_ladder, ticks, (right, wrong, spurious) = scale_60k
    assert corr.status == 'complete'
    assert t_ladder <= DEFAULT_LIMITS.l35_ladder_60k_s * SLACK
    assert t_sides + t_ladder <= DEFAULT_LIMITS.l35_ladder_60k_s * SLACK
    assert wrong == 0 and spurious == 0 and right >= 0.99 * len(pair.truth)


def test_ladder_work_is_linear_not_quadratic(scale_10k, scale_60k):
    """Exact operation-count gate: budget ticks per function are bounded and do not grow with n (C6 method)."""
    ticks_10k, ticks_60k = scale_10k[4], scale_60k[4]
    assert ticks_10k <= 12 * 10_000 and ticks_60k <= 12 * 60_000
    assert ticks_60k / ticks_10k < 7.0          # 6x the functions -> about 6x the work, never 36x


def test_ladder_pair_evaluations_never_form_a_full_matrix(scale_60k):
    corr, pair, *_ = scale_60k
    n_pairs = len(corr.pairs)
    assert dict(corr.stats)['waves'] <= 64                    # propagation converges in few waves
    assert n_pairs < 60_000 * 1.1                             # 1:1 pairs, never n x m candidates
