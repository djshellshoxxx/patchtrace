"""G-U5 for the residual stage at 10k and 60k synthetic functions, plus the all-residual worst case (SPEC-31 08 s1, s6;
L-35; 04 s9 `test_blocking_never_builds_full_matrix`). SYNTHETIC IR only.

Gates: L-35 with 5x wall-clock slack on CI, exact operation-count gates (the candidate pairs of a pass are at most
L-22 x the unmatched functions, never the n x m matrix), and the precision of the pairs the stage adds, per tier and
pass, against the generator's ground truth. The precision figures are properties of the generator (35 % address
shifts, half of the functions edited, a layout that mostly survives), NOT accuracy claims. Wall-clock numbers of the
local run are recorded in docs/qa.md; Windows numbers come from the Windows CI runner.
"""
from __future__ import annotations

import dataclasses
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unified_ir_builder import generate_pair  # noqa: E402
from unified_residual_support import DenseMnemonics, GeneratedMnemonics, dense_world  # noqa: E402

from patchtrace.unified.ladder.blocking import eligible  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder_data  # noqa: E402
from patchtrace.unified.ladder.residual import RESIDUAL_IDS, pass_table, residual_passes  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.ladder.types import Correspondence  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402

SLACK = 5                                     # 08 s6: CI wall-clock slack
SETTINGS = {'changed': 0.5, 'shifted': 0.2, 'duplicates': 0.01}        # half of the functions edited
BUDGET_S = {10_000: DEFAULT_LIMITS.l35_ladder_10k_s, 60_000: DEFAULT_LIMITS.l35_ladder_60k_s}
K = DEFAULT_LIMITS.l22_candidates_per_function


@dataclass
class Run:
    n: int
    corr: Correspondence
    seconds: float
    ticks: int
    log: dict = field(default_factory=dict)         # per residual pass: seconds, and the pool sizes at P16 / P19
    precision: dict = field(default_factory=dict)   # (group, tier) -> (pairs, right)


def instrumented(table, log):
    """The same table with each residual pass timed and its candidate pools recorded from inside the stage."""
    def wrap(spec):
        run = spec.run

        def timed(st, rnd):
            if spec.id in ('P16', 'P19'):
                log[f'pool:{spec.id}'] = (len(eligible(st, 'a')), len(eligible(st, 'b')))
            started = time.perf_counter()
            run(st, rnd)
            log[f'seconds:{spec.id}'] = time.perf_counter() - started
        return dataclasses.replace(spec, run=timed)
    return tuple(wrap(spec) if spec.id in RESIDUAL_IDS else spec for spec in table)


def precision_table(corr, is_right):
    table: dict[tuple[str, str], list[int]] = {}
    for pair in corr.pairs:
        group = pair.pass_id if pair.pass_id in RESIDUAL_IDS else 'S2'
        row = table.setdefault((group, pair.tier), [0, 0])
        row[0] += 1
        row[1] += is_right(corr.older_rva[pair.older_fid], corr.newer_rva[pair.newer_fid])
    return {key: tuple(value) for key, value in sorted(table.items())}


def report(title, run):
    stage = sum(v for k, v in run.log.items() if k.startswith('seconds:'))
    stats = dict(run.corr.stats)
    print(f'{title}: ladder {run.seconds:.2f}s (residual stage {stage:.2f}s: '
          f'{ {k[8:]: round(v, 2) for k, v in run.log.items() if k.startswith("seconds:")} }) ticks={run.ticks} '
          f'pairs={len(run.corr.pairs)} pools={ {k[5:]: v for k, v in run.log.items() if k.startswith("pool:")} } '
          f'limits_hit={dict(run.corr.limits_hit)}')
    print('   counters', {k: v for k, v in stats.items() if k.startswith(('blocked', 'blocking', 'evaluated', 'ambiguous',
                                                                       'lap', 'no-mn'))})
    for (group, tier), (count, right) in run.precision.items():
        print(f'   {group:>3} tier {tier}: {count:6d} pairs, {right:6d} right, precision {right / count:.4f}')


def run_generated(n):
    world = generate_pair(n, seed=1, **SETTINGS)
    older, newer = SideData.from_ir(world.older), SideData.from_ir(world.newer)
    log: dict = {}
    table = instrumented(pass_table(older=GeneratedMnemonics(world, 'older'), newer=GeneratedMnemonics(world, 'newer')), log)
    budget = Budget()
    started = time.perf_counter()
    corr = run_ladder_data(older, newer, budget=budget, passes=table)
    seconds = time.perf_counter() - started
    run = Run(n, corr, seconds, budget.used, log, precision_table(corr, lambda old, new: world.truth.get(old) == new))
    report(f'G-U5 residual n={n}', run)
    return run


@pytest.fixture(scope='module', params=[10_000, 60_000], ids=['10k', '60k'])
def generated(request):
    return run_generated(request.param)


def test_residual_ladder_under_budget(generated):
    assert generated.corr.status == 'complete'
    assert set(dict(generated.corr.limits_hit)) <= {'neighbour-cap'}
    assert generated.seconds <= BUDGET_S[generated.n] * SLACK
    stage = sum(v for k, v in generated.log.items() if k.startswith('seconds:'))
    assert 0 < stage <= BUDGET_S[generated.n]            # the stage alone never takes the whole L-35 budget


def test_blocking_never_builds_full_matrix_at_scale(generated):
    """Counter on pair evaluations <= K x n (04 s9), measured against the pools the stage really saw."""
    stats = dict(generated.corr.stats)
    for pass_id in ('P16', 'P19'):
        pool_a, pool_b = generated.log[f'pool:{pass_id}']
        blocked, evaluated = stats[f'blocked-pairs:{pass_id}'], stats[f'evaluated:{pass_id}']
        assert 0 < evaluated <= blocked <= K * (pool_a + pool_b)
        assert blocked * 20 < pool_a * pool_b            # a tiny fraction of the n x m matrix
    assert generated.ticks <= 14 * generated.n           # budget ticks stay linear in the image size


def test_residual_pairs_are_right_and_tier_c_precision_is_reported(generated):
    rows = {key: value for key, value in generated.precision.items() if key[0] in RESIDUAL_IDS}
    assert rows
    for (group, tier), (count, right) in rows.items():
        if tier in 'AB':
            assert right == count, (group, tier)                       # tier B of the stage: no wrong pair
    pairs = sum(count for count, _ in rows.values())
    right = sum(right for _, right in rows.values())
    assert pairs > 0 and right >= 0.95 * pairs, (pairs, right)           # regression floor on THIS generator, not a claim


# ---- the all-residual worst case ---------------------------------------------------------------------------------------------------

def run_dense(n):
    world = dense_world(n)
    older, newer = SideData.from_ir(world.older), SideData.from_ir(world.newer)
    log: dict = {}
    table = instrumented(residual_passes(DenseMnemonics(world, 'older'), DenseMnemonics(world, 'newer')), log)
    budget = Budget()
    started = time.perf_counter()
    corr = run_ladder_data(older, newer, budget=budget, passes=table)
    seconds = time.perf_counter() - started
    right = sum(1 for pair in corr.pairs if world.identity_older[corr.older_rva[pair.older_fid]]
                == world.identity_newer[corr.newer_rva[pair.newer_fid]])
    run = Run(n, corr, seconds, budget.used, log, {('dense', 'B'): (len(corr.pairs), right)})
    report(f'G-U5 all-residual n={n}', run)
    return run


@pytest.fixture(scope='module')
def dense():
    return run_dense(60_000)


def test_every_function_residual_and_every_bucket_oversized_still_fits_the_budget(dense):
    """60k functions per side, none matchable by content, each calling 3 of 10 common imports: token buckets of
    thousands. The cap splits or abstains (recorded), the work stays linear and the twins are still found."""
    stats = dict(dense.corr.stats)
    assert dense.corr.status == 'complete'
    assert dense.seconds <= BUDGET_S[60_000] * SLACK
    assert sum(v for k, v in dense.log.items() if k.startswith('seconds:')) <= BUDGET_S[60_000]
    assert dict(dense.corr.limits_hit).get('block-cap', 0) > 0              # the abstention path is exercised at scale
    assert 'assign-time-cap' not in dict(dense.corr.limits_hit)
    pool_a, pool_b = dense.log['pool:P16']
    assert (pool_a, pool_b) == (dense.n, dense.n)                           # nothing matched before the stage
    assert 0 < stats['evaluated:P16'] <= stats['blocked-pairs:P16'] <= K * (pool_a + pool_b)
    assert stats['blocking-work:P16'] < 200 * (pool_a + pool_b)             # bucket members enumerated: linear in n
    assert dense.precision[('dense', 'B')] == (dense.n, dense.n)            # every twin, and only twins
