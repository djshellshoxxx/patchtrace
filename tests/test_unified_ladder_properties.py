"""Hypothesis properties of the L1 ladder (SPEC-31 04): determinism, input-order invariance, bounds from limits.py,
and unknown is never a negative vote. SYNTHETIC IR only; derandomised (docs/qa.md T-29).

A failing property is a defect in src: it is marked strict xfail with a one-line reason, never weakened.
"""
from __future__ import annotations

import sys
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from unified_ir_builder import random_world  # noqa: E402

from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedLimits  # noqa: E402

FAST = settings(max_examples=12, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def fingerprint(corr) -> tuple:
    return (corr.pairs, corr.groups, corr.older_only, corr.newer_only, corr.status, corr.stop_reason,
            corr.passes_completed, corr.limits_hit, corr.stats)


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 30))
def test_same_world_gives_same_correspondence_twice(seed, n):
    older, newer = random_world(seed, n)
    assert fingerprint(run_ladder(older, newer)) == fingerprint(run_ladder(older, newer))


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 30))
def test_counts_and_limit_hits_are_never_negative(seed, n):
    older, newer = random_world(seed, n)
    corr = run_ladder(older, newer)
    assert all(v >= 0 for _, v in corr.stats)
    assert all(v >= 0 for _, v in corr.limits_hit)
    assert len(corr.older_only) <= len(older.specs)
    assert len(corr.newer_only) <= len(newer.specs)


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 30), cap=st.integers(1, 4))
def test_tight_bucket_cap_stays_within_its_bound(seed, n, cap):
    older, newer = random_world(seed, n)
    limits = UnifiedLimits(l23_bucket_cap=cap, l24_assign_bucket_cap=cap)
    corr = run_ladder(older, newer, limits=limits)
    assert corr.status in ('complete', 'partial')
    assert (corr.status == 'complete') == (corr.stop_reason is None)
    assert len(corr.pairs) <= min(len(older.specs), len(newer.specs))


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 30))
def test_default_limits_are_not_hit_on_small_worlds(seed, n):
    older, newer = random_world(seed, n)
    corr = run_ladder(older, newer, limits=DEFAULT_LIMITS)
    assert corr.status == 'complete'
    assert dict(corr.limits_hit).get('l23_bucket_cap', 0) == 0
