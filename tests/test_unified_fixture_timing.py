"""UNVERIFIED: fixture budgets not measured. Timing is bounded and never executes target bytes."""
from __future__ import annotations

from unified_support.pairs import corpus
from unified_support.timing import measure


def clock(values: tuple[float, ...]):
    iterator = iter(values)
    return lambda: next(iterator)


def test_inclusive_budget_and_early_failure_use_no_fixed_sleep() -> None:
    assert measure("boundary", lambda: None, repetitions=1, budget_seconds=1.0,
                   clock=clock((1.0, 2.0))).passed
    calls = []
    bad = measure("overrun", lambda: calls.append(1), repetitions=3, budget_seconds=1.0,
                  clock=clock((1.0, 2.1)))
    assert bad.passed is False and len(calls) == 1 and len(bad.seconds) == 1


def test_generate_twenty_small_images_within_fixture_budget() -> None:
    # Ten kinds times one case, two images each. This is not a matching-speed benchmark.
    result = measure("fixture-corpus", lambda: corpus(1), repetitions=1, budget_seconds=5.0)
    assert result.passed, result
