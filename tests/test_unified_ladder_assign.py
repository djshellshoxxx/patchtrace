"""P19 assignment core (SPEC-31 04 s6.4): the pure-Python linear assignment solver and its reject columns.

Pure integer arithmetic, no ladder state: the solver is checked against brute force, for ties, for the reject
(dummy column) rule and for its callback contract. SYNTHETIC matrices only.
"""
from __future__ import annotations

import itertools
import random
import time

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.unified.ladder.assign import assign_with_rejection, solve

FAST = settings(max_examples=80, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def total(cost, columns):
    return sum(cost[row][col] for row, col in enumerate(columns))


def brute_force(cost):
    rows, cols = len(cost), len(cost[0])
    return min(sum(cost[r][c] for r, c in enumerate(pick)) for pick in itertools.permutations(range(cols), rows))


def test_solve_matches_brute_force_on_small_matrices():
    rng = random.Random(5)
    for _ in range(250):
        rows = rng.randint(1, 5)
        cols = rng.randint(rows, 6)
        cost = [[rng.randint(0, 9) for _ in range(cols)] for _ in range(rows)]
        picked = solve(cost)
        assert len(set(picked)) == rows and all(0 <= c < cols for c in picked)
        assert total(cost, picked) == brute_force(cost)


def test_solve_matches_brute_force_with_negative_costs():
    rng = random.Random(11)
    for _ in range(300):
        rows = rng.randint(1, 5)
        cols = rng.randint(rows, 6)
        cost = [[rng.randint(-9, 9) for _ in range(cols)] for _ in range(rows)]
        assert total(cost, solve(cost)) == brute_force(cost)


@FAST
@given(data=st.data())
def test_solve_is_optimal_for_any_integer_costs(data):
    rows = data.draw(st.integers(1, 5))
    cols = data.draw(st.integers(rows, 6))
    cost = [[data.draw(st.integers(-20, 20)) for _ in range(cols)] for _ in range(rows)]
    assert total(cost, solve(cost)) == brute_force(cost)


def test_solve_shapes():
    assert solve([]) == []
    assert solve([[4]]) == [0]
    assert solve([[5, 1, 9]]) == [1]
    assert solve([[1, 2], [2, 1]]) == [0, 1]
    with pytest.raises(ValueError):
        solve([[1], [2]])                       # more rows than columns has no assignment


def test_ties_resolve_to_the_lowest_columns_in_row_order():
    """Documented tie-break (determinism): all-equal costs give the identity assignment."""
    assert solve([[7] * 5 for _ in range(5)]) == [0, 1, 2, 3, 4]
    assert solve([[7] * 6 for _ in range(4)]) == [0, 1, 2, 3]


def test_solve_does_not_mutate_its_input():
    cost = [[3, 1, 2], [2, 3, 1]]
    snapshot = [row[:] for row in cost]
    solve(cost)
    assert cost == snapshot


def test_tick_counts_scanned_columns_and_exceptions_propagate():
    seen = []
    cost = [[(i * 7 + j * 3) % 11 for j in range(8)] for i in range(5)]
    solve(cost, tick=seen.append)
    assert seen and all(isinstance(n, int) and n > 0 for n in seen)

    class Stop(Exception):
        pass

    def boom(_units):
        raise Stop

    with pytest.raises(Stop):
        solve(cost, tick=boom)


# ---- reject columns (one dummy column per row, cost 1 - floor) ------------------------------------------------------------

def test_lap_reject_cost_leaves_function_unmatched():
    """A row whose best similarity is below the floor stays unassigned; the others are assigned."""
    sim = [[900, 100],
           [300, 590]]                                   # row 1: best 0.59 < floor 0.6
    assert assign_with_rejection(sim, floor=600) == [0, None]


def test_rejection_prefers_the_best_total_over_the_greedy_pick():
    sim = [[900, 850],
           [880, 100]]
    assert assign_with_rejection(sim, floor=600) == [1, 0]     # 850 + 880 beats 900 + reject


def test_a_pair_exactly_at_the_floor_is_assigned():
    assert assign_with_rejection([[600]], floor=600) == [0]
    assert assign_with_rejection([[599]], floor=600) == [None]


def test_more_rows_than_columns_is_fine_with_reject_columns():
    sim = [[900], [800], [700]]
    assert assign_with_rejection(sim, floor=600) == [0, None, None]


def test_empty_and_all_rejected():
    assert assign_with_rejection([], floor=600) == []
    assert assign_with_rejection([[0, 0], [0, 0]], floor=600) == [None, None]


@FAST
@given(data=st.data())
def test_rejection_never_assigns_a_column_twice_and_never_below_the_floor(data):
    rows = data.draw(st.integers(1, 6))
    cols = data.draw(st.integers(1, 6))
    floor = data.draw(st.integers(300, 900))
    sim = [[data.draw(st.integers(0, 1000)) for _ in range(cols)] for _ in range(rows)]
    result = assign_with_rejection(sim, floor=floor)
    used = [c for c in result if c is not None]
    assert len(used) == len(set(used))
    assert all(sim[r][c] >= floor for r, c in enumerate(result) if c is not None)
    # optimal: no assignment of the same shape (allowing rejects) has a larger sum of (similarity - floor)
    gain = sum(sim[r][c] - floor for r, c in enumerate(result) if c is not None)
    best = 0
    for pick in itertools.product(range(-1, cols), repeat=rows):
        taken = [c for c in pick if c >= 0]
        if len(taken) != len(set(taken)):
            continue
        best = max(best, sum(sim[r][c] - floor for r, c in enumerate(pick) if c >= 0 and sim[r][c] >= floor))
    assert gain == best


def test_k200_contended_matrix_is_quick():
    """O(k^3) worst case at the L-24 bucket cap: 200 rows that all prefer the same columns (a few seconds at most)."""
    rng = random.Random(3)
    k = 200
    sim = [[1000 - j // 2 - rng.randint(0, 3) for j in range(k)] for _ in range(k)]
    started = time.perf_counter()
    result = assign_with_rejection(sim, floor=600)
    elapsed = time.perf_counter() - started
    assert len({c for c in result if c is not None}) == len([c for c in result if c is not None])
    assert elapsed <= 30
