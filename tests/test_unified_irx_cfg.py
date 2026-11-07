"""irx audit: back-edge counting is linear-ish in the number of blocks and equals the dominator-chain definition."""
from __future__ import annotations

import time

from hypothesis import given
from hypothesis import strategies as st

from patchtrace.unified.ir.cfg import count_back_edges, dominators


def by_chain_walk(n, succ, entry):
    """The definition: v dominates u iff v lies on u's immediate-dominator chain."""
    idom = dominators(n, succ, entry)
    count = 0
    for u in range(n):
        if idom[u] == -1:
            continue
        for v in succ[u]:
            if idom[v] == -1:
                continue
            node = u
            while True:
                if node == v:
                    count += 1
                    break
                if idom[node] == node:
                    break
                node = idom[node]
    return count


@given(st.integers(1, 14).flatmap(lambda n: st.tuples(
    st.just(n), st.lists(st.lists(st.integers(0, n - 1), max_size=3), min_size=n, max_size=n), st.integers(0, n - 1))))
def test_back_edge_count_equals_the_chain_walk_definition(case):
    n, succ, entry = case
    assert count_back_edges(n, succ, entry) == by_chain_walk(n, succ, entry)


def test_a_long_straight_line_with_one_loop_is_not_quadratic():
    n = 60_000
    succ = [[i + 1] for i in range(n - 1)] + [[0]]
    started = time.monotonic()
    assert count_back_edges(n, succ, 0) == 1
    assert time.monotonic() - started < 5      # the chain walk needs ~40 s here
