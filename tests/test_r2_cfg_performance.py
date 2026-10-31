"""R2 loop-count semantics and query-work guard, independent of wall-clock speed."""
from __future__ import annotations

import random

import pytest

from patchtrace.unified.ir import cfg


def _reachable(succ, entry, removed=-1):
    if not 0 <= entry < len(succ) or entry == removed:
        return set()
    reached = {entry}
    pending = [entry]
    while pending:
        for target in succ[pending.pop()]:
            if target != removed and target not in reached:
                reached.add(target)
                pending.append(target)
    return reached


def _oracle(succ, entry):
    """Definition: v dominates reachable u iff removing v makes u unreachable."""
    live = _reachable(succ, entry)
    without = {v: _reachable(succ, entry, v) for v in live}
    return sum(u not in without[v] for u in live for v in succ[u] if v in live)


@pytest.mark.parametrize('seed', range(60))
def test_loop_count_agrees_with_vertex_removal_oracle(seed):
    rng = random.Random(seed)
    n = rng.randrange(1, 35)
    density = rng.choice((0.02, 0.12, 0.5))
    succ = [[v for v in range(n) if rng.random() < density] for _u in range(n)]
    if seed % 3 == 0:
        for u in range(n - 1):
            succ[u].append(u + 1)
    if seed % 4 == 0:
        for row in succ:
            row.extend(row[:2])  # repeated edges count separately
    for entry in (-1, 0, n // 2, n - 1, n):
        assert cfg.count_back_edges(n, succ, entry) == _oracle(succ, entry)


def test_self_loops_duplicate_edges_and_unreachable_nodes():
    succ = [[1, 1], [1, 2], [1, 1], [3]]
    assert cfg.count_back_edges(4, succ, 0) == 3
    assert cfg.count_back_edges(4, succ, 3) == 1
    assert cfg.count_back_edges(0, []) == 0


def test_forward_chain_loop_queries_use_linear_idom_accesses(monkeypatch):
    n = 512
    succ = [[u + 1] if u + 1 < n else [] for u in range(n)]

    class CountedParents(list):
        accesses = 0

        def __getitem__(self, index):
            self.accesses += 1
            return super().__getitem__(index)

    parents = CountedParents([0, *range(n - 1)])
    monkeypatch.setattr(cfg, 'dominators', lambda *_args: parents)
    assert cfg.count_back_edges(n, succ) == 0
    assert parents.accesses <= 12 * (n + n - 1)
