"""Call-graph kernel: CSR digraph (WB2 G1)."""
from __future__ import annotations

import random
import time

import pytest

from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.limits import GraphError


def test_neighbours_sorted_and_deduplicated_with_self_loop():
    g = build_csr(4, [(0, 3), (0, 1), (0, 3), (2, 2), (1, 0)])
    assert list(g.successors(0)) == [1, 3]
    assert list(g.predecessors(0)) == [1]
    assert list(g.successors(2)) == [2] and list(g.predecessors(2)) == [2]
    assert g.edge_count == 4
    assert (g.out_degree(0), g.in_degree(3), g.in_degree(1)) == (2, 1, 1)
    assert list(g.edges()) == [(0, 1), (0, 3), (1, 0), (2, 2)]


def test_has_edge():
    g = build_csr(5, [(0, 1), (0, 4), (3, 3)])
    assert g.has_edge(0, 4) and g.has_edge(3, 3)
    assert not g.has_edge(0, 2) and not g.has_edge(4, 0) and not g.has_edge(1, 0)


def test_empty_and_isolated():
    assert build_csr(0, []).edge_count == 0
    g = build_csr(3, [])
    assert list(g.successors(1)) == [] and g.n == 3


def test_insertion_order_does_not_matter():
    rng = random.Random(7)
    edges = [(rng.randrange(30), rng.randrange(30)) for _ in range(120)]
    shuffled = edges[:]
    rng.shuffle(shuffled)
    assert list(build_csr(30, edges).edges()) == list(build_csr(30, shuffled).edges())


@pytest.mark.parametrize('bad', [(0, 3), (-1, 0), (3, 0)], ids=['dst-high', 'src-negative', 'src-high'])
def test_out_of_range_edge_is_input_error(bad):
    with pytest.raises(GraphError) as exc:
        build_csr(3, [bad])
    assert exc.value.code == 'PT-GRAPH-INPUT'


def test_negative_node_count_is_input_error():
    with pytest.raises(GraphError):
        build_csr(-1, [])


def test_gate_60k_nodes_447k_edges_builds_within_budget():
    n, m = 60_000, 447_000
    rng = random.Random(1)
    edges = [(rng.randrange(n), rng.randrange(n)) for _ in range(m)]
    start = time.perf_counter()
    g = build_csr(n, edges)
    elapsed = time.perf_counter() - start
    assert g.n == n and 440_000 <= g.edge_count <= m
    assert elapsed <= 5.0  # measured 0.22-0.35 s; 5x slack for shared CI
