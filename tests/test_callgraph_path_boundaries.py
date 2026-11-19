"""Independent finite path oracle and cancellation/length boundaries."""
from __future__ import annotations

from itertools import permutations

import pytest
from test_callgraph_path_budget import Reads

from patchtrace.callgraph import algo
from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.limits import CANCEL_POP_INTERVAL, GraphError


def _paths_by_permutation(edges, source=0, target=3):
    """Enumerate simple paths independently of the production BFS/DFS strategy."""
    found = []
    for length in range(3):
        for middle in permutations((1, 2), length):
            path = (source, *middle, target)
            if all(edge in edges for edge in zip(path, path[1:], strict=False)):
                found.append(path)
    return tuple(sorted(found, key=lambda path: (len(path), path)))


def test_every_four_node_directed_graph_returns_only_the_canonical_path_prefix():
    possible = [(u, v) for u in range(4) for v in range(4) if u != v]
    for mask in range(1 << len(possible)):
        edges = {edge for bit, edge in enumerate(possible) if mask & (1 << bit)}
        expected = _paths_by_permutation(edges)
        graph = build_csr(4, edges)
        for budget in (0, 1, 3, 7, 100):
            result = algo.simple_paths(graph, 0, 3, budget=budget)
            assert result.paths == expected[:len(result.paths)], (mask, budget, result, expected)
            if not result.truncated:
                assert result.paths == expected, (mask, budget, result, expected)


def test_identity_path_with_zero_budget_reads_no_adjacencies(monkeypatch):
    graph = build_csr(3, [(0, 1), (1, 2), (2, 0)])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 1, 1, budget=0)
    assert result.paths == ((1,),) and not result.truncated
    assert reads.examined == reads.copied == 0


def test_already_cancelled_identity_path_does_not_publish_a_completed_result(monkeypatch):
    graph = build_csr(3, [(0, 1), (1, 2), (2, 0)])
    reads = Reads(monkeypatch)
    with pytest.raises(GraphError) as caught:
        algo.simple_paths(graph, 1, 1, budget=0, cancel=lambda: True)
    assert caught.value.code == 'PT-GRAPH-CANCEL'
    assert reads.examined == reads.copied == 0


@pytest.mark.parametrize('budget', [3, 4, 5, 100])
def test_retained_witness_never_exceeds_the_requested_length(budget, monkeypatch):
    graph = build_csr(9, [(0, 1), (1, 2), (2, 3), (3, 4), *[(node, 4) for node in range(5, 9)]])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 0, 4, max_length=2, budget=budget)
    assert result.paths == ()
    assert reads.examined <= budget and reads.copied == 0
    if budget == 100:
        assert not result.truncated


def test_cancel_during_disallowed_membership_scans_is_charged_and_bounded(monkeypatch):
    count = 3 * CANCEL_POP_INTERVAL
    graph = build_csr(count + 2, [(0, node) for node in range(1, count + 2)])
    reads = Reads(monkeypatch)
    with pytest.raises(GraphError) as caught:
        algo.simple_paths(graph, 0, count + 1, allowed=frozenset(),
                          cancel=lambda: reads.examined >= CANCEL_POP_INTERVAL)
    assert caught.value.code == 'PT-GRAPH-CANCEL'
    assert CANCEL_POP_INTERVAL <= reads.examined <= 2 * CANCEL_POP_INTERVAL
    assert reads.copied == 0
