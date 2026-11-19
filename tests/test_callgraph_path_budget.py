"""CG-1: count actual adjacency reads across the whole path query, without timing gates."""
from __future__ import annotations

import random
from dataclasses import replace

import pytest
from callgraph_cli_support import make_project, run
from callgraph_fixtures import build_fixture
from callgraph_graph_support import snapshot

from patchtrace.callgraph import algo
from patchtrace.callgraph.csr import CSRGraph, build_csr
from patchtrace.callgraph.limits import CANCEL_POP_INTERVAL, PATH_VISIT_BUDGET, GraphError
from patchtrace.callgraph.paths import find_paths
from patchtrace.callgraph.query import find_node


class Reads:
    def __init__(self, monkeypatch):
        self.examined = self.copied = 0
        for name in ('successors', 'predecessors', 'iter_successors', 'iter_predecessors'):
            if hasattr(CSRGraph, name):
                self._observe(monkeypatch, name)

    def _observe(self, monkeypatch, name):
        original = getattr(CSRGraph, name)

        def observed(graph, node):
            row = original(graph, node)
            if not name.startswith('iter_'):
                self.copied += len(row)

            def iterate():
                for value in row:
                    self.examined += 1
                    yield value
            return iterate()
        monkeypatch.setattr(CSRGraph, name, observed)


def _hub_raw(k=6, dead=800):
    names = ['src', *[f'A{i}' for i in range(k)], *[f'B{i}' for i in range(k)],
             'hub', *[f'dead{i}' for i in range(dead)], 'z', 'dst']
    calls = {name: [] for name in names}
    calls['src'] = [*[f'A{i}' for i in range(k)], 'z']
    for i in range(k):
        calls[f'A{i}'] = [f'B{j}' for j in range(k)]
        calls[f'B{i}'] = ['hub']
    calls['hub'] = ['src', *[f'dead{i}' for i in range(dead)]]
    calls['z'] = ['dst']
    raw = build_fixture('no_matches')
    raw['functions'] = {'added': [
        {'name': name, 'fullname': name, 'address': f'{0x1000 + i * 16:x}',
         'calling': [], 'called': calls[name]}
        for i, name in enumerate(names)], 'modified': [], 'deleted': []}
    raw['matches'] = {'name_matches': {}, 'address_matches': {}}
    return raw


def _hub_snapshot():
    return snapshot('no_matches', lambda raw: raw.update(_hub_raw()))


def _query(snap, source='src', target='dst', cancel=None):
    src, dst = (find_node(snap, 'newer', name).id for name in (source, target))
    return find_paths(snap, 'newer', src, dst, cancel)


def test_actual_normalized_hub_query_stops_at_shared_budget_and_retains_found_path(monkeypatch):
    snap = _hub_snapshot()
    assert (snap.newer.graph.n, snap.newer.graph.edge_count) == (816, 851)
    reads = Reads(monkeypatch)
    result = _query(snap)
    assert reads.examined <= PATH_VISIT_BUDGET
    assert reads.copied == 0
    assert result.truncated and 'work limit' in result.note
    assert [[result.labels[node] for node in path] for path in result.paths] == [['src', 'z', 'dst']]


@pytest.mark.parametrize('budget', [0, 1, 2, 3])
def test_budget_boundary_counts_shortest_reverse_and_enumeration(budget, monkeypatch):
    graph = build_csr(2, [(0, 1)])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 0, 1, max_length=1, budget=budget)
    assert reads.examined == min(budget, 3)
    assert reads.copied == 0
    assert result.paths == (((0, 1),) if budget >= 1 else ())
    assert result.truncated is (budget < 3)


def test_exhaustion_after_a_valid_path_retains_it(monkeypatch):
    graph = build_csr(2, [(0, 1)])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 0, 1, max_length=2, budget=3)
    assert reads.examined == 3
    assert result.paths == ((0, 1),) and result.truncated


def test_reverse_prepass_exhaustion_retains_the_completed_shortest_witness(monkeypatch):
    graph = build_csr(202, [(0, 1), *[(node, 1) for node in range(2, 202)]])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 0, 1, budget=40)
    assert reads.examined == 40 and reads.copied == 0
    assert result.truncated and result.paths == ((0, 1),)


def test_disallowed_neighbours_consume_budget_before_membership_filter(monkeypatch):
    graph = build_csr(102, [(0, node) for node in range(1, 102)])
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, 0, 101, budget=20, allowed=frozenset())
    assert reads.examined == 20 and reads.copied == 0
    assert result.truncated and result.paths == ()


def test_shortest_first_tie_order_and_five_path_limit_are_stable_under_edge_permutations():
    edges = [(0, 6), (1, 0), *[(0, node) for node in range(1, 6)],
             *[(node, 6) for node in range(1, 6)]]
    expected = ((0, 6), (0, 1, 6), (0, 2, 6), (0, 3, 6), (0, 4, 6))
    for permuted in (edges, list(reversed(edges)), edges[::2] + edges[1::2] + edges):
        result = algo.simple_paths(build_csr(7, permuted), 0, 6)
        assert result.paths == expected and not result.truncated


def _oracle(n, edges, src, dst):
    neighbours = {node: sorted({v for u, v in edges if u == node}) for node in range(n)}
    queue, found = [(src,)], []
    for path in queue:
        if path[-1] == dst:
            found.append(path)
            if len(found) == 5:
                break
        else:
            queue.extend((*path, node) for node in neighbours[path[-1]] if node not in path)
    return tuple(found)


def test_retained_witness_and_completed_paths_match_shortest_lexicographic_oracle():
    rng = random.Random(105)
    for _ in range(80):
        n = 7
        edges = [(u, v) for u in range(n) for v in range(n) if rng.random() < 0.3]
        src, dst = rng.randrange(n), rng.randrange(n)
        expected = _oracle(n, edges, src, dst)
        graph = build_csr(n, edges)
        for budget in (0, 1, 2, 4, 8, 16, 32, 64, 10_000):
            result = algo.simple_paths(graph, src, dst, budget=budget)
            assert result.paths == expected[:len(result.paths)]
            if not result.truncated:
                assert result.paths == expected


@pytest.mark.parametrize('reverse', [False, True])
def test_witness_orders_full_prefixes_and_forward_suffixes_not_frontier_node_ids(reverse, monkeypatch):
    # Forward frontier [5, 4] represents prefixes (0, 2, 5), (0, 3, 4). Sorting those
    # frontier IDs would select the wrong parent for 1. Reversing the graph exercises
    # suffix discovery in the opposite order: 1 must choose next hop 4, not first-seen 5.
    edges = [(0, 2), (0, 3), (2, 5), (3, 4), (5, 1), (4, 1), (1, 6), (6, 7),
             *[(node, 7) for node in range(8, 20)]]
    if reverse:
        edges = [(v, u) for u, v in edges]
    src, dst = (7, 0) if reverse else (0, 7)
    graph = build_csr(20, edges)
    reads = Reads(monkeypatch)
    result = algo.simple_paths(graph, src, dst, budget=20)
    assert result.paths == _oracle(20, edges, src, dst)[:1]
    assert result.truncated and reads.examined == 20 and reads.copied == 0


def test_cancel_at_start_reads_no_edges(monkeypatch):
    snap = _hub_snapshot()
    reads = Reads(monkeypatch)
    with pytest.raises(GraphError) as caught:
        _query(snap, cancel=lambda: True)
    assert caught.value.code == 'PT-GRAPH-CANCEL'
    assert reads.examined == reads.copied == 0


def test_cancel_during_rejected_successor_scans_is_not_delayed_by_queue_pop_count(monkeypatch):
    snap = _hub_snapshot()
    reads = Reads(monkeypatch)
    with pytest.raises(GraphError) as caught:
        _query(snap, cancel=lambda: reads.examined >= CANCEL_POP_INTERVAL)
    assert caught.value.code == 'PT-GRAPH-CANCEL'
    assert CANCEL_POP_INTERVAL <= reads.examined <= 2 * CANCEL_POP_INTERVAL
    assert reads.copied == 0


def test_existing_csr_is_used_without_a_global_edge_scan(monkeypatch):
    snap = _hub_snapshot()
    monkeypatch.setattr(CSRGraph, 'edges', lambda _self: pytest.fail('query rebuilt the complete graph'))
    assert _query(snap).paths


def test_listed_membership_and_unlisted_endpoints_are_preserved():
    def mutate(raw):
        raw['functions'] = {'added': [
            {'name': 'src', 'address': '1000', 'called': ['hidden'], 'calling': []},
            {'name': 'dst', 'address': '2000', 'called': [], 'calling': ['hidden']},
        ], 'modified': [], 'deleted': []}
        raw['matches'] = {'name_matches': {}, 'address_matches': {}}
    snap = snapshot('no_matches', mutate)
    assert not _query(snap).paths
    assert _query(snap, source='hidden').paths
    assert _query(snap, target='hidden').paths
    whole = _query(replace(snap, completeness='whole-program'))
    assert [[whole.labels[node] for node in path] for path in whole.paths] == [['src', 'hidden', 'dst']]


def test_actual_cli_reports_budget_exhaustion_as_partial_and_keeps_observed_path(tmp_path):
    root = make_project(tmp_path / 'project', _hub_raw())
    result = run('paths', str(root), '--from', 'src', '--to', 'dst', '--json')
    assert result.code == 3 and result.document['status'] == 'partial'
    observed = result.document['result']['results'][0]
    assert observed['truncated'] and 'work limit' in observed['note']
    assert [[observed['labels'][node] for node in path] for path in observed['paths']] == [['src', 'z', 'dst']]
