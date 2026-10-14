"""Call-graph kernel: algorithms and differential oracle (WB2 G1)."""
from __future__ import annotations

import os
import random
import subprocess
import sys
import time
from pathlib import Path

import pytest

from patchtrace.callgraph import algo
from patchtrace.callgraph.csr import build_csr
from patchtrace.callgraph.limits import GraphError


def _random_graph(rng: random.Random, max_n: int = 14):
    n = rng.randint(1, max_n)
    edges = [(rng.randrange(n), rng.randrange(n)) for _ in range(rng.randint(0, 3 * n))]
    return n, edges


def test_reach_distances_depth_and_cap():
    g = build_csr(6, [(0, 1), (1, 2), (2, 3), (0, 4), (5, 0)])
    assert algo.reach(g, [0]).distances == {0: 0, 1: 1, 4: 1, 2: 2, 3: 3}
    assert algo.reach(g, [0], max_depth=1).distances == {0: 0, 1: 1, 4: 1}
    assert algo.reach(g, [3], 'in').distances == {3: 0, 2: 1, 1: 2, 0: 3, 5: 4}
    assert set(algo.reach(g, [1], 'both').distances) == {0, 1, 2, 3, 4, 5}
    capped = algo.reach(g, [0], cap=3)
    assert capped.truncated and len(capped.distances) == 3
    assert not algo.reach(g, [0], cap=5).truncated


def test_reach_multi_source_and_invalid_source():
    g = build_csr(5, [(0, 1), (3, 4)])
    assert algo.reach(g, [0, 3]).distances == {0: 0, 3: 0, 1: 1, 4: 1}
    with pytest.raises(GraphError) as exc:
        algo.reach(g, [9])
    assert exc.value.code == 'PT-GRAPH-INPUT'


def test_ancestors_descendants_exclude_self_even_in_cycle():
    g = build_csr(3, [(0, 1), (1, 0), (1, 2)])
    assert algo.descendants(g, 0) == [1, 2]
    assert algo.ancestors(g, 0) == [1]


def test_scc_cycle_and_singletons():
    g = build_csr(5, [(0, 1), (1, 2), (2, 0), (2, 3)])
    assert algo.strongly_connected_components(g) == [(0, 1, 2), (3,), (4,)]


def test_deep_chain_is_not_recursive():
    n = 50_000
    g = build_csr(n, [(i, i + 1) for i in range(n - 1)] + [(n - 1, 0)])
    assert algo.strongly_connected_components(g) == [tuple(range(n))]


def test_shortest_distance():
    g = build_csr(5, [(0, 1), (1, 2), (0, 3), (3, 2), (2, 4)])
    assert algo.shortest_distance(g, 0, 4) == 3
    assert algo.shortest_distance(g, 4, 0) == -1
    assert algo.shortest_distance(g, 2, 2) == 0


def test_simple_paths_shortest_first_and_bounded():
    # two length-2 routes, one length-3 route
    g = build_csr(5, [(0, 1), (1, 4), (0, 2), (2, 4), (0, 3), (3, 2)])
    result = algo.simple_paths(g, 0, 4)
    assert result.paths == ((0, 1, 4), (0, 2, 4), (0, 3, 2, 4))
    assert not result.truncated
    assert algo.simple_paths(g, 0, 4, max_paths=1).paths == ((0, 1, 4),)
    assert algo.simple_paths(g, 0, 4, max_length=2).paths == ((0, 1, 4), (0, 2, 4))
    assert algo.simple_paths(g, 4, 0).paths == ()
    assert algo.simple_paths(g, 2, 2).paths == ((2,),)


def test_simple_paths_never_repeat_nodes_in_cycles():
    g = build_csr(4, [(0, 1), (1, 0), (1, 2), (2, 1), (2, 3)])
    assert algo.simple_paths(g, 0, 3).paths == ((0, 1, 2, 3),)


def test_simple_paths_visit_budget_truncates():
    layers = 6
    edges = [(a * 3 + 1 + i, (a + 1) * 3 + 1 + j) for a in range(layers) for i in range(3) for j in range(3)]
    n = (layers + 1) * 3 + 2
    edges += [(0, 1 + i) for i in range(3)] + [(layers * 3 + 1 + i, n - 1) for i in range(3)]
    g = build_csr(n, edges)
    result = algo.simple_paths(g, 0, n - 1, max_paths=10_000, budget=200)
    assert result.truncated


def test_cancel_is_checked_and_raises():
    g = build_csr(20_000, [(i, i + 1) for i in range(19_999)])
    with pytest.raises(GraphError) as exc:
        algo.reach(g, [0], cancel=lambda: True)
    assert exc.value.code == 'PT-GRAPH-CANCEL'
    with pytest.raises(GraphError):
        algo.strongly_connected_components(g, cancel=lambda: True)


def _nx_graph(nx, n, edges):
    d = nx.DiGraph()
    d.add_nodes_from(range(n))
    d.add_edges_from(edges)
    return d


def test_differential_vs_networkx_400_trials():
    nx = pytest.importorskip('networkx')
    rng = random.Random(20261014)
    for _ in range(400):
        n, edges = _random_graph(rng)
        g, ref = build_csr(n, edges), _nx_graph(nx, n, edges)
        assert algo.strongly_connected_components(g) == sorted(
            (tuple(sorted(c)) for c in nx.strongly_connected_components(ref)), key=lambda c: c[0])
        src, dst = rng.randrange(n), rng.randrange(n)
        assert algo.ancestors(g, dst) == sorted(nx.ancestors(ref, dst))
        assert algo.descendants(g, src) == sorted(nx.descendants(ref, src))
        depth = rng.randint(0, 4)
        assert algo.reach(g, [src], max_depth=depth).distances == dict(
            nx.single_source_shortest_path_length(ref, src, cutoff=depth))
        multi = sorted({rng.randrange(n) for _ in range(3)})
        assert algo.reach(g, multi, 'in').distances == dict(
            nx.multi_source_dijkstra_path_length(ref.reverse(copy=False), multi))
        expected = nx.shortest_path_length(ref, src, dst) if nx.has_path(ref, src, dst) else -1
        assert algo.shortest_distance(g, src, dst) == expected
        got = algo.simple_paths(g, src, dst, max_paths=5, max_length=12)
        if expected < 0:
            assert got.paths == ()
            continue
        ref_lengths = []
        for path in nx.shortest_simple_paths(ref, src, dst):
            if len(path) - 1 > 12 or len(ref_lengths) == 5:
                break
            ref_lengths.append(len(path) - 1)
        assert [len(p) - 1 for p in got.paths] == ref_lengths
        assert len(set(got.paths)) == len(got.paths)
        for path in got.paths:
            assert path[0] == src and path[-1] == dst and len(set(path)) == len(path)
            assert all(g.has_edge(a, b) for a, b in zip(path, path[1:], strict=False))


_HASHSEED_SCRIPT = """
import random
from patchtrace.callgraph import algo
from patchtrace.callgraph.csr import build_csr
rng = random.Random(5)
n = 40
g = build_csr(n, [(rng.randrange(n), rng.randrange(n)) for _ in range(120)])
print(algo.strongly_connected_components(g))
print(list(algo.reach(g, [0]).distances.items()))
print(algo.simple_paths(g, 0, 39).paths, algo.ancestors(g, 7), list(g.edges()))
"""


def test_same_output_under_pythonhashseed_0_and_1():
    src = str(Path(__file__).resolve().parents[1] / 'src')
    outputs = []
    for seed in ('0', '1'):
        env = {**os.environ, 'PYTHONHASHSEED': seed, 'PYTHONPATH': src}
        run = subprocess.run([sys.executable, '-c', _HASHSEED_SCRIPT], env=env, capture_output=True,
                             text=True, check=True, timeout=60)
        outputs.append(run.stdout)
    assert outputs[0] == outputs[1] and outputs[0].strip()


def test_gate_60k_447k_algorithms_within_budget():
    n, m = 60_000, 447_000
    rng = random.Random(2)
    g = build_csr(n, [(rng.randrange(n), rng.randrange(n)) for _ in range(m)])
    start = time.perf_counter()
    components = algo.strongly_connected_components(g)
    anc = algo.ancestors(g, 0)
    dist = algo.shortest_distance(g, 0, n - 1)
    paths = algo.simple_paths(g, 0, n - 1)
    elapsed = time.perf_counter() - start
    assert sum(len(c) for c in components) == n
    assert anc and dist > 0 and paths.paths
    assert elapsed <= 20.0  # measured about 0.5 s for these steps; wide slack for shared CI
