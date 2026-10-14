"""SPEC-31 S1: BinDiff-style MD index (ir/mdindex.py) and loop counting (ir/cfg.py).

The MD vectors below were produced by an independent C++ transcription of the arithmetic of google/bindiff v8
`graph_util.h` (std::sort + std::accumulate, no Boost), and a 3,000-graph random comparison with the Python port was
bit-identical (docs/qa.md). They are NOT outputs of the real `bindiff --md_index` (blocked: no pinned BinDiff)."""
from __future__ import annotations

import random

import pytest

from patchtrace.unified.ir import mdindex as md
from patchtrace.unified.ir.cfg import count_back_edges, dominators

DIAMOND = (4, [(0, 1), (0, 2), (1, 3), (2, 3)])
VECTORS = {
    # name: (graph, top-down, bottom-up, call-graph vertex MDs top-down)
    'diamond': (DIAMOND, '0x1.1c389fbaa49c7p-2', '0x1.297c7384bd582p-2',
                ['0x1.56b8230fe4a1dp-3', '0x1.1c389fbaa49c7p-3', '0x1.1c389fbaa49c7p-3', '0x1.c37238cac92e1p-4']),
    'chain3': ((3, [(0, 1), (1, 2)]), '0x1.492056e110feep-3', '0x1.64f44be89a475p-3',
               ['0x1.90ce335f33e9ep-4', '0x1.492056e110feep-3', '0x1.01727a62ee13fp-4']),
    'loop_entry': ((2, [(0, 1), (1, 0)]), '0x1.fe357ca76af6p-3', '0x1.fe357ca76af6p-3',
                   ['0x1.fe357ca76af6p-3', '0x1.fe357ca76af6p-3']),
    'self_loop_dup': ((3, [(0, 1), (0, 1), (1, 1), (1, 2)]), '0x1.87c0332764dcap-3', '0x1.86ba1e2f43f3ap-3',
                      ['0x1.ad96f5317ac5bp-4', '0x1.d4a91659a6dbep-3', '0x1.902f557195e9cp-5']),
    'while': ((4, [(0, 1), (1, 2), (2, 1), (1, 3)]), '0x1.a9ede0d39f19bp-3', '0x1.c1f715493402ep-3',
              ['0x1.0f3c6a02e1332p-4', '0x1.a9ede0d39f19bp-3', '0x1.6dae3fe1c7af4p-4', '0x1.ade22f852aa1fp-5']),
}


def test_md_index_diamond_vector():
    n, edges = DIAMOND
    assert md.md_index(n, edges) == 0.277559753195558          # R02 s6 hand computation, review M9
    assert md.md_key(md.md_index(n, edges)) == 277559753196


@pytest.mark.parametrize('name', sorted(VECTORS))
def test_md_index_matches_the_independent_transcription_bit_for_bit(name):
    (n, edges), top, bottom, vertex = VECTORS[name]
    assert md.flow_graph_md(n, edges) == (float.fromhex(top), float.fromhex(bottom))
    assert md.call_graph_vertex_md(n, edges) == [float.fromhex(x) for x in vertex]


def test_md_index_plain_loop_not_compensated_sum():
    # Python >= 3.12 `sum()` of floats is compensated; the C++ accumulate is a plain left-to-right loop (D-16)
    rnd = random.Random(7)
    graphs = 0
    for _ in range(300):
        n = rnd.randrange(8, 40)
        edges = [(rnd.randrange(n), rnd.randrange(n)) for _ in range(3 * n)]
        values = sorted(md.edge_values(n, edges))
        plain = 0.0
        for value in values:
            plain += value
        assert md.md_index(n, edges) == plain
        graphs += sum(values) != plain
    assert graphs > 0, 'no planted case where sum() and the plain loop differ: the test would not catch a regression'


def test_md_of_a_graph_without_edges_is_zero_and_trivial():
    assert md.md_index(3, []) == 0.0 and md.flow_graph_md(1, []) == (0.0, 0.0)


def test_entry_that_is_a_loop_target_keeps_all_top_down_levels_at_zero():
    # BinDiff quirk: no vertex of in-degree 0 -> no BFS root -> every level stays 0 (parity mode)
    assert md.bfs_levels(2, [[1], [0]], []) == [0, 0]
    assert md.bfs_levels(2, [[1], [0]], [], quirks=False) == [0, 1]
    assert md.md_index(2, [(0, 1), (1, 0)]) != md.md_index(2, [(0, 1), (1, 0)], quirks=False)


def test_levels_are_breadth_first_depths():
    adjacency = [[1, 2], [3], [3], []]
    assert md.bfs_levels(4, adjacency, [0]) == [0, 1, 1, 2]


def test_summation_order_is_independent_of_edge_order():
    n, edges = 6, [(0, 1), (0, 2), (0, 3), (0, 4), (1, 5), (2, 5), (3, 5), (4, 5)]   # switch-style fan out / in
    shuffled = list(edges)
    random.Random(3).shuffle(shuffled)
    assert md.flow_graph_md(n, edges) == md.flow_graph_md(n, shuffled)
    assert md.md_index(n, edges) == float.fromhex('0x1.becc442367096p-2')       # independent C++ transcription


# --- loops ----------------------------------------------------------------------------------------------------------

def test_back_edges_are_edges_to_a_dominator():
    # 0 -> 1 -> 2 -> 1 (loop), 1 -> 3; the cross edge 0 -> 3 is not a back edge
    succ = [[1, 3], [2, 3], [1], []]
    assert count_back_edges(4, succ) == 1
    assert count_back_edges(1, [[0]]) == 1                      # self loop
    assert count_back_edges(3, [[1], [2], []]) == 0
    # irreducible: 0 -> 1, 0 -> 2, 1 <-> 2: neither 1 nor 2 dominates the other, so no back edge
    assert count_back_edges(3, [[1, 2], [2], [1]]) == 0


def test_dominators_ignore_unreachable_blocks():
    idom = dominators(4, [[1], [2], [], [1]])
    assert idom[0] == 0 and idom[1] == 0 and idom[2] == 1 and idom[3] == -1
    assert count_back_edges(4, [[1], [2], [], [1]]) == 0


def test_an_unreachable_block_with_an_edge_into_the_graph_is_never_a_back_edge():
    # block 1 is unreachable and jumps to the entry; walking its (missing) dominator chain must not wrap around
    # to the last block's chain and report a loop
    assert count_back_edges(3, [[2], [0], []]) == 0
    assert count_back_edges(4, [[2], [0, 3], [3], []]) == 0
    assert count_back_edges(4, [[2], [0, 3], [3], [2]]) == 1        # 3 -> 2 is a real back edge only where 2 dominates 3

