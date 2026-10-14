"""BinDiff-style MD index of a directed graph (flow graph of one function, or the call graph).

Portions derived from google/bindiff v8 (https://github.com/google/bindiff, tag v8, commit
aecc14dcc2e0f06a0f8957dc465a9073215b5920; files graph_util.h, flow_graph.cc, call_graph.cc), licensed under the
Apache License, Version 2.0, Copyright 2011-2023 Google LLC. This file re-expresses those algorithms in Python for
PatchTrace (MIT) and is MODIFIED from the originals (language, data structures, parity switch below). The licence
text and the provenance record ship as third_party/notices/bindiff-v8-aecc14d/ (docs/specs/unified-engine/09).
"BinDiff" is a trademark of Google LLC; PatchTrace's unified engine is not BinDiff and never claims to be.

Definition (graph_util.h `CalculateMdIndexInternal`): for an edge (s, t)
    md(s, t) = 1 / (sqrt(2)*in(s) + sqrt(3)*out(s) + sqrt(5)*in(t) + sqrt(7)*out(t) + sqrt(11)*lvl(s) + sqrt(13)*lvl(t))
with `in`/`out` the degrees (multi-edges and self loops counted) and `lvl` the breadth-first level from the vertices
without in-edges (top-down) or, over reversed edges, from the vertices without out-edges (bottom-up). The graph MD is
the sum of the edge values; the C++ code sorts the summands ascending and accumulates left to right in IEEE double
arithmetic (`std::sort` + `std::accumulate`), so this module does the same with a PLAIN loop: Python 3.12's `sum()`
of floats is compensated and would differ (SPEC-31 D-16, C-16). `math.sqrt` is correctly rounded on every IEEE-754
platform, so results are bit-identical across operating systems.

Parity quirks kept behind `bindiff_quirks=True` (the default):
  * level 0 doubles as "unvisited" (a vertex whose level is 0 is never queued twice, roots included);
  * a graph without a vertex of in-degree 0 (for example an entry block that is a loop target) keeps every
    top-down level at 0 (and symmetrically for bottom-up);
  * duplicate edges and self loops count in the degrees and in the sum exactly as BinDiff counts them.
With `bindiff_quirks=False` vertices keep a separate visited flag and a graph without roots is traversed from
vertex 0, which gives levels for every reachable vertex (not used for the IR keys).
"""
from __future__ import annotations

import math
from collections import deque
from collections.abc import Sequence

_W = tuple(math.sqrt(w) for w in (2.0, 3.0, 5.0, 7.0, 11.0, 13.0))
KEY_SCALE = 10 ** 12
Edge = tuple[int, int]


def _degrees(n: int, edges: Sequence[Edge]) -> tuple[list[int], list[int], list[list[int]], list[list[int]]]:
    indeg, outdeg = [0] * n, [0] * n
    out_adj: list[list[int]] = [[] for _ in range(n)]
    in_adj: list[list[int]] = [[] for _ in range(n)]
    for s, t in edges:
        outdeg[s] += 1
        indeg[t] += 1
        out_adj[s].append(t)
        in_adj[t].append(s)
    return indeg, outdeg, out_adj, in_adj


def bfs_levels(n: int, adjacency: list[list[int]], roots: Sequence[int], *, quirks: bool = True) -> list[int]:
    """Breadth-first levels from `roots` along `adjacency` (BreadthFirstSearch / InvertedBreadthFirstSearch)."""
    level = [0] * n
    queue = deque(roots)
    seen = [False] * n
    for root in roots:
        seen[root] = True
    if not quirks and not queue and n:
        queue.append(0)
        seen[0] = True
    while queue:
        vertex = queue.popleft()
        for target in adjacency[vertex]:
            if (level[target] if quirks else seen[target]):
                continue
            seen[target] = True
            queue.append(target)
            level[target] = level[vertex] + 1
    return level


def edge_values(n: int, edges: Sequence[Edge], *, bottom_up: bool = False, quirks: bool = True) -> list[float]:
    """MD value of every edge, in edge order (call-graph vertex MDs sum these)."""
    indeg, outdeg, out_adj, in_adj = _degrees(n, edges)
    if bottom_up:
        level = bfs_levels(n, in_adj, [v for v in range(n) if outdeg[v] == 0], quirks=quirks)
    else:
        level = bfs_levels(n, out_adj, [v for v in range(n) if indeg[v] == 0], quirks=quirks)
    w0, w1, w2, w3, w4, w5 = _W
    return [1.0 / (w0 * indeg[s] + w1 * outdeg[s] + w2 * indeg[t] + w3 * outdeg[t] + w4 * level[s] + w5 * level[t])
            for s, t in edges]


def _sum_sorted(values: list[float]) -> float:
    values = sorted(values)
    total = 0.0
    for value in values:  # plain left-to-right accumulation, mirroring std::accumulate (NOT sum(): compensated)
        total += value
    return total


def md_index(n: int, edges: Sequence[Edge], *, bottom_up: bool = False, quirks: bool = True) -> float:
    """Graph MD index: the sum of the edge values (0.0 for a graph without edges, BinDiff's "trivial")."""
    if not edges:
        return 0.0
    return _sum_sorted(edge_values(n, edges, bottom_up=bottom_up, quirks=quirks))


def md_key(value: float) -> int:
    """Stable integer key of an MD value: `round(md * 10**12)` (D-16); 12 decimals as `bindiff --md_index` prints."""
    return round(value * KEY_SCALE)


def flow_graph_md(n: int, edges: Sequence[Edge], *, quirks: bool = True) -> tuple[float, float]:
    """(top-down, bottom-up) MD index of a function's flow graph (FlowGraph::Init)."""
    return md_index(n, edges, quirks=quirks), md_index(n, edges, bottom_up=True, quirks=quirks)


def call_graph_vertex_md(n: int, edges: Sequence[Edge], *, bottom_up: bool = False, quirks: bool = True) -> list[float]:
    """MD of every call-graph vertex: the sum of the stored MD of its in- and out-edges (CallGraph::GetMdIndex);
    a self loop is incident twice, as in the Boost graph. Summands are sorted before the plain accumulation."""
    values = edge_values(n, edges, bottom_up=bottom_up, quirks=quirks)
    incident: list[list[float]] = [[] for _ in range(n)]
    for (s, t), value in zip(edges, values, strict=True):
        incident[t].append(value)   # in-edges first, then out-edges (order is irrelevant after the sort)
        incident[s].append(value)
    return [_sum_sorted(item) for item in incident]
