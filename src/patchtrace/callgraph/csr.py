"""Immutable directed graph in compressed-sparse-row form (forward and reverse), stdlib only."""
from __future__ import annotations

from array import array
from collections.abc import Iterable, Iterator

from .limits import GraphError


class CSRGraph:
    """Nodes are 0..n-1. Parallel edges collapse; self-loops are kept. Neighbours are sorted
    ascending, so every traversal is deterministic regardless of insertion order or hash seed."""

    __slots__ = ('n', 'edge_count', '_out_off', '_out_adj', '_in_off', '_in_adj')

    def __init__(self, n: int, out_off: array, out_adj: array, in_off: array, in_adj: array) -> None:
        self.n = n
        self.edge_count = len(out_adj)
        self._out_off, self._out_adj = out_off, out_adj
        self._in_off, self._in_adj = in_off, in_adj

    def successors(self, node: int) -> array:
        return self._out_adj[self._out_off[node]:self._out_off[node + 1]]

    def predecessors(self, node: int) -> array:
        return self._in_adj[self._in_off[node]:self._in_off[node + 1]]

    def out_degree(self, node: int) -> int:
        return self._out_off[node + 1] - self._out_off[node]

    def in_degree(self, node: int) -> int:
        return self._in_off[node + 1] - self._in_off[node]

    def has_edge(self, src: int, dst: int) -> bool:
        lo, hi = self._out_off[src], self._out_off[src + 1]
        end = hi
        while lo < hi:
            mid = (lo + hi) // 2
            if self._out_adj[mid] < dst:
                lo = mid + 1
            else:
                hi = mid
        return lo < end and self._out_adj[lo] == dst

    def edges(self) -> Iterator[tuple[int, int]]:
        for u in range(self.n):
            for v in self.successors(u):
                yield u, v


def _compress(n: int, keys: list[int]) -> tuple[array, array]:
    """`keys` are sorted unique `row * n + col`; returns (offsets, columns)."""
    off = array('q', bytes(8 * (n + 1)))
    for k in keys:
        off[k // n + 1] += 1
    for i in range(n):
        off[i + 1] += off[i]
    return off, array('i', (k % n for k in keys))


def build_csr(n: int, edges: Iterable[tuple[int, int]]) -> CSRGraph:
    if n < 0:
        raise GraphError('PT-GRAPH-INPUT', 'node count must be non-negative')
    forward: set[int] = set()
    for u, v in edges:
        if not (0 <= u < n and 0 <= v < n):
            raise GraphError('PT-GRAPH-INPUT', f'edge ({u}, {v}) is outside 0..{n - 1}')
        forward.add(u * n + v)
    if n == 0:
        return CSRGraph(0, array('q', [0]), array('i'), array('q', [0]), array('i'))
    out_off, out_adj = _compress(n, sorted(forward))
    in_off, in_adj = _compress(n, sorted((k % n) * n + k // n for k in forward))
    return CSRGraph(n, out_off, out_adj, in_off, in_adj)
