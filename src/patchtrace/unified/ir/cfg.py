"""Control-flow helpers for the `fn.loops` column: back edges whose target dominates the source (BinDiff's loop count).

Iterative dominators (Cooper, Harvey, Kennedy: "A Simple, Fast Dominance Algorithm") over the blocks reachable from
the entry block. Pure, deterministic, O(blocks * edges) in the worst case, which is fine for one function.
"""
from __future__ import annotations

from collections.abc import Sequence


def _reverse_postorder(n: int, succ: Sequence[Sequence[int]], entry: int) -> list[int]:
    order: list[int] = []
    seen = [False] * n
    stack: list[tuple[int, int]] = [(entry, 0)]
    seen[entry] = True
    while stack:
        vertex, index = stack.pop()
        if index < len(succ[vertex]):
            stack.append((vertex, index + 1))
            target = succ[vertex][index]
            if not seen[target]:
                seen[target] = True
                stack.append((target, 0))
        else:
            order.append(vertex)
    order.reverse()
    return order


def dominators(n: int, succ: Sequence[Sequence[int]], entry: int = 0) -> list[int]:
    """Immediate dominator of every block reachable from `entry` (the entry dominates itself), else -1."""
    if not 0 <= entry < n:
        return [-1] * n
    order = _reverse_postorder(n, succ, entry)
    position = {vertex: i for i, vertex in enumerate(order)}
    preds: list[list[int]] = [[] for _ in range(n)]
    for vertex in order:
        for target in succ[vertex]:
            preds[target].append(vertex)
    idom = [-1] * n
    idom[entry] = entry

    def intersect(a: int, b: int) -> int:
        while a != b:
            while position[a] > position[b]:
                a = idom[a]
            while position[b] > position[a]:
                b = idom[b]
        return a

    changed = True
    while changed:
        changed = False
        for vertex in order:
            if vertex == entry:
                continue
            new = -1
            for pred in preds[vertex]:
                if idom[pred] == -1:
                    continue
                new = pred if new == -1 else intersect(pred, new)
            if new != -1 and idom[vertex] != new:
                idom[vertex] = new
                changed = True
    return idom


def count_back_edges(n: int, succ: Sequence[Sequence[int]], entry: int = 0) -> int:
    """Edges (u, v) with v dominating reachable u; self loops and duplicate edges count.

    DFS intervals of the immediate-dominator tree answer each ancestry query in O(1).
    The work after `dominators` is O(blocks + edges), including a long acyclic chain.
    """
    if n == 0:
        return 0
    idom = dominators(n, succ, entry)
    children: list[list[int]] = [[] for _ in range(n)]
    for node, parent in enumerate(idom):
        if parent >= 0 and parent != node:
            children[parent].append(node)
    start, end = [-1] * n, [-1] * n
    stack = [(entry, False)] if 0 <= entry < n else []
    clock = 0
    while stack:
        node, exiting = stack.pop()
        if exiting:
            end[node] = clock
        else:
            start[node] = clock
            clock += 1
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(children[node]))
    count = 0
    for u in range(n):
        if start[u] == -1:
            continue
        for v in succ[u]:
            if 0 <= start[v] <= start[u] < end[v]:
                count += 1
    return count
