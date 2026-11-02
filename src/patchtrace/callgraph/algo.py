"""Deterministic graph algorithms over `CSRGraph` (iterative; no recursion, no randomness)."""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Set
from typing import Literal, NamedTuple, Protocol

from .csr import CSRGraph
from .limits import (
    CANCEL_POP_INTERVAL,
    MAX_PATH_LENGTH,
    MAX_PATHS,
    PATH_VISIT_BUDGET,
    CancelCheck,
    GraphError,
)

Direction = Literal['out', 'in', 'both']


class Reach(NamedTuple):
    distances: dict[int, int]  # node -> hops from the nearest source, in visit order
    truncated: bool  # stopped because `cap` nodes were collected


class PathsResult(NamedTuple):
    paths: tuple[tuple[int, ...], ...]
    truncated: bool  # visit budget exhausted: more paths may exist


class _Traversal(Protocol):
    n: int

    def successors(self, node: int) -> Iterable[int]: ...
    def predecessors(self, node: int) -> Iterable[int]: ...


class _PathBudgetExhausted(Exception):
    """Private control flow: retain observed paths when the shared query budget ends."""


class _PathGraph:
    """One query's lazy membership filter and shared forward/reverse edge budget."""

    def __init__(self, graph: CSRGraph, src: int, dst: int, budget: int,
                 allowed: Set[int] | None, cancel: CancelCheck) -> None:
        self.n = graph.n
        self.graph, self.endpoints = graph, (src, dst)
        self.budget, self.allowed, self.cancel = budget, allowed, cancel
        self.examined = 0

    def successors(self, node: int) -> Iterator[int]:
        return self._row(node, reverse=False)

    def predecessors(self, node: int) -> Iterator[int]:
        return self._row(node, reverse=True)

    def _row(self, node: int, *, reverse: bool) -> Iterator[int]:
        degree = self.graph.in_degree(node) if reverse else self.graph.out_degree(node)
        values = self.graph.iter_predecessors(node) if reverse else self.graph.iter_successors(node)
        for _ in range(degree):
            # Charge before fetching, including candidates excluded by membership or the caller.
            if self.examined >= self.budget:
                raise _PathBudgetExhausted
            self.examined += 1
            _tick(self.examined, self.cancel)
            other = next(values)
            if self.allowed is None or other in self.allowed or other in self.endpoints:
                yield other


def _tick(pops: int, cancel: CancelCheck) -> None:
    if cancel is not None and pops % CANCEL_POP_INTERVAL == 0 and cancel():
        raise GraphError('PT-GRAPH-CANCEL', 'cancelled')


def _neighbours(g: _Traversal, node: int, direction: Direction) -> Iterable[int]:
    if direction == 'out':
        return g.successors(node)
    if direction == 'in':
        return g.predecessors(node)
    return (*g.successors(node), *g.predecessors(node))


def reach(
    g: _Traversal,
    sources: Iterable[int],
    direction: Direction = 'out',
    max_depth: int | None = None,
    cap: int | None = None,
    cancel: CancelCheck = None,
) -> Reach:
    """Breadth-first hop distances from one or many sources (sources are at distance 0)."""
    dist: dict[int, int] = {}
    queue: list[int] = []
    for s in sources:
        if not 0 <= s < g.n:
            raise GraphError('PT-GRAPH-INPUT', f'node {s} is outside 0..{g.n - 1}')
        if s not in dist:
            dist[s] = 0
            queue.append(s)
    head = 0
    while head < len(queue):
        _tick(head, cancel)
        node = queue[head]
        head += 1
        d = dist[node]
        if max_depth is not None and d >= max_depth:
            continue
        for nxt in _neighbours(g, node, direction):
            if nxt in dist:
                continue
            if cap is not None and len(dist) >= cap:
                return Reach(dist, True)
            dist[nxt] = d + 1
            queue.append(nxt)
    return Reach(dist, False)


def descendants(g: CSRGraph, node: int, cancel: CancelCheck = None) -> list[int]:
    """Nodes reachable by one or more forward edges, excluding `node` itself, ascending."""
    return sorted(set(reach(g, [node], 'out', cancel=cancel).distances) - {node})


def ancestors(g: CSRGraph, node: int, cancel: CancelCheck = None) -> list[int]:
    """Nodes that reach `node` by one or more edges, excluding `node` itself, ascending."""
    return sorted(set(reach(g, [node], 'in', cancel=cancel).distances) - {node})


def strongly_connected_components(g: CSRGraph, cancel: CancelCheck = None) -> list[tuple[int, ...]]:
    """Iterative Tarjan. Members ascending; components ordered by smallest member."""
    index = [-1] * g.n
    low = [0] * g.n
    on_stack = [False] * g.n
    stack: list[int] = []
    components: list[tuple[int, ...]] = []
    counter = 0
    steps = 0
    for root in range(g.n):
        if index[root] != -1:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack[root] = True
        work: list[tuple[int, int]] = [(root, 0)]
        while work:
            steps += 1
            _tick(steps, cancel)
            v, i = work.pop()
            succ = g.successors(v)
            if i < len(succ):
                work.append((v, i + 1))
                w = succ[i]
                if index[w] == -1:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack[w] = True
                    work.append((w, 0))
                elif on_stack[w]:
                    low[v] = min(low[v], index[w])
                continue
            if low[v] == index[v]:
                members = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    members.append(w)
                    if w == v:
                        break
                components.append(tuple(sorted(members)))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
    components.sort(key=lambda c: c[0])
    return components


def shortest_distance(g: _Traversal, src: int, dst: int, cancel: CancelCheck = None) -> int:
    """Hops on a shortest forward path (bidirectional BFS), or -1 when `dst` is unreachable."""
    return _shortest(g, src, dst, cancel)


def _join_path(parents: tuple[dict[int, int], dict[int, int]], src: int, dst: int,
               caller: int, callee: int) -> tuple[int, ...]:
    prefix, suffix = [caller], [callee]
    while prefix[-1] != src:
        prefix.append(parents[0][prefix[-1]])
    while suffix[-1] != dst:
        suffix.append(parents[1][suffix[-1]])
    return (*reversed(prefix), *suffix)


def _shortest(g: _Traversal, src: int, dst: int, cancel: CancelCheck = None, *,
              witness: list[tuple[int, ...]] | None = None, max_length: int = MAX_PATH_LENGTH) -> int:
    """Optionally retain a first shortest path from already visited BFS parent links."""
    for node in (src, dst):
        if not 0 <= node < g.n:
            raise GraphError('PT-GRAPH-INPUT', f'node {node} is outside 0..{g.n - 1}')
    if src == dst:
        return 0
    seen = ({src: 0}, {dst: 0})
    frontier = ([src], [dst])
    parents: tuple[dict[int, int], dict[int, int]] | None = ({}, {}) if witness is not None else None
    pops = 0
    while frontier[0] and frontier[1]:
        side = 0 if len(frontier[0]) <= len(frontier[1]) else 1
        mine, other = seen[side], seen[1 - side]
        nxt_frontier: list[int] = []
        best = -1
        best_path: tuple[int, ...] | None = None
        for node in frontier[side]:
            pops += 1
            _tick(pops, cancel)
            for w in (g.successors(node) if side == 0 else g.predecessors(node)):
                if w in other:
                    total = mine[node] + 1 + other[w]
                    best = total if best < 0 else min(best, total)
                    if parents is not None and total <= max_length:
                        caller, callee = (node, w) if side == 0 else (w, node)
                        candidate = _join_path(parents, src, dst, caller, callee)
                        if best_path is None or (len(candidate), candidate) < (len(best_path), best_path):
                            best_path = candidate
                if w not in mine:
                    mine[w] = mine[node] + 1
                    nxt_frontier.append(w)
                    if parents is not None:
                        # Forward discovery keeps FIFO prefix order with ascending rows;
                        # sorting the next frontier by node ID would break this invariant.
                        parents[side][w] = node
                elif (parents is not None and side == 1 and mine[w] == mine[node] + 1
                      and node < parents[1][w]):
                    # Reverse BFS discovers suffixes from their end; the smallest next hop
                    # gives their forward lexicographic order after this layer completes.
                    parents[1][w] = node
        if best >= 0:
            if witness is not None and best_path is not None and len(best_path) - 1 == best:
                witness.append(best_path)
            return best
        frontier = (nxt_frontier, frontier[1]) if side == 0 else (frontier[0], nxt_frontier)
    return -1


def simple_paths(
    g: CSRGraph,
    src: int,
    dst: int,
    max_paths: int = MAX_PATHS,
    max_length: int = MAX_PATH_LENGTH,
    budget: int = PATH_VISIT_BUDGET,
    cancel: CancelCheck = None,
    *,
    allowed: Set[int] | None = None,
) -> PathsResult:
    """Up to `max_paths` simple forward paths, shortest first (ties in ascending node order),
    each of at most `max_length` edges. All three phases share `budget` adjacency examinations.
    `allowed` restricts intermediate nodes; endpoints remain eligible. No graph or row is copied."""
    walk = _PathGraph(g, src, dst, budget, allowed, cancel)
    found: list[tuple[int, ...]] = []
    witness: list[tuple[int, ...]] = []
    _tick(0, cancel)
    try:
        if _shortest(walk, src, dst, witness=witness, max_length=max_length) < 0:
            return PathsResult((), False)
        if src == dst:
            return PathsResult(((src,),), False)
        to_dst = reach(walk, [dst], 'in', max_depth=max_length).distances
        if src not in to_dst:
            return PathsResult((), False)
        for length in range(to_dst[src], max_length + 1):
            path = [src]
            on_path = {src}
            iters = [walk.successors(src)]
            while iters:
                depth = len(path)  # edges used if the next node is appended
                for w in iters[-1]:
                    if w in on_path:
                        continue
                    if w == dst:
                        if depth != length:
                            continue
                        found.append((*path, w))
                        if len(found) >= max_paths:
                            return PathsResult(tuple(found), False)
                        continue
                    if to_dst.get(w, length + 1) <= length - depth:
                        path.append(w)
                        on_path.add(w)
                        iters.append(walk.successors(w))
                        break
                else:
                    iters.pop()
                    on_path.discard(path.pop())
    except _PathBudgetExhausted:
        return PathsResult(tuple(found or witness), True)
    return PathsResult(tuple(found), False)
