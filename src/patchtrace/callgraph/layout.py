"""Deterministic ego hop-layered layout of a call neighbourhood (WB2 G6, pure; the Qt canvas only paints it).

Layers are signed hop distances from the seed (callers left, callees right), so cycles need no edge
reversal: a call that points against the layer order is reported as kind 'back'. The layout takes ids and
edges only, never label text, and orders everything by id, so it is independent of dict and set order."""
from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from .contracts import GraphView
from .limits import (
    CANCEL_CLAIM_INTERVAL,
    LAYOUT_DUMMIES,
    LAYOUT_HALF_DEPTH,
    LAYOUT_INPUT_EDGES,
    LAYOUT_INPUT_NODES,
    LAYOUT_NODES_DEFAULT,
    LAYOUT_NODES_HARD,
    LAYOUT_SWEEPS,
    MAX_LABEL_STORED,
    CancelCheck,
    GraphError,
)

NODE_W = 192
NODE_H = 28  # even, so centres are integers
LAYER_GAP = 96
ROW_GAP = 12
DUMMY_GAP = 6
COORD_ITERATIONS = 4

EdgeKind = Literal['forward', 'back', 'same-layer', 'self']
NoteKind = Literal['depth', 'nodes', 'disconnected', 'long-edges']


@dataclass(frozen=True)
class LayoutNode:
    id: str
    layer: int
    x: int
    y: int
    w: int = NODE_W
    h: int = NODE_H


@dataclass(frozen=True)
class LayoutEdge:
    src: str
    dst: str
    kind: EdgeKind
    points: tuple[tuple[int, int], ...]  # polyline from the caller's anchor to the callee's anchor


@dataclass(frozen=True)
class LayoutNote:
    """Something left out; `limit` is the cap that caused it (0 when the cause is not a cap)."""
    kind: NoteKind
    dropped: int
    limit: int


@dataclass(frozen=True)
class Layout:
    seed: str
    nodes: tuple[LayoutNode, ...]  # sorted by id
    edges: tuple[LayoutEdge, ...]  # sorted by (src, dst)
    width: int
    height: int
    notes: tuple[LayoutNote, ...]

    @property
    def truncated(self) -> bool:
        return bool(self.notes)


def layout_view(view: GraphView, seed_id: str, *, cancel: CancelCheck = None, **budgets: int) -> Layout:
    return layout_graph((n.id for n in view.nodes), ((e.src, e.dst) for e in view.edges), seed_id,
                        cancel=cancel, **budgets)


def _budget(value: int, name: str, maximum: int, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise GraphError('PT-GRAPH-INPUT', f'{name} must be an integer of at least {minimum}')
    return min(value, maximum)


def _identity(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > MAX_LABEL_STORED:
        raise GraphError('PT-GRAPH-INPUT', 'layout node identities must be nonempty bounded strings')


def _inputs(node_ids: Iterable[str], edges: Iterable[tuple[str, str]], cancel: CancelCheck):
    names: set[str] = set()
    for count, name in enumerate(node_ids):
        _periodic(cancel, count)
        if count >= LAYOUT_INPUT_NODES:
            raise GraphError('PT-GRAPH-LIMIT', 'layout node input exceeds its work limit')
        _identity(name)
        names.add(name)
    ids = sorted(names)
    index = {name: i for i, name in enumerate(ids)}
    unique: set[tuple[int, int]] = set()
    for count, edge in enumerate(edges):
        _periodic(cancel, count)
        if count >= LAYOUT_INPUT_EDGES:
            raise GraphError('PT-GRAPH-LIMIT', 'layout edge input exceeds its work limit')
        if not isinstance(edge, (tuple, list)) or len(edge) != 2:
            raise GraphError('PT-GRAPH-INPUT', 'layout edges must contain exactly two node identities')
        a, b = edge
        _identity(a)
        _identity(b)
        if a in index and b in index:
            unique.add((index[a], index[b]))
    _check(cancel)
    return ids, index, sorted(unique)


def layout_graph(
    node_ids: Iterable[str], edges: Iterable[tuple[str, str]], seed: str, *, max_nodes: int = LAYOUT_NODES_DEFAULT,
    max_dummies: int = LAYOUT_DUMMIES, sweeps: int = LAYOUT_SWEEPS, half_depth: int = LAYOUT_HALF_DEPTH,
    cancel: CancelCheck = None,
) -> Layout:
    _check(cancel)
    _identity(seed)
    max_nodes = _budget(max_nodes, 'max_nodes', LAYOUT_NODES_HARD, minimum=1)
    max_dummies = _budget(max_dummies, 'max_dummies', LAYOUT_DUMMIES)
    sweeps = _budget(sweeps, 'sweeps', LAYOUT_SWEEPS)
    half_depth = _budget(half_depth, 'half_depth', LAYOUT_HALF_DEPTH)
    ids, index, pairs = _inputs(node_ids, edges, cancel)
    if seed not in index:
        raise GraphError('PT-GRAPH-INPUT', 'the layout seed is not one of the nodes')
    out: list[list[int]] = [[] for _ in ids]
    back: list[list[int]] = [[] for _ in ids]
    for count, (a, b) in enumerate(pairs):
        _periodic(cancel, count)
        out[a].append(b)
        back[b].append(a)
    layer = _assign_layers(out, back, index[seed], cancel)
    notes = [LayoutNote('disconnected', len(ids) - len(layer), 0)]
    deep = [i for i, lv in layer.items() if abs(lv) > half_depth]
    notes.append(LayoutNote('depth', len(deep), half_depth))
    for i in deep:
        del layer[i]
    order = sorted(layer, key=lambda i: (i != index[seed], abs(layer[i]), layer[i], i))
    notes.append(LayoutNote('nodes', max(0, len(order) - max_nodes), max_nodes))
    for i in order[max_nodes:]:
        del layer[i]
    routes, long_edges = _drop_long_edges(
        [p for p in pairs if p[0] in layer and p[1] in layer], layer, max_dummies, cancel)
    notes.append(LayoutNote('long-edges', long_edges, max_dummies))
    return _build(ids, layer, routes, index[seed], sweeps, tuple(n for n in notes if n.dropped), cancel)


def _assign_layers(out: Sequence[Sequence[int]], back: Sequence[Sequence[int]], seed: int,
                   cancel: CancelCheck) -> dict[int, int]:
    down, up = _bfs(out, seed, cancel), _bfs(back, seed, cancel)
    layer: dict[int, int] = {}
    for node in sorted(set(down) | set(up)):
        d, u = down.get(node), up.get(node)
        layer[node] = d if u is None or (d is not None and d <= u) else -u  # equal distance: callee side
    # Nodes reached only through a shared caller or callee sit one layer from their placed neighbour.
    queue = deque(sorted(layer, key=lambda i: (abs(layer[i]), layer[i], i)))
    work = 0
    while queue:
        _periodic(cancel, work)
        node = queue.popleft()
        for other, step in sorted([(o, 1) for o in out[node]] + [(o, -1) for o in back[node]]):
            work += 1
            _periodic(cancel, work)
            if other not in layer:
                layer[other] = layer[node] + step
                queue.append(other)
    return layer


def _bfs(adjacency: Sequence[Sequence[int]], start: int, cancel: CancelCheck) -> dict[int, int]:
    seen, queue = {start: 0}, deque([start])
    work = 0
    while queue:
        _periodic(cancel, work)
        node = queue.popleft()
        for other in adjacency[node]:
            work += 1
            _periodic(cancel, work)
            if other not in seen:
                seen[other] = seen[node] + 1
                queue.append(other)
    return seen


def _drop_long_edges(
    pairs: list[tuple[int, int]], layer: dict[int, int], max_dummies: int, cancel: CancelCheck,
) -> tuple[list[tuple[int, int]], int]:
    """The longest edges go first when their dummy nodes would exceed the cap."""
    def cost(edge: tuple[int, int]) -> int:
        return max(0, abs(layer[edge[0]] - layer[edge[1]]) - 1)

    total = sum(cost(p) for p in pairs)
    if total <= max_dummies:
        return pairs, 0
    dropped: set[tuple[int, int]] = set()
    for count, edge in enumerate(sorted(pairs, key=lambda p: (-cost(p), p))):
        _periodic(cancel, count)
        if total <= max_dummies:
            break
        dropped.add(edge)
        total -= cost(edge)
    return [p for p in pairs if p not in dropped], len(dropped)


class _Items:
    """Real nodes first (id order), then one dummy per layer an edge crosses. Segments join adjacent layers."""

    def __init__(self, kept: Sequence[int], layer: dict[int, int]) -> None:
        self.real = {node: pos for pos, node in enumerate(kept)}
        self.layer = [layer[node] for node in kept]
        self.left: list[list[int]] = [[] for _ in kept]
        self.right: list[list[int]] = [[] for _ in kept]
        self.segments: list[tuple[int, int]] = []

    def add_dummy(self, lv: int) -> int:
        self.layer.append(lv)
        self.left.append([])
        self.right.append([])
        return len(self.layer) - 1

    def link(self, a: int, b: int) -> None:
        self.right[a].append(b)
        self.left[b].append(a)
        self.segments.append((a, b))

    def half(self, item: int) -> int:
        return NODE_H // 2 if item < len(self.real) else 0


def _build(
    ids: Sequence[str], layer: dict[int, int], edges: Sequence[tuple[int, int]], seed: int, sweeps: int,
    notes: tuple[LayoutNote, ...], cancel: CancelCheck,
) -> Layout:
    kept = sorted(layer)
    items = _Items(kept, layer)
    routes: list[tuple[int, int, EdgeKind, list[int]]] = []
    for count, (a, b) in enumerate(edges):
        _periodic(cancel, count)
        s, d = items.real[a], items.real[b]
        if a == b:
            routes.append((a, b, 'self', [s]))
        elif layer[a] == layer[b]:
            routes.append((a, b, 'same-layer', [s, d]))
        else:
            forward = layer[a] < layer[b]
            lo, hi = (a, b) if forward else (b, a)
            chain = [items.real[lo], *(items.add_dummy(lv) for lv in range(layer[lo] + 1, layer[hi])), items.real[hi]]
            for x, y in zip(chain, chain[1:], strict=False):
                items.link(x, y)
            routes.append((a, b, 'forward' if forward else 'back', chain if forward else chain[::-1]))
    layers = _order(items, sweeps, cancel)
    centre = _coordinates(items, layers, cancel)
    _check(cancel)
    return _emit(ids, kept, items, routes, centre, ids[seed], notes)


def _order(items: _Items, sweeps: int, cancel: CancelCheck) -> dict[int, list[int]]:
    layers: dict[int, list[int]] = {}
    for item, lv in enumerate(items.layer):
        layers.setdefault(lv, []).append(item)
    keys = sorted(layers)
    best = {lv: list(members) for lv, members in layers.items()}
    best_cross = _crossings(items, layers, cancel)
    for _ in range(max(0, sweeps)):
        if best_cross == 0:
            break
        _check(cancel)
        for sequence, nbrs in ((keys[1:], items.left), (keys[-2::-1], items.right)):
            for lv in sequence:
                _check(cancel)
                _barycentre(layers, lv, nbrs)
        cross = _crossings(items, layers, cancel)
        if cross >= best_cross:  # stop once a sweep no longer reduces crossings
            break
        best, best_cross = {lv: list(m) for lv, m in layers.items()}, cross
    return best


def _check(cancel: CancelCheck) -> None:
    if cancel is not None and cancel():
        raise GraphError('PT-GRAPH-CANCEL', 'cancelled')


def _periodic(cancel: CancelCheck, work: int) -> None:
    if work % CANCEL_CLAIM_INTERVAL == 0:
        _check(cancel)


def _positions(layers: dict[int, list[int]]) -> dict[int, int]:
    return {item: p for members in layers.values() for p, item in enumerate(members)}


def _barycentre(layers: dict[int, list[int]], lv: int, nbrs: Sequence[Sequence[int]]) -> None:
    pos = _positions(layers)

    def key(item: int) -> tuple[int, int, int]:
        ref = nbrs[item]
        # integer mean position; an item with no neighbour on that side keeps its own place
        return (sum(pos[o] for o in ref) * 1024 // len(ref) if ref else pos[item] * 1024), pos[item], item

    layers[lv].sort(key=key)


def _crossings(items: _Items, layers: dict[int, list[int]], cancel: CancelCheck) -> int:
    """Edge crossings between adjacent layers, counted as inversions with a Fenwick tree."""
    pos = _positions(layers)
    by_layer: dict[int, list[tuple[int, int]]] = {}
    for a, b in items.segments:
        by_layer.setdefault(items.layer[a], []).append((pos[a], pos[b]))
    total = 0
    for lv, segments in by_layer.items():
        size = len(layers[lv + 1])
        tree = [0] * (size + 1)
        for seen, (_, low) in enumerate(sorted(segments)):
            _periodic(cancel, seen)
            at, not_right = low + 1, 0
            while at > 0:
                not_right += tree[at]
                at -= at & -at
            total += seen - not_right  # earlier segments that end strictly right of this one
            at = low + 1
            while at <= size:
                tree[at] += 1
                at += at & -at
    return total


def _coordinates(items: _Items, layers: dict[int, list[int]], cancel: CancelCheck) -> list[int]:
    """Centre y per item: iterated neighbour mean, then pool-adjacent-violators to restore spacing."""
    centre = [0] * len(items.layer)
    offsets: dict[int, list[int]] = {}
    for lv, members in layers.items():
        run = [0]
        for prev, cur in zip(members, members[1:], strict=False):
            gap = ROW_GAP if prev < len(items.real) and cur < len(items.real) else DUMMY_GAP
            run.append(run[-1] + items.half(prev) + items.half(cur) + gap)
        offsets[lv] = run
        for item, off in zip(members, run, strict=True):
            centre[item] = off
    for _ in range(COORD_ITERATIONS):
        _check(cancel)
        for lv in sorted(layers):
            _check(cancel)
            members = layers[lv]
            wanted = []
            for item in members:
                nbrs = items.left[item] + items.right[item]
                wanted.append(sum(centre[o] for o in nbrs) // len(nbrs) if nbrs else centre[item])
            for item, y in zip(members, _separate(wanted, offsets[lv]), strict=True):
                centre[item] = y
    return centre


def _separate(wanted: Sequence[int], offsets: Sequence[int]) -> list[int]:
    """Least-squares placement keeping `offsets` as minimum spacing (integer pool-adjacent-violators)."""
    blocks: list[list[int]] = []  # [sum of (wanted - offset), count]
    for w, off in zip(wanted, offsets, strict=True):
        blocks.append([w - off, 1])
        while len(blocks) > 1 and blocks[-2][0] // blocks[-2][1] > blocks[-1][0] // blocks[-1][1]:
            s, n = blocks.pop()
            blocks[-1][0] += s
            blocks[-1][1] += n
    placed: list[int] = []
    for s, n in blocks:
        placed += [s // n] * n
    return [p + off for p, off in zip(placed, offsets, strict=True)]


def _emit(
    ids: Sequence[str], kept: Sequence[int], items: _Items, routes: Sequence[tuple[int, int, EdgeKind, list[int]]],
    centre: list[int], seed: str, notes: tuple[LayoutNote, ...],
) -> Layout:
    top = min(centre[i] - items.half(i) for i in range(len(centre)))
    cy = [c - top for c in centre]
    first = min(items.layer)
    col = [(lv - first) * (NODE_W + LAYER_GAP) for lv in items.layer]
    nodes = tuple(sorted(
        (LayoutNode(ids[n], items.layer[items.real[n]], col[items.real[n]], cy[items.real[n]] - NODE_H // 2)
         for n in kept), key=lambda n: n.id))
    edges = tuple(sorted((_edge(ids, items, route, col, cy) for route in routes), key=lambda e: (e.src, e.dst)))
    right = max([n.x + n.w for n in nodes] + [x for e in edges for x, _ in e.points])
    bottom = max([n.y + n.h for n in nodes] + [y for e in edges for _, y in e.points])
    return Layout(seed, nodes, edges, right, bottom, notes)


def _edge(
    ids: Sequence[str], items: _Items, route: tuple[int, int, EdgeKind, list[int]], col: list[int], cy: list[int],
) -> LayoutEdge:
    a, b, kind, chain = route
    first, last = chain[0], chain[-1]
    if kind == 'self':
        x, y = col[first] + NODE_W, cy[first]
        points = [(x, y - 4), (x + 16, y - 4), (x + 16, y + 4), (x, y + 4)]
    elif kind == 'same-layer':
        gutter = col[first] + NODE_W + LAYER_GAP // 2
        points = [(col[first] + NODE_W, cy[first]), (gutter, cy[first]), (gutter, cy[last]), (col[last] + NODE_W, cy[last])]
    else:
        inner = [(col[i] + NODE_W // 2, cy[i]) for i in chain[1:-1]]
        start_x = col[first] + (NODE_W if kind == 'forward' else 0)
        end_x = col[last] + (0 if kind == 'forward' else NODE_W)
        points = [(start_x, cy[first]), *inner, (end_x, cy[last])]
    return LayoutEdge(ids[a], ids[b], kind, tuple(points))
