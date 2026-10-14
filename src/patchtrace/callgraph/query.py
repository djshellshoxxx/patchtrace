"""Bounded neighbourhood queries over a `CallSnapshot`, returned as `GraphView` (GL-03 limits)."""
from __future__ import annotations

from typing import Literal

from ..enrichment.identity import domain_id
from .contracts import GraphEdge, GraphNode, GraphView, MoreMarker, Pairing, Side
from .limits import CANCEL_POP_INTERVAL, CancelCheck, GraphError
from .snapshot import CallSnapshot, SideGraph
from .text import sanitize

MAX_DEPTH = 4
DEFAULT_NODES, MAX_NODES = 100, 500
DEFAULT_EDGES, MAX_EDGES = 250, 2_000
NEIGHBOURS_PER_NODE = 64

QueryDirection = Literal['out', 'in', 'both']


def find_node(snap: CallSnapshot, side: Side, label: str) -> GraphNode:
    """Exact label lookup; never a fuzzy or first-wins fallback."""
    graph = snap.side(side)
    positions = graph.by_label.get(sanitize(label), ())
    if not positions:
        raise GraphError('PT-GRAPH-INPUT', f'no {side} function labelled {sanitize(label, 80)!r} in the call graph')
    if len(positions) > 1:
        raise GraphError('PT-GRAPH-INPUT', f'{len(positions)} {side} nodes share the label {sanitize(label, 80)!r}; '
                         'select by node id')
    return graph.nodes[positions[0]]


def _position(graph: SideGraph, side: Side, node_id: str) -> int:
    position = graph.index.get(node_id)
    if position is None:
        raise GraphError('PT-GRAPH-INPUT', f'unknown {side} node id')
    return position


def partner(snap: CallSnapshot, side: Side, node_id: str) -> Pairing:
    """The other build's counterpart of a node; an ambiguous node has none to name."""
    graph = snap.side(side)
    position = _position(graph, side, node_id)
    if graph.nodes[position].kind == 'ambiguous':
        return Pairing(kind='unknown')
    return snap.pairs.partner(side, graph.raw_labels[position])


def _order(graph: SideGraph, positions: set[int]) -> list[int]:
    return sorted(positions, key=lambda p: (graph.nodes[p].label, graph.nodes[p].id))


def _neighbours(graph: SideGraph, position: int, direction: QueryDirection) -> list[int]:
    found: set[int] = set()
    if direction in ('out', 'both'):
        found.update(graph.graph.successors(position))
    if direction in ('in', 'both'):
        found.update(graph.graph.predecessors(position))
    return _order(graph, found)


def _edge(graph: SideGraph, side: Side, src: int, dst: int) -> GraphEdge:
    ids = {'src': graph.nodes[src].id, 'dst': graph.nodes[dst].id}
    return GraphEdge(id=domain_id('callgraph-edge', 1, ids), src=ids['src'], dst=ids['dst'], side=side,
                     support=tuple(sorted(graph.support[(src, dst)])))


def neighbourhood(snap: CallSnapshot, side: Side, focus: list[str], direction: QueryDirection = 'both',
                  depth: int = 1, max_nodes: int = DEFAULT_NODES, max_edges: int = DEFAULT_EDGES,
                  cancel: CancelCheck = None) -> GraphView:
    if not focus:
        raise GraphError('PT-GRAPH-INPUT', 'a query needs at least one node')
    if not 0 <= depth <= MAX_DEPTH:
        raise GraphError('PT-GRAPH-INPUT', f'depth must be 0..{MAX_DEPTH}')
    if not 1 <= max_nodes <= MAX_NODES or not 1 <= max_edges <= MAX_EDGES:
        raise GraphError('PT-GRAPH-INPUT', f'limits are at most {MAX_NODES} nodes and {MAX_EDGES} edges')
    graph = snap.side(side)
    roots = [_position(graph, side, node_id) for node_id in focus]
    seen = dict.fromkeys(roots[:max_nodes], 0)
    truncated = len(roots) > max_nodes
    edges: dict[tuple[int, int], None] = {}
    more: list[MoreMarker] = []
    queue = list(seen)
    for pops, node in enumerate(queue):
        if cancel is not None and pops % CANCEL_POP_INTERVAL == 0 and cancel():
            raise GraphError('PT-GRAPH-CANCEL', 'cancelled')
        if seen[node] >= depth:
            continue
        around = _neighbours(graph, node, direction)
        if len(around) > NEIGHBOURS_PER_NODE:
            more.append(MoreMarker(node=graph.nodes[node].id, count=len(around) - NEIGHBOURS_PER_NODE))
        for other in around[:NEIGHBOURS_PER_NODE]:
            if other not in seen:
                if len(seen) >= max_nodes:
                    truncated = True
                    continue
                seen[other] = seen[node] + 1
                queue.append(other)
            for pair in ((node, other), (other, node)):
                if pair in graph.support and pair not in edges:
                    if len(edges) >= max_edges:
                        truncated = True
                    else:
                        edges[pair] = None
    return _view(snap, side, graph, list(seen), list(edges), more, truncated)


def _view(snap: CallSnapshot, side: Side, graph: SideGraph, nodes: list[int], edges: list[tuple[int, int]],
          more: list[MoreMarker], truncated: bool) -> GraphView:
    limitations = list(snap.limitations)
    if truncated or snap.truncated:
        limitations.append('The view is capped; more nodes or edges exist than are shown.')
    shown = sorted((graph.nodes[p] for p in nodes), key=lambda n: (n.label, n.id))
    ordered = sorted(edges, key=lambda e: (graph.nodes[e[0]].label, graph.nodes[e[1]].label,
                                           graph.nodes[e[0]].id, graph.nodes[e[1]].id))
    data = snap.data
    return GraphView(
        project_id=data.project_id, run_id=data.run_id, older_sha256=data.older_sha256,
        newer_sha256=data.newer_sha256, side=side, nodes=tuple(shown),
        edges=tuple(_edge(graph, side, s, d) for s, d in ordered),
        more=tuple(sorted(more, key=lambda m: m.node)), truncated=truncated or snap.truncated,
        completeness=snap.completeness, limitations=tuple(limitations), source=snap.source)
