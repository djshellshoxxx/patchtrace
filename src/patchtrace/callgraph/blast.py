"""A5 blast radius and entry distance: honest upper bounds over the observed (stored-list) edges."""
from __future__ import annotations

from .algo import ancestors, shortest_distance
from .contracts import Side
from .contracts_delta import Blast, EntryDistance, EntryPort
from .limits import CancelCheck, GraphError
from .snapshot import CallSnapshot, SideGraph
from .text import sanitize


def _position(graph: SideGraph, side: Side, node_id: str) -> int:
    position = graph.index.get(node_id)
    if position is None:
        raise GraphError('PT-GRAPH-INPUT', f'unknown {side} node id')
    return position


def blast(snap: CallSnapshot, side: Side, node_id: str, cancel: CancelCheck = None) -> Blast:
    graph = snap.side(side)
    position = _position(graph, side, node_id)
    direct = sum('calling' in graph.support[(caller, position)] for caller in graph.graph.predecessors(position))
    callers = ancestors(graph.graph, position, cancel)
    return Blast(direct_callers=direct, observed_callers=len(callers),
                 unknown_frontier=sum(c not in graph.listed for c in callers))


def entry_distance(snap: CallSnapshot, side: Side, node_id: str, entries: EntryPort | None,
                   cancel: CancelCheck = None) -> EntryDistance:
    """Hops on the shortest observed path from an entry (an upper bound), `not-reached`, or `unknown`
    when no entry label is present in the graph."""
    graph = snap.side(side)
    target = _position(graph, side, node_id)
    best: tuple[int, str] | None = None
    present = False
    for label in sorted(entries.entries(side)) if entries is not None else ():
        positions = graph.by_label.get(sanitize(label), ())
        if len(positions) != 1:
            continue
        present = True
        hops = shortest_distance(graph.graph, positions[0], target, cancel)
        if hops >= 0 and (best is None or hops < best[0]):
            best = (hops, sanitize(label, 120))
    if best is not None:
        return EntryDistance(state='reached', hops=best[0], via=best[1])
    return EntryDistance(state='not-reached' if present else 'unknown')
