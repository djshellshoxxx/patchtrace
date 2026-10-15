"""A6 observed call paths between two nodes, over functions that have stored call lists."""
from __future__ import annotations

from .algo import simple_paths
from .contracts import Side
from .contracts_delta import ObservedPaths
from .csr import build_csr
from .limits import CancelCheck, GraphError
from .snapshot import CallSnapshot

_NONE_NOTE = 'Not found among the {count} functions with stored call lists; this is not proof that no path exists.'
_FOUND_NOTE = 'Observed path of at most {hops} calls; calls outside the stored lists are not seen.'


def find_paths(snap: CallSnapshot, side: Side, src_id: str, dst_id: str,
               cancel: CancelCheck = None) -> ObservedPaths:
    graph = snap.side(side)
    for node_id in (src_id, dst_id):
        if node_id not in graph.index:
            raise GraphError('PT-GRAPH-INPUT', f'unknown {side} node id')
    src, dst = graph.index[src_id], graph.index[dst_id]
    allowed = set(range(graph.graph.n)) if snap.completeness == 'whole-program' else set(graph.listed) | {src, dst}
    order = sorted(allowed)
    remap = {old: new for new, old in enumerate(order)}
    sub = build_csr(len(order), ((remap[u], remap[v]) for u, v in graph.graph.edges()
                                 if u in remap and v in remap))
    result = simple_paths(sub, remap[src], remap[dst], cancel=cancel)
    paths = tuple(tuple(graph.nodes[order[p]].id for p in path) for path in result.paths)
    labels = {node_id: graph.nodes[graph.index[node_id]].label for path in paths for node_id in path}
    note = (_FOUND_NOTE.format(hops=len(paths[0]) - 1) if paths
            else _NONE_NOTE.format(count=len(graph.listed)))
    return ObservedPaths(side=side, paths=paths, labels=labels, truncated=result.truncated,
                         completeness=snap.completeness, note=note)
