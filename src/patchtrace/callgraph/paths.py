"""A6 observed call paths between two nodes, over functions that have stored call lists."""
from __future__ import annotations

from .algo import simple_paths
from .contracts import Side
from .contracts_delta import ObservedPaths
from .limits import CancelCheck, GraphError
from .snapshot import CallSnapshot

_NONE_NOTE = 'Not found among the {count} functions with stored call lists; this is not proof that no path exists.'
_FOUND_NOTE = 'Observed path of at most {hops} calls; calls outside the stored lists are not seen.'
_CAPPED_NOTE = 'Path search reached its work limit; more paths may exist.'


def find_paths(snap: CallSnapshot, side: Side, src_id: str, dst_id: str,
               cancel: CancelCheck = None) -> ObservedPaths:
    graph = snap.side(side)
    for node_id in (src_id, dst_id):
        if node_id not in graph.index:
            raise GraphError('PT-GRAPH-INPUT', f'unknown {side} node id')
    src, dst = graph.index[src_id], graph.index[dst_id]
    allowed = None if snap.completeness == 'whole-program' else graph.listed
    result = simple_paths(graph.graph, src, dst, cancel=cancel, allowed=allowed)
    paths = tuple(tuple(graph.nodes[p].id for p in path) for path in result.paths)
    labels = {node_id: graph.nodes[graph.index[node_id]].label for path in paths for node_id in path}
    note = (_FOUND_NOTE.format(hops=len(paths[0]) - 1) if paths
            else _NONE_NOTE.format(count=len(graph.listed)))
    if result.truncated:
        note += ' ' + _CAPPED_NOTE
    return ObservedPaths(side=side, paths=paths, labels=labels, truncated=result.truncated,
                         completeness=snap.completeness, note=note)
