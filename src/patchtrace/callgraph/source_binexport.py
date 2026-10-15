"""Whole-program `CallSource` over a parsed BinExport2 message's `call_graph` (tier `addresses`).

BinExport2 call-graph edges carry no call/jump kind, so tail-call jumps appear as calls; that is stated in
`limitations` and never hidden."""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Literal

from .contracts import Claim, Completeness, Side
from .limits import CANCEL_CLAIM_INTERVAL, CancelCheck, GraphError
from .source_ir import MAX_IR_EDGES, default_label
from .text import sanitize

VERTEX_LIBRARY, VERTEX_IMPORTED = 1, 2  # BinExport2.CallGraph.Vertex.Type


class BinExportCallSource:
    source_id = 'binexport'
    tier: Literal['labels', 'addresses'] = 'addresses'
    completeness: Completeness = 'whole-program'
    limitations = ('BinExport2 does not distinguish call edges from tail-call jumps; jumps may be listed as calls.',)

    def __init__(self, messages: Mapping[Side, object], max_edges: int = MAX_IR_EDGES) -> None:
        self._messages, self._max_edges = messages, max_edges

    def _vertices(self, side: Side) -> list[tuple[str, bool]]:
        """(label, is external) per vertex, in message order."""
        graph = self._messages[side].call_graph
        libraries = [library.name for library in self._messages[side].library]
        out = []
        for vertex in graph.vertex:
            name = vertex.mangled_name
            external = vertex.type in (VERTEX_LIBRARY, VERTEX_IMPORTED)
            if external and name and vertex.HasField('library_index') and vertex.library_index < len(libraries) \
                    and libraries[vertex.library_index]:
                label = f'{libraries[vertex.library_index]}::{name}'
            else:
                label = name or default_label(0, vertex.address)
            out.append((sanitize(label), external))
        return out

    def claims(self, side: Side, cancel: CancelCheck) -> Iterable[Claim]:
        vertices, edges = self._vertices(side), self._messages[side].call_graph.edge
        if len(edges) > self._max_edges:
            raise GraphError('PT-GRAPH-LIMIT', f'call graph has {len(edges):,} edges; the limit is '
                             f'{self._max_edges:,}')
        for emitted, edge in enumerate(edges, 1):
            src, dst = edge.source_vertex_index, edge.target_vertex_index
            if not (0 <= src < len(vertices) and 0 <= dst < len(vertices)):
                raise GraphError('PT-GRAPH-SOURCE', f'call-graph edge {emitted - 1} names a missing vertex')
            if cancel is not None and emitted % CANCEL_CLAIM_INTERVAL == 0 and cancel():
                raise GraphError('PT-GRAPH-CANCEL', 'cancelled')
            yield Claim(vertices[src][0], vertices[dst][0], 'called')

    def listed(self, side: Side) -> Iterable[str]:
        return (label for label, external in self._vertices(side) if not external)
