"""Qt-free worker side of the Calls panel: build the snapshot, deltas and leads from an immutable project copy,
query a neighbourhood and lay it out. Workers get a deep copy of the project, never the live service."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..models import ComparisonProject
from .contracts import GraphView, Pairing, Side
from .contracts_delta import CallDelta, GraphLead
from .delta import DeltaContext, compute_deltas, diff_types_by_match
from .leads import build_leads
from .limits import GraphError
from .project_input import ProjectInput, read_project_input
from .query import QueryDirection, find_node, neighbourhood, partner
from .snapshot import CallSnapshot, build_snapshot
from .text import one_line
from .view_model import NeighbourRow, neighbour_rows

Cancel = Callable[[], bool]
NEIGHBOUR_NODES = 500   # normal cap of the spec (the default query is 100)
NEIGHBOUR_EDGES = 2_000
LAYER_X, ROW_Y = 240.0, 56.0


@dataclass(frozen=True)
class GraphData:
    """Everything one project read produced; immutable once built, shared with workers read-only."""
    snapshot: CallSnapshot
    deltas: tuple[CallDelta, ...]
    leads: tuple[GraphLead, ...]
    raw_missing: bool


@dataclass(frozen=True)
class Failure:
    code: str
    message: str


@dataclass(frozen=True)
class QuerySpec:
    match_id: str
    side: Side
    direction: QueryDirection
    depth: int
    show_unresolved: bool


@dataclass(frozen=True)
class Neighbourhood:
    spec: QuerySpec
    view: GraphView
    focus_id: str
    rows: tuple[NeighbourRow, ...]
    total: int


def load_graph_data(project: ComparisonProject, root: Path | None, cancel: Cancel) -> GraphData | Failure:
    """Worker: the snapshot, deltas and leads of a project copy. A stored-data problem is a `Failure` value."""
    from ..nway.series import read_raw_matches
    try:
        data = read_project_input(project, root, read_raw_matches)
    except GraphError as exc:
        return Failure(exc.code, exc.message)
    return load_from_input(data, project, cancel)


def load_from_input(data: ProjectInput, project: ComparisonProject, cancel: Cancel) -> GraphData | Failure:
    try:
        snapshot = build_snapshot(data, cancel=cancel)
        deltas = compute_deltas(snapshot, DeltaContext(diff_types=diff_types_by_match(project)), cancel)
        leads = build_leads(snapshot, deltas, None, cancel)
    except GraphError as exc:
        return Failure(exc.code, exc.message)
    return GraphData(snapshot, deltas, leads, data.raw.status != 'ok')


def seed_label(data: GraphData, spec: QuerySpec) -> str | None:
    delta = next((d for d in data.deltas if d.match_id == spec.match_id), None)
    if delta is None:
        return None
    return delta.newer_label if spec.side == 'newer' else delta.older_label


def query(data: GraphData, spec: QuerySpec, cancel: Cancel) -> Neighbourhood | Failure | None:
    """Worker: the bounded neighbourhood of the seed row. None means the seed has no node on this side."""
    label = seed_label(data, spec)
    if label is None:
        return None
    try:
        focus = find_node(data.snapshot, spec.side, label)
        view = neighbourhood(data.snapshot, spec.side, [focus.id], spec.direction, spec.depth,
                             NEIGHBOUR_NODES, NEIGHBOUR_EDGES, cancel)
        view = _without_unresolved(view) if not spec.show_unresolved else view
        delta = next((d for d in data.deltas if d.match_id == spec.match_id), None)
        pairings = {n.id: _pairing(data.snapshot, spec.side, n.id) for n in view.nodes}
        rows, total = neighbour_rows(view, focus.id, delta=delta, pairings=pairings)
    except GraphError as exc:
        return Failure(exc.code, exc.message)
    return Neighbourhood(spec, view, focus.id, rows, total)


def _pairing(snapshot: CallSnapshot, side: Side, node_id: str) -> Pairing:
    return partner(snapshot, side, node_id)


def _without_unresolved(view: GraphView) -> GraphView:
    keep = {n.id for n in view.nodes if n.kind not in ('label-only', 'external')}
    return view.model_copy(update={
        'nodes': tuple(n for n in view.nodes if n.id in keep),
        'edges': tuple(e for e in view.edges if e.src in keep and e.dst in keep)})


def layers(found: Neighbourhood) -> dict[str, int]:
    """Signed hop layer of each node: callers negative, callees positive, the seed 0. Deterministic."""
    by_id = {r.node_id: r for r in found.rows}
    out = {found.focus_id: 0}
    for node in found.view.nodes:
        row = by_id.get(node.id)
        if row is not None:
            out[node.id] = -row.hops if row.relation == 'Caller' else row.hops
    return out


def positions(found: Neighbourhood) -> dict[str, tuple[float, float]]:
    """Layer columns left to right, rows ordered by (label, id); no randomness, no sweeps needed."""
    layer_of = layers(found)
    names = {n.id: one_line(n.label) for n in found.view.nodes}
    columns: dict[int, list[str]] = {}
    for node_id, layer in layer_of.items():
        columns.setdefault(layer, []).append(node_id)
    out: dict[str, tuple[float, float]] = {}
    for layer, ids in columns.items():
        for row, node_id in enumerate(sorted(ids, key=lambda i: (names.get(i, ''), i))):
            out[node_id] = (layer * LAYER_X, row * ROW_Y)
    return out
