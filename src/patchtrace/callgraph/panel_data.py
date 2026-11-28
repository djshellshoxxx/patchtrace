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
from .dot import render_dot
from .export_json import GraphExport, default_name
from .layout import Layout, layout_view
from .leads import build_leads
from .limits import GraphError
from .project_input import ProjectInput, read_project_input
from .query import QueryDirection, find_node, neighbourhood, partner
from .snapshot import CallSnapshot, build_snapshot
from .view_model import NeighbourRow, neighbour_rows

Cancel = Callable[[], bool]
NEIGHBOUR_NODES = 500   # normal cap of the spec (the default query is 100)
NEIGHBOUR_EDGES = 2_000


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
    diagram: Layout | Failure


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
        diagram = _diagram(view, focus.id, cancel)
    except GraphError as exc:
        return Failure(exc.code, exc.message)
    return Neighbourhood(spec, view, focus.id, rows, total, diagram)


def _diagram(view: GraphView, focus: str, cancel: Cancel) -> Layout | Failure:
    """A drawing limit must not discard the complete queried graph or its textual evidence."""
    try:
        return layout_view(view, focus, cancel=cancel)
    except GraphError as exc:
        if exc.code == 'PT-GRAPH-CANCEL':
            raise
        return Failure(exc.code, exc.message)


def _pairing(snapshot: CallSnapshot, side: Side, node_id: str) -> Pairing:
    return partner(snapshot, side, node_id)


def _without_unresolved(view: GraphView) -> GraphView:
    keep = {n.id for n in view.nodes if n.kind not in ('label-only', 'external')}
    return view.model_copy(update={
        'nodes': tuple(n for n in view.nodes if n.id in keep),
        'edges': tuple(e for e in view.edges if e.src in keep and e.dst in keep)})


def layers(found: Neighbourhood) -> dict[str, int]:
    """Read the completed worker geometry; this never runs layout on a UI caller."""
    return {n.id: n.layer for n in found.diagram.nodes} if isinstance(found.diagram, Layout) else {}


def positions(found: Neighbourhood) -> dict[str, tuple[float, float]]:
    """Cached centres in normalized layout units; the GUI applies its actual font metrics."""
    return ({n.id: (n.x + n.w / 2, n.y + n.h / 2) for n in found.diagram.nodes}
            if isinstance(found.diagram, Layout) else {})


def diagram_notice(found: Neighbourhood) -> str:
    """Drawing-only limitations, independent of the source graph's truncation and more markers."""
    diagram = found.diagram
    if isinstance(diagram, Failure):
        return f'Diagram unavailable: {diagram.message}. Use the Neighbours table or narrow the depth.'
    reasons = {'nodes': 'nodes at the drawing limit', 'depth': 'nodes beyond the drawing depth',
               'disconnected': 'disconnected nodes', 'long-edges': 'long call routes at the drawing limit'}
    if not diagram.notes:
        return ''
    omissions = '; '.join(f'{note.dropped:,} {reasons[note.kind]}' for note in diagram.notes)
    return f'Diagram omits {omissions}. The Neighbours table and export retain the queried graph.'


# ---- DOT export of what is shown (docs/specs/panels/graph-inspection.md section 1) -------------------------------


def dot_export(data: GraphData, found: Neighbourhood) -> GraphExport:
    """The visible neighbourhood as a one-sided `GraphExport`; nothing outside the shown view is added."""
    ids = data.snapshot.data
    view = found.view
    shown = {found.spec.side: view}
    return GraphExport(
        project_id=ids.project_id, run_id=ids.run_id, match_id=found.spec.match_id, older_sha256=ids.older_sha256,
        newer_sha256=ids.newer_sha256, older=shown.get('older'), newer=shown.get('newer'), truncated=view.truncated,
        limitations=view.limitations)


def dot_text(data: GraphData, found: Neighbourhood) -> str:
    """DOT text of the visible graph. Raises `GraphError` (PT-GRAPH-EXPORT) over the size cap."""
    return render_dot(dot_export(data, found))


def dot_name(text: str) -> str:
    """Suggested file name: derived from the content, never from function names."""
    return default_name(text, 'dot')
