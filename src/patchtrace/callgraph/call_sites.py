"""Qt-free call edges and call-site rows of the Calls panel (docs/specs/panels/graph-inspection.md section 2).

An edge row is one observed call (caller to callee) in the visible neighbourhood. A call-site row is one line of the
caller's stored decompiled text whose identifier token equals the callee: a text match, never a machine instruction
address. Addresses shown are function entry addresses as Ghidriff lists them (one side only)."""
from __future__ import annotations

from dataclasses import dataclass

from ..models import ComparisonProject
from .contracts import GraphEdge, GraphNode, GraphView
from .text import one_line
from .view_model import CALLSITE_FOUND, CALLSITE_MISSING, find_call_sites

CALLSITE_ROW_CAP = 50
ROW_TEXT_LIMIT = 160
EDGE_ROW_CAP = 2_000
NO_CODE_TEXT = 'No decompiled text is stored for the caller.'
UNKNOWN = 'Unknown'

EDGE_COLUMNS = ('Caller', 'Callee', 'Caller entry', 'Callee entry', 'Basis')
CALLSITE_COLUMNS = ('Line', 'Text')


def address_text(address: int | None) -> str:
    """Function entry address as hex; a missing address is Unknown, never zero."""
    return UNKNOWN if address is None else f'0x{address:x}'


@dataclass(frozen=True)
class EdgeRow:
    edge_id: str
    caller_id: str
    callee_id: str
    caller: str
    callee: str
    caller_address: str
    callee_address: str
    basis: str
    accessible: str


def edge_cell(row: EdgeRow, column: int) -> str:
    return (row.caller, row.callee, row.caller_address, row.callee_address, row.basis)[column]


def _basis(edge: GraphEdge) -> str:
    return 'Listed by both ends' if len(set(edge.support)) > 1 else 'Listed by one end'


def _edge_row(edge: GraphEdge, nodes: dict[str, GraphNode]) -> EdgeRow | None:
    caller, callee = nodes.get(edge.src), nodes.get(edge.dst)
    if caller is None or callee is None:
        return None
    names = (one_line(caller.label), one_line(callee.label))
    addresses = (address_text(caller.address), address_text(callee.address))
    basis = _basis(edge)
    spoken = f'{names[0]} calls {names[1]}, caller entry {addresses[0]}, callee entry {addresses[1]}, {basis.lower()}'
    return EdgeRow(edge.id, caller.id, callee.id, names[0], names[1], addresses[0], addresses[1], basis, spoken)


def edge_rows(view: GraphView, node_id: str, cap: int = EDGE_ROW_CAP) -> tuple[tuple[EdgeRow, ...], int]:
    """(rows, total): the edges of `view` that touch `node_id`, sorted by (caller, callee, edge id)."""
    nodes = {n.id: n for n in view.nodes}
    rows = [row for edge in view.edges if node_id in (edge.src, edge.dst)
            if (row := _edge_row(edge, nodes)) is not None]
    rows.sort(key=lambda r: (r.caller, r.callee, r.edge_id))
    return tuple(rows[:cap]), len(rows)


@dataclass(frozen=True)
class CallSiteRow:
    line: int
    text: str
    accessible: str


@dataclass(frozen=True)
class CallSiteView:
    rows: tuple[CallSiteRow, ...]
    total: int
    message: str  # empty when at least one line matched


def call_site_view(code: str | None, callee: str, cap: int = CALLSITE_ROW_CAP) -> CallSiteView:
    """The lines of `code` that name `callee`; an empty result says why in `message`."""
    if not code:
        return CallSiteView((), 0, NO_CODE_TEXT)
    found = find_call_sites(code, callee)
    if not found:
        return CallSiteView((), 0, CALLSITE_MISSING)
    rows = tuple(CallSiteRow(number, one_line(line.strip(), ROW_TEXT_LIMIT),
                             f'line {number}, {CALLSITE_FOUND}: {one_line(line.strip(), ROW_TEXT_LIMIT)}')
                 for number, line in found[:cap])
    return CallSiteView(rows, len(found), '')


def callsite_cell(row: CallSiteRow, column: int) -> str:
    return (str(row.line), row.text)[column]


def function_code(project: ComparisonProject, function_id: str) -> str | None:
    """Stored decompiled text of one function record of the latest completed run, or None."""
    run = next((r for r in reversed(project.runs) if r.status == 'completed'), None)
    if run is None:
        return None
    for match in project.matches:
        if match.run_id != run.id:
            continue
        for record in (*match.older, *match.newer):
            if record.id == function_id:
                return record.code
    return None
