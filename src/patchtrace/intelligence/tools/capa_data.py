"""Qt-free data side of the Capabilities panel (CAP-6a): what the GUI thread reads from the project, what a worker
assembles from it, and the table description. The project database belongs to the GUI thread (its connection is
thread-bound), so `read_stored` runs there and `assemble` and `prepare` get only immutable values."""
from __future__ import annotations

from dataclasses import dataclass

from ...gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from ...gui.text import sanitize_text
from .capa_pairs import PairCapabilityDelta, PairGroup, compute_pairs, groups_from_project
from .capa_view import Arrangement, CapabilityView, RunInfo, ViewOptions, ViewRow, rule_hashes
from .common import ToolError, ToolEvidenceSet, ToolRun

SIDES = ('older', 'newer')
Found = tuple[ToolRun, ToolEvidenceSet | None] | None


@dataclass(frozen=True, slots=True)
class Stored:
    """The newest produced capa run per side, the diec results for the quality flags and the pair groups
    (None: no completed analysis, so pairing is unavailable)."""
    capa: tuple[Found, Found]
    diec: tuple[ToolEvidenceSet | None, ToolEvidenceSet | None]
    groups: tuple[PairGroup, ...] | None
    project: str
    analysis_run_id: str


@dataclass(frozen=True, slots=True)
class Assembled:
    view: CapabilityView
    delta: PairCapabilityDelta
    unchanged: bool


@dataclass(frozen=True, slots=True)
class FlatRow:
    """One table row: the view row under one group (a row can sit in several groups when grouped by label)."""
    key: str
    group: str
    row: ViewRow


def _groups(service, latest) -> tuple[PairGroup, ...] | None:
    from ...nway.contracts import NwayError
    from ...nway.series import current_run_id, read_raw_matches
    project = service.project
    bases = tuple(latest[side][1].image_base for side in SIDES)
    if current_run_id(project) is None or not all(bases):
        return None
    try:
        raw, _notes = read_raw_matches(service.root, project)
    except NwayError as exc:
        raise ToolError('PT-TOOL-STORE', str(exc)) from None
    return tuple(groups_from_project(project.matches, raw, bases))


def read_stored(service, project) -> Stored:
    """GUI thread: stored capa and diec evidence (hash-checked sidecars) and the pair groups. Raises `ToolError`."""
    from ...enrichment.storage import EnrichmentStore
    from ...nway.series import current_run_id
    from .store import ToolStore
    tools = ToolStore(EnrichmentStore(service.store), service.root, project.id, project.revision)
    capa = tuple(tools.latest('capa', side) for side in SIDES)
    diec = tuple((found[1] if (found := tools.latest('diec', side)) else None) for side in SIDES)
    both = all(found is not None and found[1] is not None for found in capa)
    groups = _groups(service, {side: found for side, found in zip(SIDES, capa, strict=True)}) if both else None
    return Stored(capa, diec, groups, project.id, current_run_id(project) or '')


def missing_side(stored: Stored) -> str | None:
    """The side that has no produced capa result while the other has one (a half-finished run), else None."""
    have = [found is not None and found[1] is not None for found in stored.capa]
    return None if all(have) or not any(have) else SIDES[have.index(False)]


def has_results(stored: Stored | None) -> bool:
    return stored is not None and any(found is not None for found in stored.capa)


def assemble(stored: Stored, unchanged: bool, token=None) -> Assembled:
    """Worker: compute the pair delta and the view. Raises `ToolError` (shown as C6 with its code)."""
    from .delta import quality_flags
    (older_run, older), (newer_run, newer) = stored.capa
    flags = quality_flags(stored.diec, (older, newer))
    delta = compute_pairs(older_run, older, newer_run, newer, stored.groups, flags=flags, include_unchanged=unchanged)
    if token is not None:
        token.raise_if_cancelled()
    info = RunInfo(sanitize_text(stored.project, 80), sanitize_text(stored.analysis_run_id, 80), False, older_run,
                   newer_run)
    view = CapabilityView(delta, stored.groups or (), rule_hashes(older.capabilities, newer.capabilities), info)
    return Assembled(view, delta, unchanged)


COLUMNS = (
    ColumnSpec('capability', 'Capability', lambda r: r.row.rule or 'Unnamed rule', width_em=30,
               accessible=lambda r: CapabilityView.accessible_text(r.row)),
    ColumnSpec('older', 'Older', lambda r: r.row.older, width_em=22),
    ColumnSpec('newer', 'Newer', lambda r: r.row.newer, width_em=22),
    ColumnSpec('change', 'Change', lambda r: r.row.status, width_em=18),
    ColumnSpec('pair', 'Function pair (older to newer)', lambda r: r.row.pair or 'Not attributed to a function',
               width_em=34),
    ColumnSpec('group', 'Group', lambda r: r.group, width_em=26))
SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.row.haystack)


def flatten(arrangement: Arrangement) -> tuple[FlatRow, ...]:
    return tuple(FlatRow(f'{group.key}\x1f{row.change.change_id}', group.label, row)
                 for group in arrangement.groups for row in group.rows)


def needs_unchanged(options: ViewOptions) -> bool:
    return options.filter in ('unchanged', 'all')


def prepare(view: CapabilityView, options: ViewOptions, token=None) -> tuple[Arrangement, PreparedTable]:
    """Worker: arrange and prepare the table (a search is applied by the table itself, so it never recomputes)."""
    arrangement = view.arrange(options)
    return arrangement, prepare_table(SPEC, COLUMNS, flatten(arrangement), token)
