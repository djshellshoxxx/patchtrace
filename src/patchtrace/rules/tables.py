"""Table layouts of the Detection rules panel and the off-thread build of the big ones. Pure: no Qt (the strings, keys and
order are prepared here so the GUI thread only swaps a pointer)."""
from __future__ import annotations

from dataclasses import dataclass

from ..gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from . import view_model as vm

CANDIDATE_COLUMNS = (
    ColumnSpec('rule', 'Rule', lambda r: r.name, width_em=22),
    ColumnSpec('build', 'Build', lambda r: r.direction, width_em=12),
    ColumnSpec('function', 'Function', lambda r: r.function, width_em=24),
    ColumnSpec('status', 'Status', lambda r: r.status, width_em=18),
    ColumnSpec('checks', 'Checks', lambda r: r.checks, width_em=36),
    ColumnSpec('features', 'Features', lambda r: r.features, width_em=14),
    ColumnSpec('tested', 'Test result', lambda r: r.tested, width_em=34))
CANDIDATE_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.search)
FEATURE_COLUMNS = (
    ColumnSpec('include', 'Include', lambda r: r.include, width_em=8),
    ColumnSpec('kind', 'Kind', lambda r: r.kind, width_em=14),
    ColumnSpec('feature', 'Feature', lambda r: r.feature, width_em=40),
    ColumnSpec('older', 'Older build', lambda r: r.older, width_em=18),
    ColumnSpec('newer', 'Newer build', lambda r: r.newer, width_em=18),
    ColumnSpec('source', 'Source', lambda r: r.source, width_em=24),
    ColumnSpec('where', 'Where', lambda r: r.where, width_em=16))
FEATURE_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.feature)
CHECK_COLUMNS = (
    ColumnSpec('check', 'Check', lambda r: r.check, width_em=30),
    ColumnSpec('state', 'State', lambda r: r.state, width_em=12),
    ColumnSpec('measured', 'Measured', lambda r: r.measured, width_em=24),
    ColumnSpec('basis', 'Basis', lambda r: r.basis, width_em=40))
CHECK_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.check)
SAVED_COLUMNS = (
    ColumnSpec('label', 'Label', lambda r: r.label, width_em=28),
    ColumnSpec('version', 'Version', lambda r: r.version, width_em=10),
    ColumnSpec('tested', 'Test state', lambda r: r.tested, width_em=30),
    ColumnSpec('created', 'Created', lambda r: r.created, width_em=24))
SAVED_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: r.search)
GRID_SPEC = TableSpec(row_key=lambda r: r.key, search_text=lambda r: f'{r.label} {r.role} {r.expectation}')
GRID_FIXED = (
    ColumnSpec('build', 'Build', lambda r: r.build, width_em=8),
    ColumnSpec('label', 'Label', lambda r: r.label, width_em=24),
    ColumnSpec('role', 'Role', lambda r: r.role, width_em=16),
    ColumnSpec('expectation', 'Expectation', lambda r: r.expectation, width_em=20),
    ColumnSpec('advisory', 'Advisory says', lambda r: r.advisory, width_em=24))


def grid_columns(versions: tuple[str, ...]) -> tuple[ColumnSpec, ...]:
    """One column per rule version of the run; the fixed identity columns stay in front."""
    return GRID_FIXED + tuple(ColumnSpec(f'rule{index}', title, lambda r, i=index: r.cells[i], width_em=20)
                              for index, title in enumerate(versions))


@dataclass(frozen=True, slots=True)
class Built:
    """Everything a worker prepared from one immutable `Stored`; the controller applies it or drops it whole."""
    stored: vm.Stored
    candidates: PreparedTable
    saved: PreparedTable
    grid: PreparedTable
    grid_run: str | None


def build(stored: vm.Stored, token=None) -> Built:
    grid = vm.build_grid(stored)
    prepared_grid = (prepare_table(GRID_SPEC, grid_columns(grid.versions), grid.rows, token) if grid
                     else prepare_table(GRID_SPEC, GRID_FIXED, (), token))
    return Built(stored, prepare_table(CANDIDATE_SPEC, CANDIDATE_COLUMNS, vm.candidate_rows(stored), token),
                 prepare_table(SAVED_SPEC, SAVED_COLUMNS, vm.saved_rows(stored), token), prepared_grid,
                 grid.run_id if grid else None)


def empty_table(spec: TableSpec, columns: tuple[ColumnSpec, ...]) -> PreparedTable:
    return prepare_table(spec, columns, ())
