"""Pure `VirtualTable` description of the evidence panel (GUI plan 8.4; C6 spec §6). No Qt.

`prepare_evidence_table` runs in the load worker, so the GUI thread only swaps the prepared table in. Column
titles and units come from the view-model's engines; tooltips go through the escaping registry templates."""
from __future__ import annotations

from typing import Any

from ..gui.table_spec import ColumnSpec, PreparedTable, TableSpec, prepare_table
from ..tooltips import template
from .evidence_view import (
    ENGINE_COLUMNS,
    ENGINE_NAMES,
    ENGINE_UNITS,
    VERDICT_MEANING,
    VERDICT_PRIORITY,
    EvidenceRow,
    EvidenceViewModel,
    format_cell_detail,
)

COLUMN_EMS = {0: 28, 1: 16}
ENGINE_EMS = 18
SPEC = TableSpec(row_key=lambda row: row.match_id, search_text=lambda row: row.search_key,
                 default_order=lambda row: (VERDICT_PRIORITY[row.verdict], row.order))


def evidence_rows(vm: EvidenceViewModel) -> tuple[EvidenceRow, ...]:
    return vm.rows + vm.engine_only


def evidence_columns(vm: EvidenceViewModel) -> tuple[ColumnSpec, ...]:
    """Match, verdict, then one column per engine (its native value; ghidriff has no numeric score)."""
    engines = ', '.join(info.label for info in vm.engines)

    def row_tip(row: EvidenceRow) -> str:
        return template('evidence.row', function=row.function_label, verdict=row.verdict_text, engines=engines,
                        reason=row.address_label)

    def badge_tip(row: EvidenceRow) -> str:
        return template('evidence.badge', verdict=row.verdict_text, meaning=VERDICT_MEANING[row.verdict],
                        reason=row.reason)

    def spoken(row: EvidenceRow) -> str:
        values = ', '.join(f'{ENGINE_NAMES[c.engine]} {c.text}' for c in row.cells)
        return f'{row.function_label}, verdict {row.verdict_text}, {values}'

    columns = [
        ColumnSpec('match', 'Match / function', lambda row: row.function_label, 'name, older > newer address',
                   COLUMN_EMS[0], accessible=spoken, tooltip=row_tip),
        ColumnSpec('verdict', 'Verdict', lambda row: row.verdict_text, 'function pairing only', COLUMN_EMS[1],
                   sort_key=lambda row: VERDICT_PRIORITY[row.verdict],
                   accessible=lambda row: f'Verdict: {row.verdict_text}', tooltip=badge_tip),
    ]
    for position, engine in enumerate(ENGINE_COLUMNS):
        columns.append(_engine_column(vm, position, engine))
    return tuple(columns)


def _engine_column(vm: EvidenceViewModel, position: int, engine: str) -> ColumnSpec:
    info = vm.engine(engine)
    provenance = info.label if info else engine

    def cell_tip(row: EvidenceRow) -> str:
        cell = row.cells[position]
        return template('evidence.cell', engine=ENGINE_NAMES[engine], value=cell.text, unit=ENGINE_UNITS[engine],
                        provenance=provenance, reason=format_cell_detail(cell).replace('\n', ' | '))

    # That ONE engine's native milli; rows without a value sort last in both directions. Ghidriff has no numeric
    # match score: it sorts alphabetically by its text.
    sort_key = None if engine == 'ghidriff' else (lambda row: row.cells[position].sort_key)
    return ColumnSpec(engine, provenance if info else ENGINE_NAMES[engine], lambda row: row.cells[position].text,
                      ENGINE_UNITS[engine], ENGINE_EMS, sort_key=sort_key,
                      accessible=lambda row: row.cells[position].accessible, tooltip=cell_tip)


def prepare_evidence_table(vm: EvidenceViewModel, token: Any = None) -> PreparedTable:
    return prepare_table(SPEC, evidence_columns(vm), evidence_rows(vm), token)
