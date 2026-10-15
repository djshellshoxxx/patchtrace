"""The evidence panel's pure table description: columns, keys, default order, sort keys, escaped tooltips."""
from __future__ import annotations

import subprocess
import sys

from test_evidence_view import build

from patchtrace.gui.table_spec import order_by
from patchtrace.secondary.evidence_table import evidence_columns, prepare_evidence_table
from patchtrace.secondary.evidence_view import ENGINE_COLUMNS


def test_the_module_imports_no_qt():
    code = 'import sys, patchtrace.secondary.evidence_table; sys.exit(any(n.startswith("PySide6") for n in sys.modules))'
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_columns_are_match_verdict_then_one_per_engine_with_header_units():
    vm = build()
    columns = evidence_columns(vm)
    assert [c.key for c in columns] == ['match', 'verdict', *ENGINE_COLUMNS]
    assert columns[3].title == 'BinDiff 8' and columns[3].unit == 'similarity / algorithm'
    assert all(c.width_em > 0 for c in columns)


def test_rows_keep_match_ids_as_keys_and_start_in_verdict_priority_order():
    vm = build()
    prepared = prepare_evidence_table(vm)
    rows = vm.rows + vm.engine_only
    assert prepared.total == len(rows) and set(prepared.keys) == {row.match_id for row in rows}
    first = [prepared.rows[i].verdict for i in prepared.order]
    assert first == sorted(first, key=lambda v: ['contested', 'unknown', 'single-engine', 'agree', 'engine-only'].index(v))


def test_engine_column_sort_puts_rows_without_a_value_last_in_both_directions():
    prepared = prepare_evidence_table(build())
    keys = prepared.sort_keys[3]
    assert keys is not None and any(k is None for k in keys)
    for descending in (False, True):
        ordered = order_by(range(prepared.total), keys, descending)
        flags = [keys[i] is None for i in ordered]
        assert flags == sorted(flags)


def test_tooltips_are_escaped_rich_text():
    prepared = prepare_evidence_table(build())
    tip = prepared.columns[0].tooltip(prepared.rows[0])
    assert tip.startswith('<p ') and '<b>' not in tip
