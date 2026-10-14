"""Regression tests for safe, attributable PE inspection row tooltips."""
from __future__ import annotations

import html
from types import SimpleNamespace

from PySide6.QtWidgets import QTableWidget

from patchtrace.ui_inspection import fill_pe_table


def _result(rows, *, trust=None, error=None):
    return SimpleNamespace(
        comparisons=rows,
        sides={
            side: SimpleNamespace(overview=None if error else object(),
                                  error_code="inspection_error" if error else None,
                                  error=error, trust=trust)
            for side in ("older", "newer")
        },
    )


def test_pe_row_tooltips_escape_untrusted_binary_metadata(qtbot):
    data = SimpleNamespace(
        field="Section <b>name</b>", older="a", newer="b",
        status="changed", provenance="<img src=x onerror=alert(1)>",
        reason="<script>alert(1)</script>",
    )
    table = QTableWidget()
    qtbot.addWidget(table)
    fill_pe_table(table, _result((data,)))
    tip = table.item(0, 0).toolTip()
    assert "What:" in html.unescape(tip)
    assert "Source:" in html.unescape(tip)
    assert "<script>" not in tip
    assert "<img " not in tip
    assert "&lt;script&gt;" in tip
    assert "&lt;img" in tip


def test_failed_pe_inspection_has_complete_explanatory_row(qtbot):
    table = QTableWidget()
    qtbot.addWidget(table)
    fill_pe_table(table, _result((), error="<b>bad input</b>"))
    assert table.columnCount() == 5
    assert table.rowCount() == 1
    assert all(table.item(0, column) is not None for column in range(5))
    assert "<b>bad" in table.item(0, 1).text()
    tip = table.item(0, 1).toolTip()
    assert "What:" in html.unescape(tip)
    assert "<b>" not in tip
    assert "&lt;b&gt;" in tip


def test_authenticode_row_tooltip_escapes_diagnostic(qtbot):
    trust = SimpleNamespace(status="untrusted", detail="<i>untrusted provider detail</i>")
    table = QTableWidget()
    qtbot.addWidget(table)
    fill_pe_table(table, _result((), trust=trust))
    tip = table.item(table.rowCount() - 1, 0).toolTip()
    assert "What:" in html.unescape(tip)
    assert "<i>" not in tip
    assert "&lt;i&gt;" in tip
