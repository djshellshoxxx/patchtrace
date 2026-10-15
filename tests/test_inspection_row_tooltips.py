"""Regression tests for safe, attributable PE inspection row tooltips."""
from __future__ import annotations

import html
from types import SimpleNamespace

from PySide6.QtCore import Qt

from patchtrace.ui_inspection import RowsModel, pe_rows

TIP = Qt.ItemDataRole.ToolTipRole


def _model(result):
    model = RowsModel(('Field', 'Older', 'Newer', 'Status', 'Source'))
    model.set_rows(pe_rows(result))
    return model


def _tip(model, row, column=0):
    return model.data(model.index(row, column), TIP)


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


def test_pe_row_tooltips_escape_untrusted_binary_metadata():
    data = SimpleNamespace(
        field="Section <b>name</b>", older="a", newer="b",
        status="changed", provenance="<img src=x onerror=alert(1)>",
        reason="<script>alert(1)</script>",
    )
    model = _model(_result((data,)))
    tip = _tip(model, 0)
    assert "What:" in html.unescape(tip)
    assert "Source:" in html.unescape(tip)
    assert "<script>" not in tip
    assert "<img " not in tip
    assert "&lt;script&gt;" in tip
    assert "&lt;img" in tip


def test_failed_pe_inspection_has_complete_explanatory_row():
    model = _model(_result((), error="<b>bad input</b>"))
    assert model.columnCount() == 5
    assert model.rowCount() == 1
    assert all(model.data(model.index(0, column)) is not None for column in range(5))
    assert "<b>bad" in model.data(model.index(0, 1))
    tip = _tip(model, 0, 1)
    assert "What:" in html.unescape(tip)
    assert "<b>" not in tip
    assert "&lt;b&gt;" in tip


def test_authenticode_row_tooltip_escapes_diagnostic():
    trust = SimpleNamespace(status="untrusted", detail="<i>untrusted provider detail</i>")
    model = _model(_result((), trust=trust))
    tip = _tip(model, model.rowCount() - 1)
    assert "What:" in html.unescape(tip)
    assert "<i>" not in tip
    assert "&lt;i&gt;" in tip
