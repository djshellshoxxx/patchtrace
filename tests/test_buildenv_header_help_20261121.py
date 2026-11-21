"""Build environment: real Qt column-header help and unchanged prepared table data."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from PySide6.QtCore import Qt

from patchtrace import tooltips
from patchtrace.buildenv.panel_model import COLUMNS, SPEC
from patchtrace.buildenv.tooltip_entries import TEMPLATES, TIPS
from patchtrace.gui.qt.table import VirtualTable
from patchtrace.gui.table_spec import prepare_table
from patchtrace.gui.tips import register_tips

HEADERS = (
    ("fact", "Fact", "build_env.col.fact"),
    ("older", "OLDER", "build_env.col.older"),
    ("newer", "NEWER", "build_env.col.newer"),
    ("status", "Status", "build_env.col.status"),
    ("basis", "Basis", "build_env.col.basis"),
)


def _rows():
    return (
        SimpleNamespace(
            key="compiler", label="Compiler", older="MSVC", newer="Clang",
            status="differs", basis="signature",
        ),
        SimpleNamespace(
            key="subsystem", label="Subsystem", older="console", newer="console",
            status="matches", basis="PE field",
        ),
    )


def test_all_five_build_environment_headers_bind_registered_descriptions():
    assert tuple((column.key, column.title, column.tip_id) for column in COLUMNS) == HEADERS
    for _, _, tip_id in HEADERS:
        assert tip_id in TIPS


def test_actual_build_environment_header_roles_preserve_cell_values_and_identity(qtbot):
    register_tips(TIPS, TEMPLATES)
    table = VirtualTable("Build facts table")
    qtbot.addWidget(table)
    table.set_prepared(prepare_table(SPEC, COLUMNS, _rows()))
    table.show()
    model = table.table_model
    assert table.horizontalHeader().count() == len(HEADERS)
    assert model.rowCount() == 2
    for index, (_, title, tip_id) in enumerate(HEADERS):
        assert model.headerData(index, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole) == title
        assert model.headerData(index, Qt.Orientation.Horizontal, Qt.ItemDataRole.AccessibleTextRole) == title
        assert model.headerData(index, Qt.Orientation.Horizontal, Qt.ItemDataRole.ToolTipRole) == (
            tooltips.tooltip(tip_id)
        )
    assert [model.key_at(row) for row in range(2)] == ["compiler", "subsystem"]
    assert model.texts_at(0) == ("Compiler", "MSVC", "Clang", "differs", "signature")
    assert model.texts_at(1) == ("Subsystem", "console", "console", "matches", "PE field")
    table.set_filter("compiler")
    assert model.rowCount() == 1
    assert model.key_at(0) == "compiler"
    assert model.texts_at(0) == ("Compiler", "MSVC", "Clang", "differs", "signature")


def test_missing_single_header_id_reverts_to_plain_text_and_is_detectable(qtbot):
    register_tips(TIPS, TEMPLATES)
    altered = tuple(replace(column, tip_id="") if column.key == "basis" else column for column in COLUMNS)
    table = VirtualTable("Build facts table")
    qtbot.addWidget(table)
    table.set_prepared(prepare_table(SPEC, altered, _rows()))
    model = table.table_model
    role = Qt.ItemDataRole.ToolTipRole
    assert model.headerData(4, Qt.Orientation.Horizontal, role) == "Basis"
    assert model.headerData(4, Qt.Orientation.Horizontal, role) != tooltips.tooltip("build_env.col.basis")
