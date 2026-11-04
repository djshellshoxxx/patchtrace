"""SPEC-31 07 audit (gui card): hostile settings, out-of-range model queries, and the lifecycle of a run that is
superseded after its worker finished. Offscreen Qt; every result is made up in code."""
from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
from qt_support import main_window, settings  # noqa: F401  (the fixtures are used by name)
from unified_read_support import make_row, publish, request

import patchtrace.ui_unified as ui_unified
from patchtrace.gui.tips import register_tips
from patchtrace.ui_unified import UnifiedTableModel
from patchtrace.unified import read_model
from patchtrace.unified.panel import TEMPLATES, TIPS
from patchtrace.unified.read_model import load_unified


@pytest.fixture(autouse=True)
def tips():
    register_tips(TIPS, TEMPLATES)


def wait_for(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.005)
    assert condition()


def test_hostile_column_width_settings_are_ignored_not_fatal():
    huge = 'function:' + '9' * 5000          # int() raises ValueError past 4,300 digits
    assert read_model.parse_column_widths([huge, 'change:٣٣٣', 'decision:0000000064', 'function:120']) == {'function': 120}


def test_the_table_model_answers_out_of_range_queries_with_none(tmp_path):
    rows = [make_row([(0x1000, 'f')], [(0x1080, 'f')], materiality='material', match_id='m1')]
    vm = load_unified(request(publish(tmp_path / 'r', rows), extraction_configured=True))
    model = UnifiedTableModel()
    model.set_view_model(vm)
    count = model.columnCount()
    for column in (-1, count, count + 40):
        for role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.AccessibleTextRole,
                     ui_unified.ROW_ROLE):
            assert model.data(model.createIndex(0, column), role) is None
        assert model.headerData(column, Qt.Orientation.Horizontal) is None
    assert model.headerData(0, Qt.Orientation.Horizontal) == 'Function'


def test_a_run_whose_result_is_dropped_after_the_worker_finished_leaves_no_staged_directory(
        main_window, tmp_path, monkeypatch):  # noqa: F811
    window = main_window
    assert window.panels.show_panel('unified') is not None
    controller = window.panels.controller('unified')
    controller.settings.set('enabled', True)
    controller.engine_busy = lambda: False
    staged = tmp_path / 'staged'
    finished = threading.Event()

    def execute(request_, token, report):
        staged.mkdir()
        (staged / 'part').write_bytes(b'x')
        finished.set()
        return SimpleNamespace(staged=staged)

    monkeypatch.setattr(ui_unified.pipeline, 'capture_request', lambda service, options: object())
    monkeypatch.setattr(ui_unified.pipeline, 'resolve_request', lambda captured, cancel, previous: object())
    monkeypatch.setattr(ui_unified.pipeline, 'execute', execute)
    controller.start_run()
    deadline = time.monotonic() + 5
    while not finished.is_set() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert finished.is_set()
    controller.cancel_run()                     # before the GUI thread saw the finished worker: the result is dropped
    wait_for(lambda: not controller.tasks.busy('unified-run'))
    for _ in range(20):
        QApplication.processEvents()
        time.sleep(0.005)
    assert not staged.exists()


def test_an_unexpected_capture_failure_shows_a_failure_instead_of_leaving_the_panel_loading(
        main_window, monkeypatch):  # noqa: F811
    window = main_window
    assert window.panels.show_panel('unified') is not None
    controller = window.panels.controller('unified')
    controller.settings.set('enabled', True)
    controller.engine_busy = lambda: False

    def boom(*_args, **_kwargs):
        raise KeyError('older')

    monkeypatch.setattr(ui_unified.pipeline, 'capture_plan', boom)
    controller.reload()
    assert 'PT-UNIFIED-INTERNAL: KeyError' in controller.panel.status.full_text()
    monkeypatch.setattr(ui_unified.pipeline, 'capture_request', boom)
    controller.start_run()
    assert 'PT-UNIFIED-INTERNAL: KeyError' in controller.panel.status.full_text()
    assert controller.panel.retry_button.isVisibleTo(controller.panel)
