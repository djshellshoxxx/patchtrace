"""SPEC-31 U4: the Unified panel over the REAL pipeline, no fakes on the run path. A synthetic project (two tiny PEs and the
stored Ghidriff document of the S0 tests) with hand-assembled ProgramIR sidecars; the Run button prepares, executes
(worker child process, or in process when the platform forbids it) and publishes on the real code, and the panel then shows
what the product stored. Offscreen Qt. Synthetic data: nothing here is live evidence."""
from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QApplication
from qt_support import settings, top_level_windows  # noqa: F401  (the fixture is used by name)
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

import patchtrace.ui_unified as ui_unified
from patchtrace.gui.tips import register_tips
from patchtrace.ui import MainWindow
from patchtrace.unified import pipeline
from patchtrace.unified.panel import TEMPLATES, TIPS


@pytest.fixture(autouse=True)
def tips():
    register_tips(TIPS, TEMPLATES)


def wait_for(condition, seconds=60.0):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    assert condition()


@pytest.fixture
def real(qtbot, tmp_path, settings):  # noqa: F811
    service = make_project(tmp_path / 'project')
    place_pair(service, scratch=tmp_path)
    window = MainWindow(service, settings, tmp_path / 'profiles')
    qtbot.addWidget(window)
    window.show()
    assert window.panels.show_panel('unified') is not None
    controller = window.panels.controller('unified')
    controller.settings.set('enabled', True)
    controller.engine_busy = lambda: False
    yield window, controller, service
    window.close()
    if window.service:
        window.service.close()
        window.service = None


def run_to_result(controller):
    controller.reload()
    wait_for(lambda: controller.vm is not None and controller.vm.state == 'U1')      # nothing stored yet
    controller.update_controls()
    assert controller.panel.run_button.isEnabled()
    controller.panel.run_button.click()
    wait_for(lambda: controller.vm is not None and controller.vm.state in ('U3', 'U4') and not controller.tasks.busy('unified-run'))


def test_run_button_publishes_a_real_result_and_the_panel_shows_it(real):
    window, controller, service = real
    before = (service.project.revision, [m.id for m in service.project.matches])
    run_to_result(controller)
    vm = controller.vm
    assert vm.rows and vm.manifest.ir_older is not None and vm.manifest.status in ('complete', 'partial')
    assert controller.panel.table.isVisible() and controller.panel.model.rowCount() >= 1
    names = {r.function_label for r in vm.rows}
    assert any('get_version' in n for n in names) and any('read_item' in n for n in names)
    changed = next(r for r in vm.rows if 'get_version' in r.function_label)
    assert changed.materiality in ('material', 'review') and changed.decision == 'matched'
    assert (service.project.revision, [m.id for m in service.project.matches]) == before    # D-02: derived, apart
    assert top_level_windows() == [window]


def test_a_row_without_a_ghidriff_match_shows_the_stored_disassembly(real):
    window, controller, service = real
    run_to_result(controller)
    shown = []
    controller.nav = SimpleNamespace(show_pair=lambda *args: shown.append(args),
                                     select_match=lambda match_id, clear_filters=False: True)
    row = next(r for r in controller.vm.rows if r.ghidriff_match_id is None and 'keep_same' in r.function_label)
    controller.show_row(row)
    older, newer, label = shown[-1]
    assert 'mov' in older.lower() and 'mov' in newer.lower() and 'ProgramIR' in label
    assert older.splitlines()[0][:8].strip('0123456789abcdef') == ''
    assert ui_unified.NO_PAIR_TEXT not in (older, newer)


def test_explain_on_a_matched_row_opens_the_context_preview_with_the_real_fragment(real, monkeypatch):
    window, controller, service = real
    run_to_result(controller)
    seen = []
    monkeypatch.setattr(window, 'preview_interpretation', lambda *a, notes=(): seen.append(list(notes)))
    row = next(r for r in controller.vm.rows if r.ghidriff_match_id)
    controller.nav = SimpleNamespace(select_match=lambda match_id, clear_filters=False: True)
    controller.explain(row)
    (title, text, omitted), = seen[0]
    assert title.startswith('Unified row') and text and isinstance(omitted, tuple)


def test_a_second_run_reuses_the_stored_result(real):
    _, controller, _ = real
    run_to_result(controller)
    first = controller.vm.result_id
    controller.panel.run_button.click()
    wait_for(lambda: not controller.tasks.busy('unified-run'))
    controller.reload()
    wait_for(lambda: controller.vm is not None and controller.vm.state in ('U3', 'U4'))
    assert controller.vm.result_id == first
    assert pipeline.recent_runs(controller.window.service)
