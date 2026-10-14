# ruff: noqa: F811
"""The evidence panel on the panel host (GUI plan 8.10, steps M1 and M2). Offscreen, hermetic."""
from __future__ import annotations

import subprocess
import sys

import pytest
from qt_support import join_gui_threads, main_window, settings  # noqa: F401

from patchtrace.gui.registry import lint
from patchtrace.panel_manifest import MANIFEST
from patchtrace.secondary.evidence_panel import PANEL
from patchtrace.ui_evidence import EvidenceController


def test_the_spec_matches_its_manifest_slot_and_lints_clean():
    slot = next(entry for entry in MANIFEST if entry.id == 'evidence')
    loaded = type('Loaded', (), {'specs': {'evidence': PANEL}, 'forbidden': {}})()
    assert (PANEL.area, PANEL.tabify_with, PANEL.shortcut) == (slot.area, slot.tabify_with, slot.shortcut)
    assert PANEL.eager and not [f for f in lint(MANIFEST, loaded).findings if f.panel == 'evidence']


def test_loading_the_spec_imports_no_qt():
    code = 'import sys, patchtrace.secondary.evidence_panel; sys.exit(int("PySide6" in sys.modules))'
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_the_host_builds_the_controller_at_start_without_work(main_window):
    host = main_window.panels
    controller = host.controller('evidence')
    assert isinstance(controller, EvidenceController) and host.problems == []
    assert controller.dock.objectName() == 'evidence.dock' and not host.is_shown('evidence')
    assert controller.load_thread is None and controller.probe_thread is None and controller.generation == 0


def test_the_window_has_no_evidence_attribute_and_the_menu_entry_is_the_hosts(main_window):
    assert not hasattr(main_window, 'evidence')
    action = main_window.panels.toggle_action('evidence')
    assert action.shortcut().toString() == 'Ctrl+Shift+E' and action.text() == 'Engine evidence'
    analysis = next(a.menu() for a in main_window.menuBar().actions() if a.text() == 'Analysis')
    assert action not in analysis.actions()


def test_showing_the_panel_loads_it_and_the_selection_is_forwarded(main_window, qtbot, monkeypatch):
    host = main_window.panels
    controller = host.controller('evidence')
    controller.auto_probe = False
    host.show_panel('evidence')
    qtbot.waitUntil(lambda: controller.panel.vm.state != 'no-project' and not controller.panel.loading, timeout=5000)
    seen = []
    monkeypatch.setattr(controller.panel, 'select_match', seen.append)
    controller.selection_changed(None)
    controller.selection_changed('m1')
    assert seen == ['m1']


def test_the_legacy_dock_geometry_is_read_once_when_no_layout_was_saved(main_window):
    controller = main_window.panels.controller('evidence')
    settings_ = main_window.settings
    settings_.remove('layout/state')
    settings_.setValue('evidence/geometry', main_window.panels.panels['evidence'].dock.saveGeometry())
    controller._legacy_geometry_done = False
    controller.project_changed(None)
    assert not settings_.contains('evidence/geometry') and controller._legacy_geometry_done


def test_a_saved_layout_wins_over_the_legacy_geometry(main_window):
    controller = main_window.panels.controller('evidence')
    settings_ = main_window.settings
    settings_.setValue('layout/state', b'x')
    settings_.setValue('evidence/geometry', main_window.panels.panels['evidence'].dock.saveGeometry())
    controller._legacy_geometry_done = False
    controller.project_changed(None)
    assert settings_.contains('evidence/geometry')


@pytest.mark.parametrize('busy, reason', [(True, 'Ghidriff analysis job'), (False, '')], ids=['busy', 'idle'])
def test_busy_changes_gate_the_run_button(main_window, busy, reason, monkeypatch):
    controller = main_window.panels.controller('evidence')
    monkeypatch.setattr(controller.port, 'busy', lambda: busy)
    controller.busy_changed(busy)
    blocked = controller.panel.run_blocked_reason
    assert (reason in blocked) if reason else blocked == ''
