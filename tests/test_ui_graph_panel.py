# ruff: noqa: F811
"""Calls panel (WB2 G5/G6): state matrix, hostile text, accessibility, late results and shutdown (offscreen Qt).

Docs: docs/specs/panels/graph.md (ChatGPT draft, branch chatgpt/panels-1) and docs/specs/gui-framework.md. The controller
is driven through fake panel ports; the data are the synthetic call-graph fixtures, never live evidence."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from callgraph_graph_support import project_and_raw, reader_for
from PySide6.QtWidgets import QApplication
from qt_support import HOSTILE_PARAMS, a11y_audit, join_gui_threads  # noqa: F401

from patchtrace.callgraph import panel_data as pd
from patchtrace.callgraph import view_model as vm
from patchtrace.callgraph.panel import PANEL
from patchtrace.callgraph.panel_qt import CallsController
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.gui import registry
from patchtrace.gui.anchors import NavResult
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.panel_manifest import MANIFEST

SHA = 'a' * 64


class FakeProject:
    def __init__(self, fixture: str = 'svc_pair', *, run: bool = True, open: bool = True) -> None:  # noqa: A002
        self.fixture, self.run, self.is_open = fixture, run, open
        self.revision = 1
        self.model, self.raw = project_and_raw(fixture)
        self.service = SimpleNamespace(root=None)

    def project(self):
        return self.model if self.is_open else None

    def key(self):
        return ProjectKey('root', 'p', self.revision, 'run-1' if self.run else None, SHA, SHA) if self.is_open else None

    def busy(self) -> bool:
        return False


class FakeNav:
    def __init__(self) -> None:
        self.anchors: list = []
        self.result = NavResult.shown()

    def navigate(self, anchor):
        self.anchors.append(anchor)
        return self.result


class FakeShell:
    def __init__(self) -> None:
        self.tasks = TaskRunner(reraise=True)
        self.copied: list[str] = []
        self.statuses: list[str] = []

    def copy_text(self, text: str) -> bool:
        self.copied.append(text)
        return True

    def status(self, text: str) -> None:
        self.statuses.append(text)

    def announce(self, text: str, *, assertive: bool = False) -> None: ...


def loader_for(project: FakeProject, with_raw: bool = True):
    def load(model, _root, cancel):
        data = read_project_input(model, None, reader_for(project.raw) if with_raw else None)
        return pd.load_from_input(data, model, cancel)
    return load


def start(qtbot, fixture: str = 'svc_pair', *, loader=None, project: FakeProject | None = None, load: bool = True):
    project = project or FakeProject(fixture)
    shell, nav = FakeShell(), FakeNav()
    ctx = PanelContext(PANEL, project, SimpleNamespace(), nav, shell)
    controller = CallsController(ctx, loader=loader or loader_for(project))
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1000, 700)
    controller.panel.show()
    if load:
        controller.project_changed(project.key())
        settle(qtbot, controller)
    return controller, project, nav, shell


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and not controller.loading, timeout=5000)
    QApplication.processEvents()


def status(controller) -> str:
    return controller.panel.state.status_label().full_text()


def audit(widget) -> list[str]:
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


def names(table) -> list[str]:
    model = table.table_model
    return [model.texts_at(i)[0] for i in range(model.rowCount())]


def select_change(qtbot, controller, name: str) -> None:
    table = controller.panel.changes
    row = names(table).index(name)
    table.selectRow(row)
    settle(qtbot, controller)


# ---- declaration -----------------------------------------------------------------------------------------------

def test_spec_agrees_with_the_manifest_slot_and_lints_clean():
    entry = next(e for e in MANIFEST if e.id == 'graph')
    assert (entry.area, entry.tabify_with, entry.shortcut) == (PANEL.area, PANEL.tabify_with, PANEL.shortcut)
    report = registry.lint(MANIFEST, registry.load_manifest(MANIFEST))
    assert [f for f in report.findings if 'graph' in f.message.lower() and f.code != 'PT-GUI-CAP'] == []


# ---- states ----------------------------------------------------------------------------------------------------

def test_no_project_and_no_run_say_what_to_do(qtbot):
    controller, project, *_ = start(qtbot, load=False)
    controller.project_changed(None)
    assert status(controller) == vm.STATE_TEXT['E0'] and controller.panel.state.kind == 'no-project'
    project.run = False
    controller.project_changed(project.key())
    assert status(controller) == vm.STATE_TEXT['E1'] and not controller.panel.content.isVisibleTo(controller.panel)


def test_loaded_project_lists_changes_and_is_ready_without_a_seed(qtbot):
    controller, *_ = start(qtbot)
    assert 'DriverEntry' in names(controller.panel.changes)
    assert controller.panel.state.kind == 'partial'  # the sample has no whole-program source: that is said
    assert vm.STATE_TEXT['E12'] in status(controller)


def test_seed_fills_neighbours_tree_and_diagram(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    assert controller.found is not None and controller.panel.neighbours.table_model.rowCount() >= 1
    assert controller.panel.tree.topLevelItemCount() == 1
    assert controller.panel.canvas.node_count == len(controller.found.view.nodes)
    assert 'Identity' in controller.panel.detail.toPlainText()


def test_missing_raw_output_is_partial_with_the_e6_copy(qtbot):
    project = FakeProject()
    controller, *_ = start(qtbot, project=project, loader=loader_for(project, with_raw=False))
    assert controller.panel.state.kind == 'partial' and vm.STATE_TEXT['E6'] in status(controller)


def test_unchanged_function_seed_is_not_in_the_change_set(qtbot):
    controller, *_ = start(qtbot)
    controller._set_seed('no-such-match', remember=False)
    settle(qtbot, controller)
    assert vm.STATE_TEXT['E4'] in status(controller) and controller.found is None


def test_worker_failure_is_an_error_with_retry_and_copy(qtbot):
    def bad(_model, _root, _cancel):
        return pd.Failure('PT-GRAPH-INPUT', 'no completed run')
    controller, _p, _n, shell = start(qtbot, loader=bad)
    assert controller.panel.state.kind == 'error'
    assert status(controller) == 'Calls could not be read: PT-GRAPH-INPUT: no completed run'
    assert controller.panel.state.action_button('retry').isVisibleTo(controller.panel)
    controller.panel.state.action_button('copy').click()
    assert 'PT-GRAPH-INPUT' in shell.copied[0]


def test_changed_key_after_the_read_marks_the_view_stale(qtbot):
    gate, started = threading.Event(), threading.Event()
    project = FakeProject()
    inner = loader_for(project)

    def slow(model, root, cancel):
        started.set()
        gate.wait(5)
        return inner(model, root, cancel)
    controller, *_ = start(qtbot, project=project, loader=slow, load=False)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    assert controller.panel.state.kind == 'loading' and status(controller) == vm.STATE_TEXT['E2']
    project.revision = 2  # the project changed without a project_changed hook yet
    gate.set()
    settle(qtbot, controller)
    assert controller.panel.state.kind == 'stale' and 'The call view is stale' in status(controller)


def test_escape_cancels_a_read_and_says_so(qtbot):
    started = threading.Event()

    def waits(_model, _root, cancel):
        started.set()
        while not cancel():
            cancel.wait(0.01)
        return pd.Failure('PT-GRAPH-CANCEL', 'cancelled')
    controller, *_ = start(qtbot, loader=waits, load=False)
    controller.project_changed(controller.port.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.cancel()
    assert controller.panel.state.kind == 'cancelled' and status(controller) == vm.STATE_TEXT['E8']


def test_too_large_diagram_blocks_only_the_diagram(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    canvas = controller.panel.canvas
    canvas.max_nodes = 1
    controller._fill_diagram(controller.found)
    assert 'Too large to draw' in controller.panel.diagram_note.full_text()
    assert controller.panel.neighbours.table_model.rowCount() >= 1


# ---- threads ---------------------------------------------------------------------------------------------------

def test_late_result_after_project_switch_is_dropped(qtbot):
    controller, project, *_ = start(qtbot)
    old_epoch, data = controller.epoch, controller.data
    controller.project_changed(None)
    controller._loaded(data, old_epoch, project.key())
    controller._queried(None, old_epoch)
    assert controller.data is None and controller.panel.state.kind == 'no-project'


def test_project_switch_while_reading_drops_the_running_result(qtbot):
    gate, started, ran = threading.Event(), threading.Event(), []
    project = FakeProject()
    inner = loader_for(project)

    def slow(model, root, cancel):
        started.set()
        gate.wait(5)
        ran.append(1)
        return inner(model, root, cancel)
    controller, *_ = start(qtbot, project=project, loader=slow, load=False)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    project.is_open = False
    controller.project_changed(None)
    gate.set()
    qtbot.waitUntil(lambda: bool(ran), timeout=5000)
    controller.tasks.shutdown()
    assert controller.data is None and controller.panel.state.kind == 'no-project'


def test_shutdown_cancels_the_work_and_is_idempotent(qtbot):
    started, tokens = threading.Event(), []

    def waits(_model, _root, cancel):
        tokens.append(cancel)
        started.set()
        cancel.wait(5)
        return pd.Failure('PT-GRAPH-CANCEL', 'cancelled')
    controller, *_ = start(qtbot, loader=waits, load=False)
    controller.project_changed(controller.port.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.shutdown()
    controller.shutdown()
    qtbot.waitUntil(lambda: tokens[0].is_set(), timeout=5000)
    controller.tasks.shutdown()
    assert not controller.tasks.busy() and controller.data is None


# ---- text safety ------------------------------------------------------------------------------------------------

def test_hostile_function_names_stay_plain_bounded_text(qtbot):
    controller, *_ = start(qtbot, 'hostile_names')
    shown = names(controller.panel.changes)
    assert shown and all('\n' not in n and '\r' not in n and '\x00' not in n and len(n) <= 125 for n in shown)
    select_change(qtbot, controller, 'Dispatch')
    detail = controller.panel.detail.toPlainText()
    assert '\x00' not in detail and '‮' not in detail and len(detail) <= 16_384
    assert all('\n' not in n and len(n) <= 125 for n in names(controller.panel.neighbours))
    assert audit(controller.panel) == []


@pytest.mark.parametrize('text', [h.values[0] for h in HOSTILE_PARAMS], ids=[h.id for h in HOSTILE_PARAMS])
def test_hostile_state_values_cannot_forge_a_line(qtbot, text):
    controller, *_ = start(qtbot, load=False)
    controller.key = controller.port.key()
    controller.error = (text, text)
    controller._render()
    line = status(controller)
    assert '\n' not in line and '\x1b' not in line and '‮' not in line and len(line) <= 1_200


# ---- accessibility, tooltips, actions ---------------------------------------------------------------------------

def test_accessibility_audit_is_clean_in_every_state(qtbot):
    controller, *_ = start(qtbot)
    assert audit(controller.panel) == []
    select_change(qtbot, controller, 'DriverEntry')
    assert audit(controller.panel) == []
    controller.project_changed(None)
    assert audit(controller.panel) == []


def test_every_control_has_a_registered_tooltip_with_source(qtbot):
    controller, *_ = start(qtbot)
    for widget in (controller.panel.tabs, controller.panel.changes, controller.panel.neighbours, controller.panel.detail,
                   *controller.panel.buttons.values()):
        assert 'Source' in widget.whatsThis() or 'Source:' in widget.whatsThis()
    assert all(entry.source for entry in PANEL.tips.values())


def test_open_emits_a_pinned_function_anchor_and_a_miss_changes_nothing(qtbot):
    controller, project, nav, shell = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    controller.panel.tabs.setCurrentIndex(0)
    controller.open()
    anchor = nav.anchors[-1]
    assert (anchor.kind, anchor.side, anchor.run_id, anchor.revision) == ('function', 'newer', 'run-1', 1)
    nav.result = NavResult.not_found('x', 'run-1')
    controller.open()
    assert len(nav.anchors) == 2


def test_focus_back_and_copy(qtbot):
    controller, _p, _n, shell = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    first = controller.seed
    controller._set_seed(next(d.match_id for d in controller.data.deltas if d.match_id != first), remember=True)
    settle(qtbot, controller)
    assert controller.history == [first]
    controller.back()
    settle(qtbot, controller)
    assert controller.seed == first and controller.history == []
    controller.copy()
    assert shell.copied and 'Identity' in shell.copied[-1]


def test_options_requery_without_touching_the_snapshot(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    snapshot = controller.data.snapshot
    controller.panel.depth.setValue(2)
    controller.panel.direction.setCurrentIndex(2)
    settle(qtbot, controller)
    assert controller.found.spec.depth == 2 and controller.found.spec.direction == 'out'
    assert controller.data.snapshot is snapshot
    controller.panel.flags['changed_only'].setChecked(True)
    settle(qtbot, controller)
    assert controller.rows.total <= len(controller.data.deltas)


def test_show_anchor_selects_a_known_match_and_refuses_others(qtbot):
    controller, project, *_ = start(qtbot)
    match = controller.data.deltas[0].match_id
    from patchtrace.gui.anchors import AnchorRef
    assert controller.show_anchor(AnchorRef('match', match, 'newer')).status == 'shown'
    assert controller.show_anchor(AnchorRef('match', 'nope', 'newer')).status == 'not-found'
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-1')).status == 'blocked'


def test_no_top_level_window_is_created(qtbot):
    controller, *_ = start(qtbot)
    select_change(qtbot, controller, 'DriverEntry')
    extra = [w for w in QApplication.topLevelWidgets() if w.isVisible() and w is not controller.panel]
    assert extra == []
