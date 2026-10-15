"""K4b KB and CVE dock: state matrix, hostile text, accessibility, stale results on project switch, shutdown, anchors
and actions (offscreen Qt). Synthetic reports only; the loader is injected, so nothing reads a workspace."""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads, top_level_windows  # noqa: F401
from test_kbc_view_model import lead, report

from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.kbcorrelation.leads import TEXT_NO_COMPARISON
from patchtrace.kbcorrelation.panel import PANEL
from patchtrace.kbcorrelation.panel_qt import KbController
from patchtrace.panel_manifest import MANIFEST

SRC = Path(__file__).resolve().parent.parent / 'src'
HOSTILE = '<b>x</b>&amp;{0}%s javascript:alert(1)\x1b[31m‮ '


class NoticeShell(FakeShell):
    def __init__(self, tasks):
        super().__init__(tasks)
        self.notices: dict = {}

    def notice(self, key, model):
        self.notices[key] = model


def audit(widget) -> list[str]:
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


def build(qtbot, loader, project=None):
    project = project or FakeProject()
    nav, shell = FakeNav(), NoticeShell(TaskRunner(reraise=True))
    controller = KbController(PanelContext(PANEL, project, SimpleNamespace(), nav, shell), loader=loader)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1100, 700)
    controller.panel.show()
    return controller, nav, shell, project


def start(qtbot, loader, *, project=None):
    controller, nav, shell, project = build(qtbot, loader, project)
    controller.project_changed(project.key())
    settle(qtbot, controller)
    return controller, nav, shell, project


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    QApplication.processEvents()


def state(controller) -> tuple[str, str]:
    view = controller.panel.state_view
    return view.kind, view.status_label().full_text()


def names(controller) -> list[str]:
    model = controller.panel.table.table_model
    return [model.texts_at(i)[1] for i in range(model.rowCount())]


def fixed(value):
    return lambda _workspace, _directory, _token: value


# ---- the state matrix ---------------------------------------------------------------------------------------------

def test_without_a_project_it_says_to_open_one(qtbot):
    controller, *_ = start(qtbot, fixed(report()), project=FakeProject(open=False))
    assert state(controller) == ('no-project', 'Open a project to use KB and CVE leads.')
    assert not controller.panel.content.isVisibleTo(controller.panel)


def test_ready_lists_groups_and_leads_with_coverage_notice(qtbot):
    controller, _nav, shell, _p = start(qtbot, fixed(report(state='ready')))
    assert state(controller)[0] == 'ready'
    assert names(controller) == [names(controller)[0], 'fn_1', 'fn_2', 'unattributed (always visible)', 'fn_3']
    assert shell.notices['kb.coverage'].text.startswith('Checked 1 of 1 documents')
    assert controller.panel.content.isVisibleTo(controller.panel)
    assert 'Mention only: CVE-2099-20003' in controller.panel.footer.full_text()


def test_empty_list_is_explained_not_blank(qtbot):
    empty = report(grouped=(), loose=())
    controller, _nav, shell, _p = start(qtbot, fixed(empty))
    kind, text = state(controller)
    assert kind == 'idle' and 'lists no changed functions' in text
    assert not controller.panel.content.isVisibleTo(controller.panel) and shell.notices['kb.coverage'] is None


def test_advisory_only_result_is_partial_and_keeps_its_rows(qtbot):
    controller, *_ = start(qtbot, fixed(report(state='no-comparison').model_copy(update={'text': TEXT_NO_COMPARISON})))
    kind, text = state(controller)
    assert kind == 'partial' and text.startswith('Partial result:') and 'unknown, not disagreement' in text
    assert controller.panel.content.isVisibleTo(controller.panel)


def test_stale_result_is_shown_for_reference_and_cannot_navigate(qtbot):
    controller, nav, *_ = start(qtbot, fixed(report(state='stale', stale=True).model_copy(update={'text': 'Prepared for another pair.'})))
    assert state(controller)[0] == 'stale' and 'for reference only' in state(controller)[1]
    controller.panel.table.selectRow(1)
    assert not controller.panel.buttons['goto'].isEnabled()
    controller.go()
    assert nav.selected == []


def test_project_folder_missing_is_blocked_in_words(qtbot):
    project = FakeProject()
    project.service = None
    controller, *_ = start(qtbot, fixed(report()), project=project)
    kind, text = state(controller)
    assert kind == 'blocked' and 'project folder is not available' in text


def test_loading_then_error_keeps_earlier_rows_and_offers_retry(qtbot):
    gate, started = threading.Event(), threading.Event()
    calls = []

    def loader(_w, _d, _token):
        calls.append(1)
        if len(calls) == 2:
            started.set()
            gate.wait(5)
            raise RuntimeError('boom')
        return report()
    controller, *_ = start(qtbot, loader)
    controller.reload()
    qtbot.waitUntil(started.is_set, timeout=5000)
    assert state(controller)[0] == 'refreshing' and not controller.panel.buttons['refresh'].isEnabled()
    gate.set()
    settle(qtbot, controller)
    kind, text = state(controller)
    assert kind == 'error' and 'Earlier results are unchanged' in text
    assert controller.panel.state_view.action_button('retry').isVisibleTo(controller.panel)
    assert len(names(controller)) == 5 and controller.panel.content.isVisibleTo(controller.panel)


def test_first_load_says_loading_and_hides_the_content(qtbot):
    gate, started = threading.Event(), threading.Event()

    def loader(_w, _d, _token):
        started.set()
        gate.wait(5)
        return report()
    controller, _nav, _shell, project = build(qtbot, loader)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    assert state(controller) == ('loading', 'Loading KB and CVE leads...')
    assert not controller.panel.content.isVisibleTo(controller.panel)
    gate.set()
    settle(qtbot, controller)
    assert state(controller)[0] == 'ready'


# ---- text, accessibility, windows ---------------------------------------------------------------------------------

def test_hostile_text_is_bounded_escaped_and_plain(qtbot):
    hostile = report().model_copy(update={'unattributed': (lead(9, 'unattributed', name=(HOSTILE * 40)[:900]),)})
    controller, *_ = start(qtbot, fixed(hostile))
    cell = names(controller)[-1]
    assert '\x1b' not in cell and '‮' not in cell and ' ' not in cell
    assert len(cell) <= 300 and '<b>x</b>' in cell  # shown as text, never markup
    controller.panel.table.selectRow(controller.panel.table.table_model.rowCount() - 1)
    assert '\x1b' not in controller.panel.detail.toPlainText() and len(controller.panel.detail.toPlainText()) <= 16_384
    assert audit(controller.panel) == []


def test_accessibility_audit_is_clean_in_every_state(qtbot):
    controller, *_ = start(qtbot, fixed(report()))
    assert audit(controller.panel) == []
    controller.project_changed(None)
    assert audit(controller.panel) == []
    assert controller.panel.table.accessibleName() == 'KB and CVE leads table'


def test_no_new_top_level_window(qtbot):
    before = len(top_level_windows())
    start(qtbot, fixed(report()))
    assert len(top_level_windows()) <= before + 1  # the test's own panel widget, no dialog or dock window


# ---- threads: project switch and shutdown -------------------------------------------------------------------------

def test_late_result_is_dropped_when_the_project_changes(qtbot):
    gate, started = threading.Event(), threading.Event()
    seen = []

    def loader(_w, _d, _token):
        seen.append(threading.get_ident())
        started.set()
        gate.wait(5)
        return report()
    controller, _nav, _shell, project = build(qtbot, loader)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    project.is_open = False
    controller.project_changed(None)
    gate.set()
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    QApplication.processEvents()
    assert controller.model is None and names(controller) == [] and state(controller)[0] == 'no-project'
    assert seen and seen[0] != threading.get_ident()  # the read ran on a worker, never the GUI thread


def test_shutdown_cancels_the_running_read(qtbot):
    tokens, started = [], threading.Event()

    def loader(_w, _d, token):
        tokens.append(token)
        started.set()
        token.wait(5)
        return report()
    controller, _nav, _shell, project = build(qtbot, loader)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.shutdown()
    assert tokens[0].is_set()
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)


# ---- navigation and actions ---------------------------------------------------------------------------------------

def test_goto_selects_the_comparison_row_and_copy_puts_evidence_on_the_clipboard(qtbot):
    controller, nav, shell, _p = start(qtbot, fixed(report()))
    controller.panel.table.selectRow(0)  # a group header row
    assert not controller.panel.buttons['goto'].isEnabled() and not controller.panel.buttons['copy'].isEnabled()
    controller.panel.table.selectRow(1)
    assert controller.panel.buttons['goto'].isEnabled()
    controller.panel.buttons['goto'].click()
    assert nav.selected == ['m1']
    controller.panel.buttons['copy'].click()
    assert shell.copied and shell.copied[0].startswith('Function: fn_1') and len(shell.copied[0]) <= 16 * 1024


def test_group_filter_and_search_narrow_the_rows(qtbot):
    controller, *_ = start(qtbot, fixed(report()))
    controller.panel.group.setCurrentIndex(controller.panel.group.findData('unattributed'))
    settle(qtbot, controller)
    assert names(controller) == ['unattributed (always visible)', 'fn_3']
    controller.panel.search.setText('nothing-like-this')
    assert names(controller) == []


def test_cve_anchor_selects_its_group_and_other_kinds_are_refused(qtbot):
    controller, *_ = start(qtbot, fixed(report()))
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-20001')).status == 'shown'
    settle(qtbot, controller)
    assert controller.panel.group.currentData() == 'CVE-2099-20001'
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-99999')).status == 'not-found'
    assert controller.show_anchor(AnchorRef('string', 'x')).status == 'blocked'


# ---- the declaration ----------------------------------------------------------------------------------------------

def test_the_declaration_matches_its_manifest_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'kb'])
    assert loaded.specs['kb'] is PANEL and not loaded.errors and not loaded.forbidden
    assert (PANEL.area, PANEL.shortcut) == ('right', 'Ctrl+Shift+K')
    assert [f for f in registry.lint(MANIFEST, loaded).findings if f.panel == 'kb'] == []


def test_loading_the_declaration_imports_no_qt():
    code = (f'import sys; sys.path.insert(0, {str(SRC)!r}); import patchtrace.kbcorrelation.panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0
