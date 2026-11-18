"""K4b KB and CVE dock: state matrix, hostile text, accessibility, stale results on project switch, shutdown, anchors
and actions (offscreen Qt). Synthetic reports only; the loader is injected, so nothing reads a workspace.

The last section but one (KBB-01) is the exception: it drives the dock's production reader and loader over a real,
synthetic project that the test holds open the way the desktop window does. Fixture evidence, not a live GUI run."""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import Kb
from kbc_k4a_support import analysed_project
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads, main_window, settings, top_level_windows  # noqa: F401
from test_kbc_view_model import lead, report

from patchtrace.enrichment import pipeline
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.kbcorrelation import cli as kb_cli
from patchtrace.kbcorrelation import cli_leads, panel_qt
from patchtrace.kbcorrelation.leads import TEXT_NO_COMPARISON, NullExploitation
from patchtrace.kbcorrelation.panel import PANEL
from patchtrace.kbcorrelation.panel_qt import KbController
from patchtrace.panel_manifest import MANIFEST
from patchtrace.persistence import ProjectStore
from patchtrace.service import ProjectService

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


def build(qtbot, loader, project=None, reader=lambda _service: None):
    """The injected loaders ignore the snapshot, so the stand-in reader of the fake project hands them none."""
    project = project or FakeProject()
    nav, shell = FakeNav(), NoticeShell(TaskRunner(reraise=True))
    controller = KbController(PanelContext(PANEL, project, SimpleNamespace(), nav, shell), reader=reader, loader=loader)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1100, 700)
    controller.panel.show()
    return controller, nav, shell, project


def start(qtbot, loader, *, project=None, **options):
    controller, nav, shell, project = build(qtbot, loader, project, **options)
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


# ---- the production loader over a project the desktop holds open (KBB-01 / D-DEF-01) -------------------------------

def hold(qtbot, held, workspace):
    """The dock as the panel registry builds it (production reader and loader, nothing injected) over a project the
    test keeps open, as the desktop window does. Only the advisory workspace is redirected, away from the user's."""
    project = FakeProject(held)
    shell = NoticeShell(TaskRunner(reraise=True))
    controller = KbController(PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), shell), workspace=workspace)
    qtbot.addWidget(controller.panel)
    controller.panel.show()
    controller.project_changed(project.key())
    settle(qtbot, controller)
    return controller


def watch_store(monkeypatch) -> SimpleNamespace:
    """From now on: ``opens`` lists every ``ProjectService.open`` and every new ``ProjectStore`` (a second open of the
    held project), ``touched`` the thread id of every project-store use (those opens, each checked store call and each
    enrichment row read)."""
    seen = SimpleNamespace(opens=[], touched=[])
    service_open, store_init = ProjectService.open, ProjectStore.__init__
    check_open, entries = ProjectStore._check_open, EnrichmentStore.entries

    def spy_open(cls, *args, **kwargs):
        seen.opens.append('ProjectService.open')
        seen.touched.append(threading.get_ident())
        return service_open(*args, **kwargs)

    def spy_init(self, *args, **kwargs):
        seen.opens.append('ProjectStore')
        seen.touched.append(threading.get_ident())
        store_init(self, *args, **kwargs)

    def spy_check(self):
        seen.touched.append(threading.get_ident())
        check_open(self)

    def spy_entries(self, *args, **kwargs):
        seen.touched.append(threading.get_ident())
        return entries(self, *args, **kwargs)
    monkeypatch.setattr(ProjectService, 'open', classmethod(spy_open))
    monkeypatch.setattr(ProjectStore, '__init__', spy_init)
    monkeypatch.setattr(ProjectStore, '_check_open', spy_check)
    monkeypatch.setattr(EnrichmentStore, 'entries', spy_entries)
    return seen


def watch_thread(monkeypatch, module, name: str, threads: dict) -> None:
    """Record in ``threads[name]`` the thread id on which ``module.name`` is called from now on."""
    real = getattr(module, name)

    def spy(*args, **kwargs):
        threads[name] = threading.get_ident()
        return real(*args, **kwargs)
    monkeypatch.setattr(module, name, spy)


def test_production_loader_reads_a_project_the_host_holds_open(qtbot, tmp_path, monkeypatch):
    held = ProjectService.sample(tmp_path / 'case')  # stays open for the whole test, as in the desktop window
    try:
        seen = watch_store(monkeypatch)
        controller = hold(qtbot, held, tmp_path / 'ws')
        kind, text = state(controller)
        assert kind == 'idle', text  # the sample has no advisory and no ranking: explained, never a failure
        assert controller.model.report.state == 'no-advisory'
        assert seen.opens == []  # the open project is never opened a second time
    finally:
        held.close()


@pytest.mark.usefixtures('no_sockets')
def test_only_the_gui_thread_touches_the_held_project_and_a_worker_builds_the_leads(qtbot, tmp_path, monkeypatch,
                                                                                     capsys):
    project = analysed_project(Kb(tmp_path, capsys), tmp_path, capsys)  # an attached advisory context and a ranking
    held = ProjectService.open(project)
    try:
        seen, computed = watch_store(monkeypatch), {}
        watch_thread(monkeypatch, pipeline, 'load_default', computed)
        watch_thread(monkeypatch, cli_leads, 'build_leads', computed)
        controller = hold(qtbot, held, tmp_path / 'ws')
        gui = threading.get_ident()
        assert seen.touched and set(seen.touched) == {gui}  # R1: the project store is used by its owner thread only
        assert seen.opens == []
        # The GUI thread only reads rows: checking the ranking against the comparison and building the leads, the
        # work that grows with the project, still run on a worker.
        assert set(computed) == {'load_default', 'build_leads'} and gui not in computed.values()
        assert state(controller)[0] == 'ready', state(controller)[1]
    finally:
        held.close()


@pytest.mark.usefixtures('no_sockets')
def test_the_dock_shows_what_kb_leads_prints_for_the_same_project(qtbot, tmp_path, capsys):
    project = analysed_project(Kb(tmp_path, capsys), tmp_path, capsys)
    out = io.StringIO()  # the headless CLI while nothing holds the project: the reference the dock has to match
    # The dock loads no KEV catalog, so the reference run gets the same "not loaded" lookup instead of the user's.
    assert kb_cli.main(['leads', str(project), '--workspace', str(tmp_path / 'ws'), '--json'], kev=NullExploitation(),
                       stdout=out) == 0
    expected = json.loads(out.getvalue())['result']
    held = ProjectService.open(project)
    try:
        def stored():
            return (hashlib.sha256((project / 'project.sqlite3').read_bytes()).hexdigest(),
                    sorted(path.name for path in project.iterdir()))
        before = stored()
        controller = hold(qtbot, held, tmp_path / 'ws')
        assert state(controller)[0] == 'ready', state(controller)[1]
        assert controller.model.report.model_dump(mode='json') == expected
        assert [name for name in names(controller) if '(' not in name] == [
            'read_item', 'alloc_items', 'debug_dump', 'get_version', 'report_invalid_index']
        assert stored() == before  # the dock reads the held project and writes nothing into it
    finally:
        held.close()


def test_the_real_main_window_shows_the_kb_dock_for_the_project_it_holds(
        main_window, qtbot, tmp_path, monkeypatch):  # noqa: F811 - imported pytest fixture
    """The whole production path: the panel registry's factory, the host's own port over ``window.service`` and the
    default reader and loader. Only the advisory workspace folder is moved away from the user's."""
    monkeypatch.setattr(panel_qt, '_default_workspace', lambda: tmp_path / 'ws')
    seen = watch_store(monkeypatch)
    controller = main_window.panels.show_panel('kb').controller
    assert controller.port.service is main_window.service
    qtbot.waitUntil(lambda: controller.model is not None or state(controller)[0] == 'error', timeout=5000)
    kind, text = state(controller)
    assert kind == 'idle', text
    assert controller.model.report.state == 'no-advisory'
    assert seen.opens == [] and set(seen.touched) == {threading.get_ident()}


def test_refresh_takes_a_new_snapshot_on_the_gui_thread_and_hands_it_to_the_worker(qtbot):
    taken, handed = [], []

    def reader(service):
        taken.append((service, threading.get_ident()))
        return f'snapshot {len(taken)}'

    def loader(_workspace, snapshot, _token):
        handed.append((snapshot, threading.get_ident()))
        return report()
    controller, _nav, _shell, project = start(qtbot, loader, reader=reader)
    controller.panel.buttons['refresh'].click()
    settle(qtbot, controller)
    gui = threading.get_ident()
    assert taken == [(project.service, gui), (project.service, gui)]
    assert [snapshot for snapshot, _ in handed] == ['snapshot 1', 'snapshot 2']
    assert all(ident != gui for _, ident in handed)


def test_a_failed_read_of_the_open_project_is_an_error_with_retry_and_keeps_earlier_rows(qtbot):
    reads, loads = [], []

    def reader(_service):
        reads.append(1)
        if len(reads) == 2:
            raise OSError('/home/analyst/case cannot be read')

    def loader(_workspace, _snapshot, _token):
        loads.append(1)
        return report()
    controller, *_ = start(qtbot, loader, reader=reader)
    controller.reload()  # the second read fails on the GUI thread; it becomes a state, not an exception inside Qt
    kind, text = state(controller)
    assert kind == 'error' and 'OSError stopped the work' in text and 'analyst' not in text  # the class, no message
    assert 'Earlier results are unchanged' in text and len(names(controller)) == 5
    assert len(loads) == 1 and not controller.tasks.busy()  # no worker was started for a snapshot that was not taken
    assert controller.panel.buttons['refresh'].isEnabled()
    controller.panel.state_view.action_button('retry').click()
    settle(qtbot, controller)
    assert state(controller)[0] == 'ready' and len(reads) == 3 and len(loads) == 2


def test_a_failed_read_drops_the_load_still_in_flight(qtbot):
    gate, started, reads = threading.Event(), threading.Event(), []

    def reader(_service):
        reads.append(1)
        if len(reads) == 2:
            raise RuntimeError('boom')

    def loader(_workspace, _snapshot, _token):
        started.set()
        gate.wait(5)
        return report()
    controller, _nav, _shell, project = build(qtbot, loader, reader=reader)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.reload()
    gate.set()
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    QApplication.processEvents()
    assert state(controller)[0] == 'error' and controller.model is None and names(controller) == []


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


def test_refresh_discards_pending_filter_result(qtbot, monkeypatch):
    controller, *_ = start(qtbot, lambda *_: report())
    gate, entered = threading.Event(), threading.Event()
    real_prepare = panel_qt._prepare

    def delayed(*args):
        if not entered.is_set():
            entered.set()
            gate.wait(5)
        return real_prepare(*args)
    monkeypatch.setattr(panel_qt, '_prepare', delayed)
    controller._group_changed(controller.group)
    qtbot.waitUntil(entered.is_set, timeout=5000)
    try:
        controller.reload()
        qtbot.waitUntil(lambda: not controller.loading, timeout=5000)
        refreshed = controller.model
    finally:
        gate.set()
    settle(qtbot, controller)
    assert controller.model is refreshed


def test_snapshot_limit_preserves_prior_rows_and_explains_cli_fallback(qtbot):
    from patchtrace.kbcorrelation.store import KbcStoreError
    controller, *_ = start(qtbot, lambda *_: report())
    earlier = controller.model

    def over_limit(_service):
        raise KbcStoreError('PT-KBC-LIMIT', '/private/path must not be shown')
    controller.reader = over_limit
    controller.reload()
    kind, text = state(controller)
    assert kind == 'error' and 'PT-KBC-LIMIT' in text and 'patchtrace kb leads' in text
    assert 'desktop project closed' in text and '/private/path' not in text
    assert controller.model is earlier and 'Earlier results are unchanged' in text
