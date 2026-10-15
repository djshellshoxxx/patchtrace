"""Capabilities dock (CAP-6a/6b): the state matrix, rows and detail, hostile text, accessibility, navigation, late
results after a project switch, shutdown, and the previewed local run (offscreen Qt).

The controller is driven through fake ports, a fake loader, assembler, prober and runner: no capa program, no project
database and no network is involved."""
from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from PySide6.QtCore import QEvent, Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads, top_level_windows  # noqa: F401

from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef, NavResult
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.table_spec import prepare_table
from patchtrace.intelligence.tools import capa_data, capa_exec
from patchtrace.intelligence.tools.capa_pairs import (
    CoverageSummary,
    PairCapabilityDelta,
    PairCell,
    PairChange,
    PairGroup,
)
from patchtrace.intelligence.tools.capa_panel import PANEL
from patchtrace.intelligence.tools.capa_qt import CapabilitiesController
from patchtrace.intelligence.tools.capa_view import CapabilityView, RunInfo, ViewOptions
from patchtrace.intelligence.tools.common import ToolError, ToolManifest
from patchtrace.panel_manifest import MANIFEST

SHA_O, SHA_N = 'a' * 64, 'b' * 64
HOSTILE = 'evil\x1b[31m‮<b>bold</b>\x00 forged line ' + 'x' * 600
EXE = str(Path('/opt/capa/capa').resolve())


def key_of(revision: int = 1, project: str = 'p') -> ProjectKey:
    return ProjectKey('root', project, revision, 'run-1', SHA_O, SHA_N)


class FakeProject:
    def __init__(self, tmp_path, *, open=True, revision=1, project='p') -> None:  # noqa: A002
        self.is_open, self.revision, self.project_id = open, revision, project
        self.service = SimpleNamespace(root=tmp_path, store=None)
        self.files = []
        for name in ('old.dll', 'new.dll'):
            path = tmp_path / name
            path.write_bytes(name.encode())
            self.files.append(path)

    def project(self):
        return SimpleNamespace(id=self.project_id, revision=self.revision) if self.is_open else None

    def key(self):
        return key_of(self.revision, self.project_id) if self.is_open else None

    def busy(self) -> bool:
        return False

    def artifact_paths(self):
        return (*self.files, SHA_O, SHA_N)


class FakeNav:
    def __init__(self) -> None:
        self.anchors: list[AnchorRef] = []
        self.result = NavResult.shown()

    def navigate(self, anchor):
        self.anchors.append(anchor)
        return self.result


class FakeShell:
    def __init__(self) -> None:
        self.tasks, self.settings, self.theme = TaskRunner(reraise=True), None, None
        self.announced: list[tuple[str, bool]] = []
        self.copied: list[str] = []
        self.chosen: Path | None = None

    def announce(self, text: str, *, assertive: bool = False) -> None:
        self.announced.append((text, assertive))

    def copy_text(self, text: str) -> bool:
        self.copied.append(text)
        return True

    def status(self, text: str) -> None: ...

    def choose_file(self, title: str, file_filter: str = ''):
        return self.chosen


def cell(matches: int = 0) -> PairCell:
    return PairCell(state='present', matches=matches) if matches else PairCell(state='absent')


def change(rule: str, kind: str = 'gained', *, match: str | None = 'm1', group: str = 'm:m1', ns: str = 'host/x',
           noise: str = 'none') -> PairChange:
    older, newer = {'gained': (0, 1), 'lost': (1, 0), 'unchanged': (1, 1), 'moved': (0, 1)}[kind]
    return PairChange(change_id=f'c-{rule}'[:64], group_id=group, match_id=match, category='modified', rule_id=rule,
                      namespace=ns, scope='function', kind='capability', change=kind, noise=noise,
                      older=cell(older), newer=cell(newer), observation_key='o' * 16)


def delta_of(*changes: PairChange, pairing: str = 'available', truncated: bool = False) -> PairCapabilityDelta:
    counts = {name: sum(c.change == name for c in changes)
              for name in ('gained', 'lost', 'moved', 'unchanged', 'not-compared')}
    coverage = CoverageSummary(matched_groups=1, both_evaluated=1, older_library=0, newer_library=0,
                               older_not_recovered=0, newer_not_recovered=0, ambiguous_groups=0,
                               attributed_matches=0, total_matches=0)
    return PairCapabilityDelta(comparable=True, older_run_id='r1', newer_run_id='r2', pairing=pairing,
                               changes=tuple(changes), counts=counts, coverage=coverage, truncated=truncated)


def stored_of(*, older=True, newer=True) -> capa_data.Stored:
    found = lambda ok: (SimpleNamespace(run_id='r'), SimpleNamespace(capabilities=())) if ok else None  # noqa: E731
    return capa_data.Stored((found(older), found(newer)), (None, None), (), 'p', 'run-1')


def assembler_for(delta: PairCapabilityDelta, gate: threading.Event | None = None, started=None):
    def assemble(stored, unchanged, token=None):
        if started is not None:
            started.set()
        if gate is not None:
            gate.wait(5)
        group = PairGroup(group_id='m:m1', match_id='m1', category='modified', older_rvas=(0x1000,),
                          newer_rvas=(0x2000,), older_names=('read_item',), newer_names=('read_item',))
        return capa_data.Assembled(CapabilityView(delta, (group,), {}, RunInfo('p', 'run-1')), delta, unchanged)
    return assemble


GOOD = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                    rules_source='embedded', supported=True, cli_path=EXE, backend='vivisect')


def start(qtbot, tmp_path, delta=None, *, stored=None, loader=None, assembler=None, project=None, path='', **hooks):
    project = project or FakeProject(tmp_path)
    shell, nav = FakeShell(), FakeNav()
    ctx = registry.PanelContext(PANEL, project, SimpleNamespace(), nav, shell)
    stored = stored if stored is not None else stored_of()
    controller = CapabilitiesController(
        ctx, loader=loader or (lambda _s, _p: stored), assembler=assembler or assembler_for(delta or delta_of()),
        **hooks)
    controller.panel.setup.path.setText(path)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1000, 700)
    controller.panel.show()
    controller.project_changed(project.key())
    settle(qtbot, controller)
    controller.nav, controller.shell, controller.fake = nav, shell, project
    return controller


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and not controller.reading, timeout=5000)
    QApplication.processEvents()


def rows_of(controller) -> list[str]:
    model = controller.panel.changes.table.table_model
    return [model.texts_at(i)[0] for i in range(model.rowCount())]


def status_text(controller) -> str:
    return controller.panel.changes.state.model.text


def select(controller, view_row: int = 0) -> None:
    controller.panel.changes.table.selectRow(view_row)
    QApplication.processEvents()


# ---- the state matrix ---------------------------------------------------------------------------------------------

def test_c0_without_a_project(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, project=FakeProject(tmp_path, open=False))
    assert controller.state_id == 'C0' and status_text(controller) == 'Open a project to compare capabilities.'
    assert controller.panel.changes.state.kind == 'no-project'


def test_c1_and_c2_without_results_depend_on_the_chosen_tool(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, stored=stored_of(older=False, newer=False))
    assert controller.state_id == 'C1' and controller.panel.changes.state.kind == 'blocked'
    assert 'never downloads it by itself' in status_text(controller)
    controller.panel.setup.path.setText(EXE)
    assert controller.state_id == 'C2' and 'No capability results' in status_text(controller)
    assert controller.panel.changes.state.kind == 'idle'


def test_c4_ready_shows_rows_summary_and_announces_once(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule'), change('b.rule', 'lost')))
    assert controller.state_id == 'C4' and controller.panel.changes.state.kind == 'ready'
    assert rows_of(controller) == ['a.rule', 'b.rule']
    assert controller.panel.changes.content.isVisibleTo(controller.panel)
    controller.shell.announced.clear()
    controller._render()
    assert controller.shell.announced == []


def test_c5_one_side_missing_shows_no_comparison(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, stored=stored_of(newer=False))
    assert controller.state_id == 'C5' and 'newer file' in status_text(controller)
    assert 'unknown, not' in status_text(controller) and rows_of(controller) == []
    assert not controller.panel.changes.content.isVisibleTo(controller.panel)


def test_c6_error_keeps_the_words_and_offers_retry_and_copy(qtbot, tmp_path):
    def broken(_service, _project):
        raise ToolError('PT-TOOL-STORE', 'row unreadable')
    controller = start(qtbot, tmp_path, loader=broken)
    state = controller.panel.changes.state
    assert controller.state_id == 'C6' and state.kind == 'error'
    assert status_text(controller) == ('Capability results could not be assembled: PT-TOOL-STORE: row unreadable. '
                                       'Stored capa results are unchanged.')
    assert not state.action_button('retry').isHidden() and not state.action_button('copy').isHidden()
    state.action_button('copy').click()
    assert controller.shell.copied and 'PT-TOOL-STORE' in controller.shell.copied[-1]


def test_c7_stale_keeps_values_for_reference(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    controller.key = key_of(revision=2)
    controller._render()
    assert controller.state_id == 'C7' and controller.panel.changes.state.kind == 'stale'
    assert rows_of(controller) == ['a.rule']
    assert not controller.panel.changes.state.action_button('refresh').isHidden()


def test_c8_without_pairs_and_c9_without_changes(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(pairing='unavailable'))
    assert controller.state_id == 'C8' and 'Function pairs are not available' in status_text(controller)
    controller = start(qtbot, tmp_path, delta_of(change('same.rule', 'unchanged')))
    assert controller.state_id == 'C9' and 'does not mean the code is the same' in status_text(controller)


def test_c10_unusable_tool_after_a_probe(qtbot, tmp_path):
    bad = GOOD.model_copy(update={'supported': False, 'reason': 'no --backend option', 'version': None,
                                  'executable_sha256': None})
    controller = start(qtbot, tmp_path, stored=stored_of(older=False, newer=False), path=EXE,
                       prober=lambda *_a: bad)
    controller.panel.setup.probe.click()
    settle(qtbot, controller)
    assert controller.state_id == 'C10' and 'no --backend option' in status_text(controller)
    assert not controller.panel.setup.run.isEnabled()


def test_c11_too_many_rows_and_the_truncation_banner(qtbot, tmp_path):
    def many(view, options, token=None):
        from patchtrace.intelligence.tools.capa_view import Arrangement
        return Arrangement((), 200_000, too_many=200_000), prepare_table(capa_data.SPEC, capa_data.COLUMNS, ())
    controller = start(qtbot, tmp_path, preparer=many)
    assert controller.state_id == 'C11' and status_text(controller) == 'Too many rows to display (200000). Narrow the filter.'
    controller = start(qtbot, tmp_path, delta_of(change('a.rule'), truncated=True))
    assert 'incomplete' in controller.panel.changes.banner.full_text()


def test_c3_running_text_and_cancelled_text(qtbot, tmp_path):
    gate = threading.Event()
    controller = start(qtbot, tmp_path, path=EXE, prober=lambda *_a: GOOD,
                       runner=lambda spec, manifest, token, report: (report('older', 1, 2), gate.wait(5), [])[2],
                       publisher=lambda *_a: [])
    controller.panel.setup.probe.click()
    settle(qtbot, controller)
    controller.panel.setup.run.click()
    controller.panel.setup.confirm.click()
    qtbot.waitUntil(lambda: controller.state_id == 'C3', timeout=5000)
    assert status_text(controller) == ('Running capa on the older file (1 of 2). This can take several minutes per '
                                       'file.')
    assert controller.panel.changes.cancel.isVisibleTo(controller.panel)
    controller.panel.changes.cancel.click()
    gate.set()
    assert status_text(controller) == 'Cancelled. Earlier results are unchanged.'
    assert controller.panel.changes.state.kind == 'cancelled'


# ---- rows, filters and the detail ---------------------------------------------------------------------------------

def test_filter_search_and_detail(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule'), change('b.rule', 'lost', group='m:m2', match='m2')))
    page = controller.panel.changes
    page.filter.setCurrentIndex(page.filter.findData('lost'))
    qtbot.waitUntil(lambda: rows_of(controller) == ['b.rule'], timeout=5000)
    page.filter.setCurrentIndex(page.filter.findData('changes'))
    qtbot.waitUntil(lambda: rows_of(controller) == ['a.rule', 'b.rule'], timeout=5000)
    page.search.setText('b.rule')
    QApplication.processEvents()
    assert rows_of(controller) == ['b.rule']
    select(controller)
    detail = page.detail.toPlainText()
    assert detail.startswith('Change') and 'Why capa matched' in detail and 'Provenance' in detail


def test_same_rows_materialize_only_when_asked(qtbot, tmp_path):
    calls = []

    def assemble(stored, unchanged, token=None):
        calls.append(unchanged)
        return assembler_for(delta_of(change('a.rule'), change('s.rule', 'unchanged')))(stored, unchanged, token)
    controller = start(qtbot, tmp_path, assembler=assemble)
    page = controller.panel.changes
    page.filter.setCurrentIndex(page.filter.findData('unchanged'))
    qtbot.waitUntil(lambda: calls == [False, True], timeout=5000)
    settle(qtbot, controller)
    assert rows_of(controller) == ['s.rule']


def test_settings_restore_filter_and_remember_choices(qtbot, tmp_path):
    from PySide6.QtCore import QSettings

    from patchtrace.gui.qt.settings import PanelSettings
    store = PanelSettings(QSettings(str(tmp_path / 's.ini'), QSettings.Format.IniFormat), 'capabilities')
    store.set('filter', 'gained')
    store.set('group_by', 'bogus')
    project = FakeProject(tmp_path)
    ctx = registry.PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), SimpleNamespace(
        tasks=TaskRunner(reraise=True), settings=store, theme=None, announce=lambda *a, **k: None))
    controller = CapabilitiesController(ctx, loader=lambda *_a: stored_of(), assembler=assembler_for(delta_of()))
    qtbot.addWidget(controller.panel)
    assert controller.options.filter == 'gained' and controller.options.group_by == 'namespace'
    controller.panel.changes.noise.setChecked(True)
    assert store.get_bool('show_noise', False) is True
    controller.shutdown()


def test_unattributed_matches_are_listed_only_on_request_and_follow_the_search(qtbot, tmp_path):
    from patchtrace.intelligence.tools.capa_pairs import Unattributed
    item = Unattributed(rule_id='file.rule', scope='file', namespace='anti', change='gained', older_matches=0,
                        newer_matches=1, reason='file-scope')
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')).model_copy(update={'unattributed': (item,)}))
    label = controller.panel.changes.unattributed_lines
    assert not label.isVisibleTo(controller.panel)
    controller.panel.changes.unattributed.setChecked(True)
    qtbot.waitUntil(lambda: label.isVisibleTo(controller.panel), timeout=5000)
    assert 'file.rule' in label.full_text()
    controller.panel.changes.search.setText('zzz')
    assert not label.isVisibleTo(controller.panel)


# ---- hostile text, names and keys ---------------------------------------------------------------------------------

def test_hostile_text_is_bounded_and_never_markup(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change(HOSTILE[:250], ns=HOSTILE[:250])))
    page = controller.panel.changes
    model = page.table.table_model
    for text in (*model.texts_at(0), page.banner.full_text()):
        assert '\x1b' not in text and '\x00' not in text and '‮' not in text and ' ' not in text
        assert len(text) <= 300
    select(controller)
    detail = page.detail.toPlainText()
    assert '\x1b' not in detail and '‮' not in detail and len(detail) <= 8_192
    assert page.detail.isReadOnly()
    assert all(label.textFormat() == Qt.TextFormat.PlainText for label in controller.panel.findChildren(
        type(page.banner)))


def test_the_accessibility_audit_is_clean_in_both_tabs(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    for tab in (0, 1):
        controller.panel.tabs.setCurrentIndex(tab)
        problems = [p for p in a11y_audit(controller.panel) if p != 'QHeaderView#?: not keyboard focusable']
        assert problems == []


def test_every_control_has_a_registered_tooltip_with_all_four_parts(qtbot, tmp_path):
    from patchtrace import tooltips
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    for name in ('table', 'filter', 'group_by', 'search', 'show_noise', 'show_unattributed', 'show_library',
                 'detail', 'goto', 'copy', 'refresh', 'cancel', 'path', 'browse', 'probe', 'backend', 'timeout',
                 'run', 'confirm_run', 'cancel_preview', 'preview', 'log', 'tabs'):
        widget = controller.panel.findChild(object, f'capabilities.{name}')
        assert widget is not None, name
        assert widget.toolTip() and widget.accessibleName(), name
        entry = tooltips.REGISTRY[f'capabilities.{name}']
        assert entry.what and entry.why and entry.effect and entry.source, name


def test_the_footer_is_fixed_and_the_dock_opens_no_window(qtbot, tmp_path):
    before = top_level_windows()
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    assert controller.panel.changes.footer.full_text().startswith('Capabilities are behaviours that capa rules')
    controller.panel.changes.table.setFocus()
    select(controller)
    controller.go()
    controller.panel.tabs.setCurrentIndex(1)
    assert [w for w in top_level_windows() if w not in before and w is not controller.panel] == []


# ---- navigation and copy ------------------------------------------------------------------------------------------

def test_go_to_pair_emits_a_pinned_match_anchor_and_reports_a_miss(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    select(controller)
    assert controller.panel.changes.goto.isEnabled()
    controller.go()
    anchor = controller.nav.anchors[-1]
    assert (anchor.kind, anchor.key, anchor.side, anchor.run_id, anchor.revision) == ('match', 'm1', 'both', 'run-1', 1)
    controller.nav.result = NavResult.not_found('a.rule', 'run-1')
    controller.go()
    assert controller.shell.announced[-1][0].startswith('Not found')


def test_go_to_pair_is_off_without_a_unique_match(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule', match=None, group='u:1:2')))
    select(controller)
    assert not controller.panel.changes.goto.isEnabled()
    assert 'no single stored match' in controller.panel.changes.goto.toolTip()


def test_copy_puts_a_deterministic_provenance_block_on_the_clipboard(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    select(controller)
    controller.panel.changes.copy.click()
    controller.panel.changes.table.provenance_copy.emit()
    first, second = controller.shell.copied
    assert first == second and first.startswith('PatchTrace capability change') and '\r' not in first
    assert len(first.encode()) <= 16 * 1024


def test_the_capability_anchor_selects_its_row(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule'), change('b.rule')))
    result = controller.show_anchor(AnchorRef('capability', 'c-b.rule', 'both'))
    assert result.status == 'shown' and controller.current_row().rule == 'b.rule'
    assert controller.show_anchor(AnchorRef('capability', 'nope', 'both')).status == 'not-found'
    assert controller.show_anchor(AnchorRef('string', 'x', 'both')).status == 'blocked'


def test_key_events_copy_and_enter_follow_the_table_contract(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    select(controller)
    table = controller.panel.changes.table
    table.setFocus()
    event = QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    table.keyPressEvent(event)
    assert controller.shell.copied and controller.shell.copied[-1].startswith('PatchTrace capability change')


# ---- threads ------------------------------------------------------------------------------------------------------

def test_a_late_result_after_a_project_switch_is_dropped(qtbot, tmp_path):
    gate, started = threading.Event(), threading.Event()
    project = FakeProject(tmp_path, project='first')
    stored = {'first': stored_of(), 'second': stored_of()}
    deltas = {'first': delta_of(change('first.rule')), 'second': delta_of(change('second.rule'))}

    def assemble(stored_value, unchanged, token=None):
        which = 'first' if stored_value is stored['first'] else 'second'
        if which == 'first':
            started.set()
            gate.wait(5)
        return assembler_for(deltas[which])(stored_value, unchanged, token)
    controller = start(qtbot, tmp_path, project=project, assembler=assemble,
                       loader=lambda _s, p: stored[p.id])
    controller.tasks.shutdown()  # the first start() settled on a fresh project; use a clean runner for the race
    controller.tasks = TaskRunner(reraise=True)
    controller.project_changed(None)
    gate.clear()
    started.clear()
    project.project_id = 'first'
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    project.project_id = 'second'
    controller.project_changed(project.key())
    settle(qtbot, controller)
    gate.set()
    qtbot.wait(100)
    QApplication.processEvents()
    assert rows_of(controller) == ['second.rule']


def test_shutdown_cancels_running_work_and_is_idempotent(qtbot, tmp_path):
    gate, started, seen = threading.Event(), threading.Event(), []

    def assemble(stored_value, unchanged, token=None):
        started.set()
        gate.wait(5)
        seen.append(token.is_set() if token is not None else None)
        return assembler_for(delta_of(change('late.rule')))(stored_value, unchanged, token)
    project = FakeProject(tmp_path)
    ctx = registry.PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), shell := FakeShell())
    controller = CapabilitiesController(ctx, loader=lambda *_a: stored_of(), assembler=assemble)
    qtbot.addWidget(controller.panel)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.shutdown()
    controller.shutdown()
    gate.set()
    shell.tasks.shutdown()
    assert seen == [True] and rows_of(controller) == [] and not shell.tasks.busy()


# ---- setup, probe and run (CAP-6b) --------------------------------------------------------------------------------

def test_the_path_must_be_absolute_and_nothing_starts_on_edit_or_tab_change(qtbot, tmp_path):
    started = []
    controller = start(qtbot, tmp_path, prober=lambda *_a: started.append(1) or GOOD,
                       runner=lambda *_a: started.append(2) or [])
    setup = controller.panel.setup
    controller.panel.tabs.setCurrentIndex(1)
    setup.path.setText('capa')
    assert not setup.probe.isEnabled()
    controller.probe()
    assert 'absolute' in setup.status.full_text() and started == []
    setup.path.setText('x' * 300)
    assert capa_exec.path_error('x' * 300).startswith('The path is longer')


def test_browse_fills_the_path_only_from_an_absolute_choice(qtbot, tmp_path):
    controller = start(qtbot, tmp_path)
    controller.shell.chosen = Path(EXE)
    controller.panel.setup.browse.click()
    assert controller.panel.setup.path.text() == EXE and controller.panel.setup.probe.isEnabled()


def test_run_needs_a_probe_then_a_preview_then_a_confirmation(qtbot, tmp_path):
    published, ran = [], []
    result = SimpleNamespace(run=SimpleNamespace(side='older', status='ok', error=None), evidence=None)

    def runner(spec, manifest, token, report):
        ran.append(spec)
        report('older', 1, 2)
        report('newer', 2, 2)
        return [result]
    controller = start(qtbot, tmp_path, path=EXE, prober=lambda *_a: GOOD, runner=runner,
                       publisher=lambda s, p, results: published.append(results) or [])
    setup = controller.panel.setup
    assert not setup.run.isEnabled() and not setup.confirm.isEnabled()
    setup.probe.click()
    settle(qtbot, controller)
    assert setup.run.isEnabled() and not setup.confirm.isEnabled() and ran == []
    setup.run.click()
    preview = setup.preview.toPlainText()
    for part in (SHA_O, SHA_N, 'old.dll', 'new.dll', EXE, 'e' * 64, '9.4.0', 'no network is used',
                 'Time limit per file: 1800 s', 'never run'):
        assert part in preview, part
    assert setup.confirm.isEnabled() and ran == []
    setup.confirm.click()
    settle(qtbot, controller)
    assert len(ran) == 1 and published == [[result]] and ran[0].timeout == 1800
    assert not setup.confirm.isEnabled()


def test_changing_an_option_invalidates_the_preview_and_escape_closes_it(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, path=EXE, prober=lambda *_a: GOOD)
    setup = controller.panel.setup
    setup.probe.click()
    settle(qtbot, controller)
    setup.run.click()
    assert setup.preview.toPlainText() and setup.confirm.isEnabled()
    setup.timeout.setValue(60)
    assert setup.preview.toPlainText() == '' and not setup.confirm.isEnabled()
    setup.run.click()
    controller.panel.preview_escape.activated.emit()
    assert setup.preview.toPlainText() == '' and 'Nothing was started' in setup.status.full_text()


def test_a_failed_side_is_shown_as_unfinished_and_not_as_no_capabilities(qtbot, tmp_path):
    failed = SimpleNamespace(run=SimpleNamespace(side='newer', status='timeout', error='capa did not finish'),
                             evidence=None)
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')), path=EXE, prober=lambda *_a: GOOD,
                       runner=lambda *_a: [failed], publisher=lambda *_a: [failed])
    controller.panel.setup.probe.click()
    settle(qtbot, controller)
    controller.panel.setup.run.click()
    controller.panel.setup.confirm.click()
    qtbot.waitUntil(lambda: controller.state_id == 'C5', timeout=5000)
    assert 'newer file (capa did not finish)' in status_text(controller)


def test_busy_lanes_disable_their_controls_but_reading_stays_available(qtbot, tmp_path):
    gate = threading.Event()
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')), path=EXE, prober=lambda *_a: GOOD,
                       runner=lambda *_a: (gate.wait(5), [])[1], publisher=lambda *_a: [])
    setup = controller.panel.setup
    setup.probe.click()
    settle(qtbot, controller)
    setup.run.click()
    setup.confirm.click()
    qtbot.waitUntil(lambda: controller.running is not None, timeout=5000)
    assert not setup.browse.isEnabled() and not setup.probe.isEnabled() and not setup.run.isEnabled()
    select(controller)
    assert controller.panel.changes.copy.isEnabled() and controller.panel.changes.detail.toPlainText()
    gate.set()
    settle(qtbot, controller)


def test_the_default_probe_and_run_helpers_refuse_a_relative_path_and_equal_files():
    assert capa_exec.path_error('') and capa_exec.path_error('capa') and capa_exec.path_error(EXE) is None
    assert capa_exec.usable(None, EXE, 'vivisect') == 'Probe the program first.'
    assert capa_exec.usable(GOOD, EXE, 'vivisect') is None
    assert 'path changed' in capa_exec.usable(GOOD, str(Path(EXE).with_name('other')), 'vivisect')
    assert 'backend changed' in capa_exec.usable(GOOD, EXE, 'ghidra')


def test_table_columns_follow_the_specified_headers(qtbot, tmp_path):
    controller = start(qtbot, tmp_path, delta_of(change('a.rule')))
    headers = [column.title for column in capa_data.COLUMNS]
    assert headers[:5] == ['Capability', 'Older', 'Newer', 'Change', 'Function pair (older to newer)']
    assert controller.panel.changes.table.table_model.texts_at(0)[1:3] == ('absent', 'present, 1 match')
    assert ViewOptions().filter == 'changes'


# ---- the declaration ----------------------------------------------------------------------------------------------

def test_the_panel_declaration_matches_its_manifest_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'capabilities'])
    assert loaded.specs['capabilities'] is PANEL and not loaded.errors and not loaded.forbidden
    assert (PANEL.area, PANEL.tabify_with, PANEL.shortcut, PANEL.focus_order) == ('bottom', 'graph', 'Ctrl+Shift+A', 150)
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'capabilities'] == []


def test_loading_the_declaration_imports_no_qt_and_no_feature_ui():
    src = Path(__file__).resolve().parents[1] / 'src'
    code = (f'import sys; sys.path.insert(0, {str(src)!r}); import patchtrace.intelligence.tools.capa_panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_", "patchtrace.gui.qt"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0
