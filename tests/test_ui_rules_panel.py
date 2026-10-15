# ruff: noqa: F811
"""Detection rules dock (YRX R6b): every state, hostile text, names and tips, anchors, stale-result and shutdown handling
(offscreen Qt). The controller is driven through fake panel ports; rows are hand-built contract records, so no YARA-X
engine is needed (the panel reads stored rows and never loads the engine)."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import HOSTILE_PARAMS, a11y_audit, join_gui_threads, top_level_windows  # noqa: F401
from test_tooltips import audit as tooltip_audit

from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.panel_manifest import MANIFEST
from patchtrace.rules import store as rule_store
from patchtrace.rules import tables as tb
from patchtrace.rules import view_model as vm
from patchtrace.rules.contracts import (
    BytesFeature,
    CellResult,
    EngineStamp,
    FunctionRef,
    Gate,
    MatrixRun,
    PairSource,
    RuleCandidate,
    RunRule,
    StringFeature,
    TargetRef,
    pattern_metrics,
    rule_text_sha256,
)
from patchtrace.rules.errors import RuleError
from patchtrace.rules.panel import PANEL
from patchtrace.rules.qt_panel import RulesController

KEY = FakeProject().key()
NOW = '2026-10-14T09:00:00+00:00'
ENGINE = EngineStamp(version='1.21.0', version_source='pin')
PATTERN = ' '.join(['4D', '5A', '90', '00'] * 4)
GATES = ('elig', 'len', 'wild', 'uniq', 'sep', 'compile', 'secret')


class Shell(FakeShell):
    def __init__(self, tasks) -> None:
        super().__init__(tasks)
        self.notices: dict = {}
        self.statuses: list[str] = []

    def notice(self, key, model) -> None:
        self.notices[key] = model

    def status(self, text: str) -> None:
        self.statuses.append(text)


def source(*, key=KEY, run_id=None, revision=None, name='TerminateProcess') -> PairSource:
    older = FunctionRef(name=name, rva=0x1000, size=64, extent='pdata')
    newer = FunctionRef(name=name, rva=0x1080, size=64, extent='pdata')
    return PairSource(project_id='p', revision=revision or key.revision, run_id=run_id or key.run_id,
                      older_sha256=key.older_sha256, newer_sha256=key.newer_sha256, match_id='match-1',
                      category='modified', review='accepted', materiality='material', analyst_confirmed_material=False,
                      older=older, newer=newer)


def candidate(direction='older', *, fill='d', gates=GATES, text_pad=0, **kw) -> RuleCandidate:
    lineage = fill * 64
    name = f'PT_{lineage[:12]}_{direction}'
    text = f'rule {name} {{\n  condition:\n    true\n}}\n' + '// pad\n' * text_pad
    length, literal, run = pattern_metrics(PATTERN)
    features = (
        BytesFeature(included=True, side=direction, window_rva=0x1010, length=length, pattern=PATTERN, literal=literal,
                     longest_run=run, mask_source='iced-x86', source_hits=1, other_hits=0, separation=f'{direction}-only'),
        StringFeature(included=False, side=direction, value_sha256='f' * 64, length=3, text='abc', encoding='ascii',
                      offset=16, evidence_run_id='r', linked_by='xref', separation='both-sides'))
    return RuleCandidate(
        candidate_id=fill * 64, lineage_id=lineage, direction=direction, source=source(**kw), features=features,
        rule_name=name, rule_text=text, rule_sha256=rule_text_sha256(text),
        gates=tuple(Gate(gate_id=g, state='pass', measured=1) for g in gates), engine=ENGINE, unvetted=False,
        compile_warnings=())


def accepted(cand, label='Terminate removed'):
    decision = rule_store.decision_for(cand, 'accept', NOW, label=label)
    return decision, rule_store.version_for(cand, decision, None, rule_store.accepted_text(cand, decision, 1))


def grid_run(version) -> MatrixRun:
    rule = RunRule(version_id=version.version_id, rule_sha256=version.rule_sha256)
    targets = (TargetRef(target_id='t1', label='older.exe', role='older-anchor', sha256='1' * 64, size=10, expect='hit'),
               TargetRef(target_id='t2', label='newer.exe', role='newer-anchor', sha256='2' * 64, size=10, expect='no-hit'),
               TargetRef(target_id='t3', label='big.dll', role='extra', sha256='3' * 64, size=10))
    cells = (CellResult(state='hit', hits=1, offsets=(16,), rvas=(0x1000,), verdict='as-expected'),
             CellResult(state='hit', hits=2, offsets=(32,), rvas=(0x1010,), verdict='unexpected-hit'),
             CellResult(state='not-scanned', reason='too-large'))
    return MatrixRun(run_id='grid-1', cache_key='9' * 64, engine=ENGINE, status='complete', rules=(rule,), targets=targets,
                     cells=cells, limits={}, finished_at=NOW)


def full_store(label='Terminate removed', skipped=0, **kw) -> vm.Stored:
    cand = candidate(**kw)
    decision, version = accepted(cand, label)
    other = candidate('newer', fill='e', **kw)
    return vm.Stored((cand, other), (decision,), (version,), (grid_run(version),), skipped)


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and not controller.loading, timeout=5000)
    QApplication.processEvents()


def start(qtbot, stored, *, project=None, loader=None, show=True):
    project = project or FakeProject()
    shell, nav = Shell(TaskRunner(reraise=True)), FakeNav()
    ctx = PanelContext(PANEL, project, SimpleNamespace(), nav, shell)
    controller = RulesController(ctx, loader=loader or (lambda _s, _p: stored))
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1100, 800)
    if show:
        controller.panel.show()
    controller.project_changed(project.key())
    settle(qtbot, controller)
    return controller, nav, shell, project


def status(controller) -> tuple[str, str]:
    return controller.panel.state.kind, controller.panel.state.status_label().full_text()


def names(table) -> list[str]:
    model = table.table_model
    return [model.texts_at(i)[0] for i in range(model.rowCount())]


# ---- declaration ----------------------------------------------------------------------------------------------------

def test_declaration_matches_its_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'rules'])
    assert loaded.specs['rules'] is PANEL and not loaded.errors and not loaded.forbidden
    assert (PANEL.area, PANEL.shortcut, PANEL.title) == ('right', 'Ctrl+Shift+R', 'Detection rules')
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'rules'] == []


def test_loading_the_declaration_imports_no_qt_no_engine_no_feature():
    code = ('import sys, patchtrace.rules.panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_", "yara_x", "iced_x86"))]; '
            'sys.exit(1 if bad else 0)')
    env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
    assert subprocess.run([sys.executable, '-c', code], check=False, env=env).returncode == 0


# ---- state matrix ---------------------------------------------------------------------------------------------------

def test_no_project_says_so(qtbot):
    controller, *_ = start(qtbot, vm.Stored(), project=FakeProject(open=False))
    assert status(controller) == ('no-project', 'Open a project to use Detection rules.')


def test_empty_store_is_idle_with_a_hint_not_a_blank_panel(qtbot):
    controller, *_ = start(qtbot, vm.Stored())
    kind, text = status(controller)
    assert kind == 'idle' and 'no results yet' in text and 'patchtrace rules' in text
    assert not controller.panel.content.isVisible()


def test_loading_then_ready_shows_all_three_tabs(qtbot, monkeypatch):
    release, seen = threading.Event(), []
    real = tb.build

    def slow(stored, token=None):
        seen.append(token)
        release.wait(5)
        return real(stored, token)
    monkeypatch.setattr(tb, 'build', slow)
    # start() settles, so drive the load by hand to observe the loading state
    project = FakeProject()
    shell = Shell(TaskRunner(reraise=True))
    ctx = PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), shell)
    controller = RulesController(ctx, loader=lambda _s, _p: full_store())
    qtbot.addWidget(controller.panel)
    controller.panel.show()
    controller.project_changed(project.key())
    assert status(controller)[0] == 'loading' and 'Loading stored rules' in status(controller)[1]
    release.set()
    settle(qtbot, controller)
    assert status(controller) == ('ready', '') and controller.panel.content.isVisible()
    assert [controller.panel.tabs.tabText(i) for i in range(3)] == list(('Proposed rules', 'Test grid', 'Saved rules'))


def test_ready_lists_rules_with_status_checks_and_tests(qtbot):
    controller, *_ = start(qtbot, full_store())
    model = controller.panel.candidates.table_model
    assert model.rowCount() == 2
    older = next(model.texts_at(i) for i in range(2) if model.texts_at(i)[1] == 'Older build')
    assert older[3] == 'Accepted' and older[4] == '7 of 7 pass' and older[5] == '1 of 2 included'
    assert older[6] == '2 match, 0 no match, 1 unknown of 3 files'   # t3 not scanned is unknown, not "no match"
    assert 'TerminateProcess at 0x1000' == older[2]
    other = next(model.texts_at(i) for i in range(2) if model.texts_at(i)[1] == 'Newer build')
    assert other[3] == 'Proposed' and other[6] == 'No saved version'


def test_selecting_a_rule_fills_features_checks_and_the_exact_text(qtbot):
    stored = full_store()
    controller, *_ = start(qtbot, stored)
    controller.panel.candidates.selectRow(0)
    cand = controller.current_candidate()
    assert controller.panel.rule_text.toPlainText() == cand.rule_text
    features = controller.panel.features.table_model
    assert features.rowCount() == 2 and features.texts_at(0)[:2] == ('Included', 'Bytes')
    assert features.texts_at(1)[:2] == ('Shown only', 'String') and features.texts_at(1)[3:5] == ('Present', 'Present')
    assert controller.panel.checks.table_model.rowCount() == 7
    assert 'Long enough' in controller.panel.checks.table_model.texts_at(1)[0]
    assert controller.panel.copy_button.isEnabled() and controller.panel.open_button.isEnabled()


def test_missing_other_side_counts_are_unknown_not_zero():
    cand = candidate()
    feature = cand.features[0].model_copy(update={'other_hits': None, 'separation': 'unknown'})
    shown = vm.feature_rows(cand.model_copy(update={'features': (feature, cand.features[1])}))
    assert shown[0].newer.startswith('Unknown') and shown[0].older.startswith('Unknown')


def test_grid_keeps_raw_results_separate_from_expectations(qtbot):
    controller, *_ = start(qtbot, full_store())
    grid = controller.panel.grid.table_model
    assert grid.columnCount() == 6 and grid.rowCount() == 3
    assert grid.headerData(5, __import__('PySide6.QtCore', fromlist=['Qt']).Qt.Orientation.Horizontal).startswith('v1 ')
    rows = {grid.texts_at(i)[1]: grid.texts_at(i) for i in range(3)}
    assert rows['older.exe'][5] == 'Match (1); as expected' and rows['older.exe'][3] == 'Expect match'
    assert rows['newer.exe'][5] == 'Match (2); unexpected match'
    assert rows['big.dll'][5] == 'Not scanned: file is larger than the limit' and rows['big.dll'][3] == 'No expectation'
    assert 'No match' not in rows['big.dll'][5]


def test_grid_filters_narrow_the_rows_and_unknown_stays_visible_by_default(qtbot):
    controller, *_ = start(qtbot, full_store())
    panel = controller.panel
    assert panel.grid.table_model.rowCount() == 3
    panel.unexpected.setChecked(True)
    assert names_of(panel) == ['newer.exe']
    panel.unexpected.setChecked(False)
    panel.result.setCurrentIndex(panel.result.findData('not-scanned'))
    assert names_of(panel) == ['big.dll']
    panel.result.setCurrentIndex(0)
    panel.role.setCurrentIndex(panel.role.findData('older-anchor'))
    assert names_of(panel) == ['older.exe']


def names_of(panel) -> list[str]:
    model = panel.grid.table_model
    return [model.texts_at(i)[1] for i in range(model.rowCount())]


def test_saved_tab_lists_versions_with_their_test_state(qtbot):
    controller, *_ = start(qtbot, full_store())
    model = controller.panel.saved.table_model
    assert model.rowCount() == 1
    assert model.texts_at(0)[:3] == ('Terminate removed', 'v1', '2 match, 0 no match, 1 unknown of 3 files')


def test_partial_when_stored_rows_could_not_be_read_and_it_is_a_notice_too(qtbot):
    controller, _, shell, _ = start(qtbot, full_store(skipped=2))
    kind, text = status(controller)
    assert kind == 'partial' and '2 stored rule rows could not be read' in text and 'unknown, not disagreement' in text
    assert controller.panel.content.isVisible()
    assert shell.notices['rules.partial'].level == 'caution'


@pytest.mark.parametrize('what', ['builds', 'run', 'revision'])
def test_stale_when_the_rows_describe_another_analysis(qtbot, what):
    kw = {'revision': 99} if what == 'revision' else {'run_id': 'old-run'} if what == 'run' else {}
    stored = full_store(**kw)
    if what == 'builds':
        key = KEY._replace(older_sha256='9' * 64)
        project = FakeProject()
        project.key = lambda: key
    else:
        project = None
    controller, _, shell, _ = start(qtbot, stored, project=project)
    kind, text = status(controller)
    assert kind == 'stale' and 'shown for reference only' in text
    assert controller.panel.content.isVisible() and controller.panel.candidates.table_model.rowCount() == 2
    assert 'rules.stale' in shell.notices and 'rules.partial' not in {k for k, v in shell.notices.items() if v}


@pytest.mark.parametrize('failure', [RuleError('PT-RULE-STORAGE', 'C:\\secret\\path'), sqlite3.OperationalError('token=abc')],
                         ids=['rule-error', 'sqlite'])
def test_error_shows_a_code_and_class_never_the_exception_text(qtbot, failure):
    def boom(_s, _p):
        raise failure
    controller, *_ = start(qtbot, None, loader=boom)
    kind, text = status(controller)
    assert kind == 'error' and 'Earlier results are unchanged' in text
    assert 'secret' not in text and 'token' not in text and type(failure).__name__ in text
    assert controller.panel.state.action_button('retry').isVisibleTo(controller.panel)


def test_retry_reads_again_and_recovers(qtbot):
    calls = []

    def flaky(_s, _p):
        calls.append(1)
        if len(calls) == 1:
            raise RuleError('PT-RULE-STORAGE', 'x')
        return full_store()
    controller, *_ = start(qtbot, None, loader=flaky)
    assert status(controller)[0] == 'error'
    controller.panel.state.action_button('retry').click()
    settle(qtbot, controller)
    assert status(controller)[0] == 'ready'


# ---- hostile text ---------------------------------------------------------------------------------------------------

def hostile_store(text: str) -> vm.Stored:
    """Rows as a damaged or tampered database could hand them over (model_copy skips validation on purpose)."""
    cand = candidate()
    ref = cand.source.older.model_copy(update={'name': text})
    cand = cand.model_copy(update={'source': cand.source.model_copy(update={'older': ref})})
    decision, version = accepted(cand)
    decision = decision.model_copy(update={'analyst_label': text, 'note': text})
    return vm.Stored((cand,), (decision,), (version,), (grid_run(version),))


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_text_stays_plain_and_bounded_even_from_a_damaged_row(qtbot, text):
    controller, *_ = start(qtbot, hostile_store(text * 300))
    panel = controller.panel
    panel.candidates.selectRow(0)
    panel.tabs.setCurrentIndex(1)
    shown = panel.detail.toPlainText() + ' '.join(
        ' '.join(m.texts_at(i)) for m in (panel.candidates.table_model, panel.saved.table_model)
        for i in range(m.rowCount()))
    for bad in ('\x1b', '\u202e', '\u2028', '\x00'):
        assert bad not in shown
    assert len(shown) < 5_000
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QLabel
    assert all(w.textFormat() == Qt.TextFormat.PlainText for w in panel.findChildren(QLabel))


@pytest.mark.parametrize('text', [p for p in HOSTILE_PARAMS if not p.values[0].isprintable() or '\u2028' in p.values[0]])
def test_the_contract_rejects_control_text_before_it_reaches_the_panel(text):
    with pytest.raises(ValueError):
        FunctionRef(name=text, rva=1, size=2, extent='pdata')


def test_the_rule_text_is_shown_and_copied_exactly(qtbot):
    controller, _, shell, _ = start(qtbot, full_store())
    controller.panel.candidates.selectRow(0)
    text = controller.current_candidate().rule_text
    controller.panel.copy_button.click()
    assert shell.copied == [text]


def test_oversize_rule_text_is_refused_not_cut():
    assert vm.clipboard_text('a' * vm.CLIPBOARD_LIMIT) is not None
    assert vm.clipboard_text('a' * (vm.CLIPBOARD_LIMIT + 1)) is None
    assert vm.OVERSIZE == 'Rule text exceeds the clipboard limit. Use Export.'


def test_oversize_copy_says_use_export(qtbot):
    stored = full_store(text_pad=2_500)
    controller, _, shell, _ = start(qtbot, stored)
    assert any(len(c.rule_text) > vm.CLIPBOARD_LIMIT for c in stored.candidates)
    for row in range(2):
        controller.panel.candidates.selectRow(row)
        if len(controller.current_candidate().rule_text) > vm.CLIPBOARD_LIMIT:
            break
    controller.panel.copy_button.click()
    assert shell.copied == [] and vm.OVERSIZE in shell.statuses and (vm.OVERSIZE, False) in shell.announced


# ---- navigation -----------------------------------------------------------------------------------------------------

def test_open_pair_emits_a_pinned_match_anchor_with_an_explicit_side(qtbot):
    controller, nav, *_ = start(qtbot, full_store())
    panel = controller.panel
    row = next(i for i in range(2) if panel.candidates.table_model.texts_at(i)[1] == 'Newer build')
    panel.candidates.selectRow(row)
    panel.open_button.click()
    (anchor,) = nav.anchors
    assert (anchor.kind, anchor.key, anchor.side, anchor.run_id, anchor.revision) == ('match', 'match-1', 'newer', 'run-1', 1)


def test_a_failed_navigation_is_said_in_words_and_changes_nothing(qtbot):
    controller, nav, shell, _ = start(qtbot, full_store())
    nav.navigate = lambda anchor: __import__('patchtrace.gui.anchors', fromlist=['NavResult']).NavResult.stale()
    controller.panel.candidates.selectRow(0)
    controller.panel.open_button.click()
    assert shell.statuses and shell.statuses[-1].startswith('The project changed')


def test_show_anchor_selects_a_rule_by_its_immutable_id(qtbot):
    stored = full_store()
    controller, *_ = start(qtbot, stored)
    version = stored.versions[0]
    assert controller.show_anchor(AnchorRef('rule', version.version_id)).status == 'shown'
    assert controller.panel.tabs.currentIndex() == 2
    assert controller.show_anchor(AnchorRef('rule', stored.candidates[1].candidate_id)).status == 'shown'
    assert controller.panel.tabs.currentIndex() == 0
    assert controller.show_anchor(AnchorRef('rule', 'f' * 64, label='gone')).status == 'not-found'
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2026-0001')).status == 'blocked'


# ---- accessibility and tips ----------------------------------------------------------------------------------------

def audit(widget) -> list[str]:
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


@pytest.mark.parametrize('stored', [vm.Stored(), None, 'full'], ids=['idle', 'error', 'ready'])
def test_a11y_audit_is_clean_in_every_shape(qtbot, stored):
    def boom(_s, _p):
        raise RuleError('PT-RULE-STORAGE', 'x')
    controller, *_ = start(qtbot, full_store() if stored == 'full' else stored, loader=boom if stored is None else None)
    if stored == 'full':
        controller.panel.candidates.selectRow(0)
    assert audit(controller.panel) == []


def test_every_control_has_a_tip_name_and_description(qtbot):
    controller, *_ = start(qtbot, full_store())
    tooltip_audit(controller.panel)
    for widget in (controller.panel.tabs, controller.panel.candidates, controller.panel.grid, controller.panel.saved,
                   controller.panel.copy_button):
        assert widget.accessibleName() and widget.accessibleDescription()


def test_no_extra_top_level_window_is_opened(qtbot):
    before = len(top_level_windows())
    controller, *_ = start(qtbot, full_store())
    controller.panel.copy_button.click()
    assert len(top_level_windows()) == before + 1   # the panel under test, shown standalone


# ---- threads --------------------------------------------------------------------------------------------------------

def test_a_late_result_is_dropped_after_the_project_changes(qtbot, monkeypatch):
    release, first_started = threading.Event(), threading.Event()
    real = tb.build
    first, second = full_store(label='first project'), vm.Stored()

    def gated(stored, token=None):
        if stored is first:
            first_started.set()
            release.wait(5)
        return real(stored, token)
    monkeypatch.setattr(tb, 'build', gated)
    project = FakeProject()
    stores = iter([first, second])
    shell = Shell(TaskRunner(reraise=True))
    ctx = PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), shell)
    controller = RulesController(ctx, loader=lambda _s, _p: next(stores))
    qtbot.addWidget(controller.panel)
    controller.panel.show()
    controller.project_changed(project.key())
    qtbot.waitUntil(first_started.is_set, timeout=5000)
    controller.project_changed(project.key()._replace(project_id='other'))
    release.set()
    qtbot.waitUntil(lambda: status(controller)[0] == 'idle', timeout=5000)
    qtbot.wait(50)
    controller.tasks.shutdown()
    assert controller.panel.candidates.table_model.rowCount() == 0 and controller.panel.saved.table_model.rowCount() == 0
    assert controller.stored is not None and controller.stored.empty


def test_a_result_for_another_key_is_ignored_even_if_delivered(qtbot):
    controller, *_ = start(qtbot, full_store())
    stale = tb.build(vm.Stored())
    controller._built((KEY._replace(project_id='elsewhere'), stale))
    assert controller.panel.candidates.table_model.rowCount() == 2


def test_shutdown_cancels_the_worker_and_is_idempotent(qtbot, monkeypatch):
    started, tokens = threading.Event(), []
    real = tb.build

    def waits(stored, token=None):
        tokens.append(token)
        started.set()
        token.wait(5)
        return real(stored, token)
    monkeypatch.setattr(tb, 'build', waits)
    project = FakeProject()
    shell = Shell(TaskRunner(reraise=True))
    ctx = PanelContext(PANEL, project, SimpleNamespace(), FakeNav(), shell)
    controller = RulesController(ctx, loader=lambda _s, _p: full_store())
    qtbot.addWidget(controller.panel)
    controller.project_changed(project.key())
    qtbot.waitUntil(started.is_set, timeout=5000)
    controller.shutdown()
    controller.shutdown()
    qtbot.waitUntil(lambda: tokens[0].is_set(), timeout=5000)
    assert controller.tasks.shutdown() == [] and not controller.tasks.busy()
    assert controller.stored is None
