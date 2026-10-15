"""WB1 S7 Search dock: states, hostile text, names and keys, paging, navigation, late results and shutdown (offscreen).

Docs: docs/specs/panels/search.md (draft) sections 4 to 8. The controller runs on fake panel ports and injected
searcher, builder and coverage callables, so no index, project database or network is needed."""
from __future__ import annotations

import re
import threading
from types import SimpleNamespace

import pytest
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads  # noqa: F401

from patchtrace.gui import registry
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.panel_manifest import MANIFEST
from patchtrace.search import view_model as vm
from patchtrace.search.contracts import (
    CoverageEntry,
    Evidence,
    Locator,
    PairExpansion,
    SearchHit,
    SearchResult,
)
from patchtrace.search.errors import SearchError
from patchtrace.search.panel import PANEL
from patchtrace.search.qt_panel import PAGE, SearchController

HOSTILE = '\x00\x1b[31m<script>alert(1)</script>\u202e\nX'
CONTROL = re.compile('[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u2028\\u2029\\u202a-\\u202e\\u2066-\\u2069]')


def hit(index: int = 0, title: str = 'ReadItem', scheme: str = 'function', **extra) -> SearchHit:
    locator = Locator(scheme=scheme, function_id=f'f{index}', side='newer', rva=0x1000 + index,
                      source_ref='s' if scheme != 'function' else None)
    evidence = Evidence(kind='function' if scheme == 'function' else 'string', side='newer', origin='ghidra',
                        title=title, locator=locator, seen_by=('ghidra',), group='fn', digest16='a' * 16)
    return SearchHit(hit_id=f'h{index}', tier=1, change_class=2, components=1, evidence=(evidence,),
                     evidence_total=1, **extra)


def cov(status: str, group: str = 'fn') -> CoverageEntry:
    return CoverageEntry(group=group, kinds=('function',), status=status)


def result(status: str = 'ok', hits=(), **extra) -> SearchResult:
    return SearchResult(status=status, hits=tuple(hits), coverage=(cov('indexed'),), **extra)


class Rig:
    def __init__(self, qtbot, *, searcher=None, builder=None, coverage=None, project=None, open_=True) -> None:
        self.calls: list = []
        self.project = project or FakeProject(open=open_)
        self.nav, self.shell = FakeNav(), FakeShell(TaskRunner(reraise=True))
        ctx = PanelContext(PANEL, self.project, SimpleNamespace(), self.nav, self.shell)
        self.controller = SearchController(ctx, searcher=searcher or self._search, coverage=coverage or self._cov,
                                           builder=builder or (lambda _s, _t, _p: None))
        self.panel = self.controller.panel
        qtbot.addWidget(self.panel)
        self.panel.resize(1000, 600)
        self.panel.show()
        self.controller.project_changed(self.project.key())
        self.qtbot = qtbot
        self.settle()

    def _search(self, _service, request, _cancel):
        self.calls.append(request)
        return result(hits=[hit()], total=1)

    @staticmethod
    def _cov(_service):
        return (cov('indexed'),)

    def settle(self) -> None:
        tasks = self.controller.tasks
        self.qtbot.waitUntil(lambda: not tasks.busy(), timeout=5000)
        QApplication.processEvents()

    def search(self, text: str = 'read') -> None:
        self.panel.query.setText(text)
        self.controller.submit()
        self.settle()

    @property
    def state(self):
        model = self.panel.state.model
        return model.kind, model.text

    def rows(self) -> list[tuple[str, ...]]:
        model = self.panel.table.table_model
        return [model.texts_at(i) for i in range(model.rowCount())]


@pytest.fixture
def rig(qtbot):
    return Rig(qtbot)


# ---- states ------------------------------------------------------------------------------------------------------

def test_q0_without_a_project(qtbot):
    rig = Rig(qtbot, open_=False)
    assert rig.state == ('no-project', 'Open a project to search it.')
    assert not rig.panel.query.isEnabled()


def test_q3_idle_with_an_index(rig):
    assert rig.state[0] == 'idle' and rig.state[1].startswith('Search names, strings, APIs')


def test_q1_not_indexed_offers_to_build(qtbot):
    rig = Rig(qtbot, coverage=lambda _s: (cov('missing'),))
    assert rig.state[1].startswith('Not indexed yet.') and rig.panel.buttons['rebuild'].isEnabled()


@pytest.mark.parametrize('found, kind, start', [
    (result(hits=[hit()], total=1), 'ready', "1 leads for 'read' in everything indexed. Showing 1."),
    (result('no-results'), 'idle', "No results for 'read' in what is indexed (fn indexed)."),
    (SearchResult(status='partial', coverage=(cov('building', 'raw'),)), 'partial', 'No results yet, but the index'),
    (result('too-broad', hits=[hit()], total_capped=True), 'partial', 'More than 20,000 matches'),
    (result('stale', hits=[hit()], total=1), 'stale', 'The project changed after this index was built'),
    (SearchResult(status='unsupported'), 'unsupported', 'Full-text search is unavailable in this build'),
], ids=['ready', 'empty', 'partial', 'too-broad', 'stale', 'unsupported'])
def test_result_states(qtbot, found, kind, start):
    rig = Rig(qtbot, searcher=lambda _s, _r, _c: found)
    rig.search()
    assert rig.state[0] == kind and rig.state[1].startswith(start)
    assert rig.panel.table.isVisibleTo(rig.panel) is bool(found.hits)


def test_error_state_keeps_the_code_and_offers_retry(qtbot):
    def fail(_s, _r, _c):
        raise SearchError('PT-SEARCH-STORE', 'index unreadable')

    rig = Rig(qtbot, searcher=fail)
    rig.search()
    assert rig.state == ('error', 'Search failed: PT-SEARCH-STORE: index unreadable. Your project was not changed.')
    assert rig.panel.state.action_button('retry').isVisibleTo(rig.panel)


def test_an_unexpected_exception_shows_only_its_class(qtbot):
    def fail(_s, _r, _c):
        raise RuntimeError('C:\\secret\\path')

    rig = Rig(qtbot, searcher=fail)
    rig.search()
    assert rig.state[0] == 'error' and 'secret' not in rig.state[1] and 'RuntimeError' in rig.state[1]


def test_invalid_query_says_why_and_searches_nothing(rig):
    rig.search('"')
    assert rig.state[1].startswith('Search query is invalid:') and not rig.calls


def test_build_progress_then_search_again(qtbot):
    seen = []

    def builder(_service, _token, progress):
        progress('fn', 0, 2)
        seen.append('built')

    rig = Rig(qtbot, builder=builder)
    rig.search('read')
    before = len(rig.calls)
    rig.controller.build()
    rig.settle()
    assert seen == ['built'] and len(rig.calls) == before + 1 and rig.controller.progress is None


def test_cancel_reports_cancelled_and_keeps_rows(rig):
    rig.search()
    rig.controller.cancel()
    assert rig.state == ('cancelled', 'Cancelled. Earlier results are unchanged.') and len(rig.rows()) == 1


def test_empty_query_clears_results(rig):
    rig.search()
    rig.search('  ')
    assert rig.rows() == [] and rig.state[0] == 'idle'


def test_side_and_scope_reissue_the_parsed_request(rig):
    rig.search()
    rig.panel.side.setCurrentIndex(2)
    rig.panel.scope.setCurrentIndex(1)
    rig.settle()
    plan = rig.calls[-1].plan
    assert plan.sides == ('newer',) and plan.scope == 'changed'
    rig.panel.sort.setCurrentIndex(2)
    rig.settle()
    assert rig.calls[-1].sort == 'name'


# ---- hostile text ------------------------------------------------------------------------------------------------

def test_hostile_text_is_bounded_and_plain(qtbot):
    rig = Rig(qtbot, searcher=lambda _s, _r, _c: result(hits=[hit(title='A' * 150 + HOSTILE)], total=1))
    rig.search('read')
    cells = rig.rows()[0]
    assert not any(CONTROL.search(c) for c in cells) and all(len(c) <= 600 for c in cells)
    rig.panel.table.selectRow(0)
    detail = rig.panel.detail.toPlainText()
    assert not CONTROL.search(detail.replace('\n', ' ')) and '<script>' in detail  # shown as text, never markup
    assert not CONTROL.search(rig.panel.state.status_label().full_text())
    assert 'script' not in rig.panel.detail.document().toHtml().split('<body')[0]
    rig.search(HOSTILE + 'read')  # a hostile query is parsed, or refused in words; either way the echo is plain
    assert not CONTROL.search(rig.state[1])


# ---- accessibility and tips --------------------------------------------------------------------------------------

def test_a11y_audit_is_clean_and_every_control_has_a_tip(rig):
    rig.search()
    problems = [p for p in a11y_audit(rig.panel) if p != 'QHeaderView#?: not keyboard focusable']
    assert problems == []
    for widget in (rig.panel.query, rig.panel.side, rig.panel.table, *rig.panel.buttons.values()):
        assert widget.accessibleName() and widget.accessibleDescription() and widget.toolTip()


def test_spec_lints_clean_against_its_manifest_slot():
    loaded = registry.load_manifest(MANIFEST)
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'search'] == []


# ---- paging, keys and navigation ---------------------------------------------------------------------------------

def test_a_second_page_is_appended_under_the_same_generation(qtbot):
    pages = [result(hits=[hit(i) for i in range(PAGE)], total=PAGE + 1, cursor='c1'),
             result(hits=[hit(PAGE)], total=PAGE + 1)]
    cursors = []

    def searcher(_s, request, _c):
        cursors.append(request.cursor)
        return pages[len(cursors) - 1]

    rig = Rig(qtbot, searcher=searcher)
    rig.search()
    assert len(rig.rows()) == PAGE
    rig.controller.fetch_more()
    rig.settle()
    assert cursors == [None, 'c1'] and len(rig.rows()) == PAGE + 1
    rig.controller.fetch_more()  # no cursor left: nothing is requested
    assert len(cursors) == 2


def test_enter_on_a_function_row_navigates_with_a_pinned_anchor(rig):
    rig.search()
    rig.panel.table.selectRow(0)
    rig.controller.go()
    anchor = rig.nav.anchors[0]
    assert (anchor.kind, anchor.key, anchor.side, anchor.run_id) == ('function', 'f0', 'newer', 'run-1')


def test_a_result_without_a_route_is_announced_and_navigates_nowhere(qtbot):
    rig = Rig(qtbot, searcher=lambda _s, _r, _c: result(hits=[hit(scheme='export')], total=1))
    rig.search()
    rig.panel.table.selectRow(0)
    rig.controller.go()
    assert rig.nav.anchors == [] and 'no route' in rig.shell.announced[0][0]


def test_other_side_needs_a_counterpart(qtbot):
    pair = PairExpansion(category='modified', counterparts=())
    rig = Rig(qtbot, searcher=lambda _s, _r, _c: result(hits=[hit(expansion=pair)], total=1))
    rig.search()
    rig.panel.table.selectRow(0)
    assert not rig.panel.buttons['other_side'].isEnabled()


def test_copy_puts_the_lead_on_the_clipboard(rig):
    rig.search()
    rig.panel.table.selectRow(0)
    rig.controller.copy()
    assert rig.shell.copied and rig.shell.copied[0].startswith('ReadItem')


def test_coverage_is_shown_in_the_detail_pane_not_a_window(rig):
    rig.search()
    before = len(QApplication.topLevelWidgets())
    rig.controller.show_coverage()
    assert 'fn | - | indexed' in rig.panel.detail.toPlainText()
    assert len(QApplication.topLevelWidgets()) == before


# ---- threads -----------------------------------------------------------------------------------------------------

def test_a_late_result_after_a_project_switch_is_dropped(qtbot):
    gate, started = threading.Event(), threading.Event()

    def slow(_s, _r, _c):
        started.set()
        gate.wait(5)
        return result(hits=[hit()], total=1)

    rig = Rig(qtbot, searcher=slow)
    rig.panel.query.setText('read')
    rig.controller.submit()
    assert started.wait(5)
    old_epoch, old_generation = rig.controller.epoch, rig.controller.generation
    rig.controller.project_changed(rig.project.key())
    gate.set()
    rig.settle()
    assert rig.rows() == []
    rig.controller._arrived(old_epoch, old_generation, SimpleNamespace(result=result(hits=[hit()]), code=''))
    assert rig.rows() == []


def test_shutdown_cancels_the_running_search_and_stops_the_timer(qtbot):
    started, observed = threading.Event(), threading.Event()

    def watch(_s, _r, cancel):
        started.set()
        while not cancel():
            observed.wait(0.01)
        observed.set()
        return result()

    rig = Rig(qtbot, searcher=watch)
    rig.panel.query.setText('read')
    rig.controller.submit()
    assert started.wait(5)
    rig.controller.debounce.start()
    rig.controller.shutdown()
    assert observed.wait(5) and not rig.controller.debounce.isActive()
    rig.controller.shutdown()  # idempotent
    rig.controller.tasks.shutdown()


def test_typing_debounces_into_one_search(rig):
    rig.panel.query.setText('re')
    rig.panel.query.setText('rea')
    assert rig.controller.debounce.isActive() and not rig.calls
    rig.qtbot.waitUntil(lambda: bool(rig.calls), timeout=3000)
    rig.settle()
    assert len(rig.calls) == 1


def test_the_spec_is_pure_until_the_factory_runs():
    import os
    import subprocess
    import sys
    from pathlib import Path
    code = ('import sys; import patchtrace.search.panel; '
            'bad=[m for m in sys.modules if m.split(".")[0] in ("PySide6","networkx")]; print(bad)')
    out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True,
                         env={**os.environ, 'PYTHONPATH': str(Path(__file__).parents[1] / 'src')}).stdout.strip()
    assert out == '[]'
    assert vm.ROW_CAP == 5000
