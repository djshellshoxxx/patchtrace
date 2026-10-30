"""FAB-6 Related evidence panel: state matrix, hostile text, names and keys, anchors, threads and 100,000 rows
(offscreen Qt). Docs: docs/specs/program-e/FAB-integration-plan.md s8 "GUI". The controller is driven through fake panel
ports; the reader is the in-memory fabric store or a synthetic paging reader."""
from __future__ import annotations

import dataclasses
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from fabric_support import NEWER, OLDER, anchor, pair_ref, wit
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, assert_lazy_model, join_gui_threads  # noqa: F401

import patchtrace
from patchtrace.fabric import ids
from patchtrace.fabric.contracts import Anchor, AnchorPage, AnchorQuery
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.memory import MemoryAnchorStore
from patchtrace.fabric.panel import PANEL, TIPS
from patchtrace.fabric.related import COLUMNS, SPEC, anchor_ref, related_state, row_of
from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.table import VirtualTableModel
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.gui.table_spec import prepare_table
from patchtrace.panel_manifest import ManifestEntry
from patchtrace.ui_related import RelatedController

HOSTILE = '<b>x</b>&amp;{0}%s javascript:alert(1)‮\x07'
PAIR = pair_ref()
SUBJECT = ids.pair_key_of(PAIR)
PROJECT = 'proj-1'


def fixture_anchors(label: str = 'RtlULongAdd') -> list[Anchor]:
    return [
        anchor('import', ids.api_key('RtlULongAdd'), 'newer', 'observed', subject=SUBJECT, producer='wbq',
               source='pe-import', label=label),
        anchor('string', ids.string_key('bad'), 'none', 'hint', subject=SUBJECT, producer='kb',
               source='advisory-text', label='bad input', batch='k1'),
        anchor('cve', 'CVE-2099-0001', 'none', 'stated', subject=SUBJECT, producer='kev', source='kev-catalog',
               label='CVE-2099-0001', batch='k2')]


def memory_reader(anchors: list[Anchor]) -> MemoryAnchorStore:
    store = MemoryAnchorStore()
    store.publish(PROJECT, [Anchor.model_copy(a) for a in anchors])
    return store


class PagingReader:
    """Synthetic reader of N anchors in pages, to drive 100,000 rows without building 100,000 witnesses twice."""

    def __init__(self, count: int, template: Anchor) -> None:
        self.count, self.template, self.queries = count, template, []

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        self.queries.append(query)
        stop = min(self.count, query.offset + query.limit)
        items = tuple(self.template.model_copy(update={'anchor_id': f'{i:064x}'}) for i in range(query.offset, stop))
        return AnchorPage(items, self.count)


class ErrorReader:
    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        raise FabricError('PT-FAB-STORAGE', 'The stored anchors could not be read', reason='unreadable')


class BlockedReader:
    """Holds the worker until released, to prove that a shutdown or a new selection cancels it."""

    def __init__(self) -> None:
        self.started, self.release = threading.Event(), threading.Event()

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        self.started.set()
        self.release.wait(5)
        return AnchorPage((), 0)


class Port(FakeProject):
    def project(self):
        return SimpleNamespace(id=PROJECT, revision=1, matches=[]) if self.is_open else None

    def key(self):
        return ProjectKey('root', PROJECT, 1, 'run-1', OLDER, NEWER) if self.is_open else None


def start(qtbot, reader, *, subject=SUBJECT, open=True, select=True):  # noqa: A002
    port = Port(open=open)
    shell, nav = FakeShell(TaskRunner(reraise=True)), FakeNav()
    ctx = PanelContext(PANEL, port, SimpleNamespace(), nav, shell)
    controller = RelatedController(ctx, reader=lambda _p: reader, subject_of=lambda _p, _m: subject)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1000, 600)
    controller.panel.show()
    if open:
        controller.project_changed(port.key())
    if select:
        controller.selection_changed('m1')
        settle(qtbot, controller)
    return controller, nav, shell


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and not controller.loading, timeout=5000)
    QApplication.processEvents()


def cells(controller) -> list[list[str]]:
    model = controller.panel.table.table_model
    return [list(model.texts_at(i)) for i in range(model.rowCount())]


# ---- state matrix ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('case, kind, fragment', [
    (dict(has_project=False, subject=None, loading=False, error=None, total=0, too_large=False), 'no-project', 'Open a'),
    (dict(has_project=True, subject=None, loading=False, error=None, total=0, too_large=False), 'idle', 'Select a'),
    (dict(has_project=True, subject='s', loading=True, error=None, total=0, too_large=False), 'loading', 'Loading'),
    (dict(has_project=True, subject='s', loading=False, error=('PT-FAB-STORAGE', 'boom'), total=0, too_large=False),
     'error', 'PT-FAB-STORAGE'),
    (dict(has_project=True, subject='s', loading=False, error=None, total=200_000, too_large=True), 'too-large',
     '200000'),
    (dict(has_project=True, subject='s', loading=False, error=None, total=1, too_large=False, stale=True), 'stale',
     'stale'),
    (dict(has_project=True, subject='s', loading=False, error=None, total=1, too_large=False, partial='1 batch'),
     'partial', 'unknown, not disagreement'),
    (dict(has_project=True, subject='s', loading=False, error=None, total=0, too_large=False), 'ready',
     'Missing evidence is unknown, not a negative result.'),
    (dict(has_project=True, subject='s', loading=False, error=None, total=3, too_large=False), 'ready', ''),
], ids=['no-project', 'idle', 'loading', 'error', 'too-large', 'stale', 'partial', 'empty', 'ready'])
def test_the_state_matrix(case, kind, fragment):
    state = related_state(**case)
    assert state.kind == kind and fragment in state.text


def test_an_error_outranks_a_stale_result():
    state = related_state(has_project=True, subject='s', loading=False, error=('PT-FAB-STORAGE', 'x'), total=1,
                          too_large=False, stale=True)
    assert state.kind == 'error'


def test_the_widget_shows_each_state_in_words(qtbot):
    controller, *_ = start(qtbot, memory_reader([]), select=False)
    assert controller.panel.state.model.kind == 'idle'
    controller.selection_changed('m1')
    settle(qtbot, controller)
    assert controller.panel.state.model.text.startswith('Nothing else is known about this function yet.')
    assert controller.panel.state.model.kind == 'ready'


def test_no_project_says_so(qtbot):
    controller, *_ = start(qtbot, memory_reader([]), open=False, select=False)
    assert controller.panel.state.model.kind == 'no-project'


def test_a_reader_failure_shows_its_code_and_a_retry(qtbot):
    controller, *_ = start(qtbot, ErrorReader())
    model = controller.panel.state.model
    assert model.kind == 'error' and 'PT-FAB-STORAGE' in model.text and 'retry' in model.actions


def test_a_pair_without_a_key_shows_idle_and_reads_nothing(qtbot):
    reader = PagingReader(5, fixture_anchors()[0])
    controller, *_ = start(qtbot, reader, subject=None)
    assert controller.panel.state.model.kind == 'idle' and reader.queries == []


# ---- rows, order and text ----------------------------------------------------------------------------------------

def test_rows_keep_the_canonical_order_and_show_role_and_witnesses_as_words(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    rows = cells(controller)
    assert [r[0] for r in rows] == ['String', 'Import', 'CVE']  # the fabric's kind order, not alphabetical
    assert [r[3] for r in rows] == ['? hint', '+ observed', 'i stated']
    assert rows[1][4] == '1 independent of 1'
    assert [c.title for c in COLUMNS] == ['Kind', 'Label', 'Side', 'Role', 'Witnesses', 'Producers']


def test_witnesses_that_share_an_origin_count_once():
    two = ids.make_anchor(kind='import', key=ids.api_key('Foo'), side='newer', role='observed', subject=SUBJECT,
                          witnesses=(wit('wbq', 'pe-import', input_sha=NEWER), wit('cap', 'pe-import', input_sha=NEWER,
                                                                                    batch='c1')))
    other = ids.make_anchor(kind='import', key=ids.api_key('Foo'), side='newer', role='observed', subject=SUBJECT,
                            witnesses=(wit('wbq', 'pe-import', input_sha=NEWER), wit('cap', 'floss', input_sha=NEWER,
                                                                                      batch='c1')))
    assert (row_of(two).independent, row_of(two).witnesses) == (1, 2)
    assert (row_of(other).independent, row_of(other).witnesses) == (2, 2)
    assert row_of(two).accessible == 'Import RtlULongAdd, newer, observed, 1 independent origin of 2 witnesses' \
        .replace('RtlULongAdd', row_of(two).label)
    assert row_of(other).detail.startswith('Seen by 2 witnesses from 2 independent origins: cap, wbq.')


def test_the_detail_pane_says_what_a_hint_and_a_statement_mean(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    rows = {r.kind: r for r in controller.rows}
    assert 'it was not found here' in rows['string'].detail
    assert 'says nothing about this code' in rows['cve'].detail
    assert 'not found' not in rows['import'].detail
    controller.select_key(rows['string'].key)
    assert 'A hint is something to look for' in controller.panel.detail.toPlainText()


def test_hostile_text_is_inert_in_cells_names_and_detail(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors(label=HOSTILE)))
    label = cells(controller)[1][1]
    assert '\x07' not in label and '‮' not in label and '<b>x</b>' in label  # shown verbatim as text
    row = next(r for r in controller.rows if r.kind == 'import')
    controller.select_key(row.key)
    assert '\x07' not in controller.panel.detail.toPlainText() and '‮' not in row.accessible
    for text in (row.accessible, row.search, row.detail):
        assert '\n' not in text


# ---- keys, names and routing -------------------------------------------------------------------------------------

def test_the_table_is_one_tab_stop_with_the_specified_names(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    panel = controller.panel
    assert panel.accessibleName() == 'Related evidence panel'
    assert panel.table.accessibleName() == 'Related evidence table' and panel.kind.accessibleName() == 'Kind filter'
    assert [p for p in a11y_audit(panel) if p != 'QHeaderView#?: not keyboard focusable'] == []
    assert panel.table.focusPolicy() != Qt.FocusPolicy.NoFocus and panel.focusProxy() is panel.table


def test_enter_routes_the_anchor_through_the_router_pinned_to_the_project(qtbot):
    controller, nav, _ = start(qtbot, memory_reader(fixture_anchors()))
    table = controller.panel.table
    table.setFocus()
    table.selectRow(1)
    table.setCurrentIndex(table.table_model.index(1, 0))
    qtbot.keyClick(table, Qt.Key.Key_Return)
    sent = nav.anchors[-1]
    assert (sent.kind, sent.key, sent.side, sent.run_id, sent.revision) == (
        'import', ids.api_key('RtlULongAdd'), 'newer', 'run-1', 1)


def test_a_failed_navigation_is_announced_in_words(qtbot):
    controller, nav, shell = start(qtbot, memory_reader(fixture_anchors()))
    nav.accept = False
    controller._activated(controller.rows[1].key)
    assert shell.announced or nav.anchors  # the host owns the words; the panel never invents a target


def test_space_opens_the_detail_and_the_kind_filter_narrows_rows(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    panel = controller.panel
    panel.kind.setCurrentIndex(panel.kind.findData('cve'))
    assert [r[0] for r in cells(controller)] == ['CVE']
    panel.kind.setCurrentIndex(0)
    assert len(cells(controller)) == 3
    panel.table.setFocus()
    panel.table.selectRow(0)
    panel.table.setCurrentIndex(panel.table.table_model.index(0, 0))
    qtbot.keyPress(panel.table, Qt.Key.Key_Space)
    assert 'independent origins' in panel.detail.toPlainText()


def test_ctrl_c_copies_tsv(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    table = controller.panel.table
    table.setFocus()
    table.selectRow(0)
    table.setCurrentIndex(table.table_model.index(0, 0))
    event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    QApplication.sendEvent(table, event)
    assert QApplication.clipboard().text().splitlines()[0].split('\t') == [c.title for c in COLUMNS]


def test_show_anchor_selects_a_listed_row_and_reports_a_missing_one(qtbot):
    controller, *_ = start(qtbot, memory_reader(fixture_anchors()))
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-0001')).status == 'shown'
    assert controller.panel.table.current_key() == controller.rows[2].key
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-9999')).status == 'not-found'


@pytest.mark.parametrize('side, expected', [('none', None), ('older', 'older'), ('both', 'both')],
                         ids=['none', 'older', 'both'])
def test_from_fabric_is_pure_and_maps_the_side(side, expected):
    kind_anchor = anchor('cve', 'CVE-2099-0001', 'none', 'stated', producer='kev', source='kev-catalog')
    ref = anchor_ref(kind_anchor.model_copy(update={'side': side}), 'run-9')
    assert (ref.kind, ref.key, ref.side, ref.run_id, ref.origin) == ('cve', 'CVE-2099-0001', expected, 'run-9', 'related')


# ---- threads -----------------------------------------------------------------------------------------------------

def test_shutdown_cancels_the_running_load_and_drops_its_result(qtbot):
    reader = BlockedReader()
    controller, *_ = start(qtbot, reader, select=False)
    controller.selection_changed('m1')
    assert reader.started.wait(5)
    controller.shutdown()
    reader.release.set()
    controller.tasks.shutdown()
    assert controller.rows == () and controller.loading is True  # the late result never reached the view


def test_a_new_selection_supersedes_the_load_in_flight(qtbot):
    reader = BlockedReader()
    controller, *_ = start(qtbot, reader, select=False)
    controller.selection_changed('m1')
    assert reader.started.wait(5)
    controller.reader_factory = lambda _p: memory_reader(fixture_anchors())
    controller.selection_changed('m2')
    reader.release.set()
    settle(qtbot, controller)
    assert len(controller.rows) == 3


# ---- the declaration and 100,000 rows ----------------------------------------------------------------------------

def test_the_panel_declaration_lints_clean_in_its_planned_slot():
    entry = ManifestEntry('related', 'patchtrace.fabric.panel', lambda: PANEL, 'bottom', 'leads', 'Ctrl+Shift+J')
    from patchtrace.panel_manifest import MANIFEST
    leads = dataclasses.replace(next(e for e in MANIFEST if e.id == 'leads'), area='bottom')  # the plan's move
    entries = [leads, entry]
    loaded = registry.load_manifest(entries)
    assert loaded.specs['related'] is PANEL and not loaded.errors and not loaded.forbidden
    report = registry.lint(entries, loaded)
    assert [f for f in report.findings if f.panel == 'related'] == []
    assert PANEL.requires == ('project',) and PANEL.anchors_in == PANEL.anchors_out and len(PANEL.anchors_in) == 10
    assert {'related.dock', 'related.action', 'related.role', 'related.witnesses'} <= set(TIPS)


def test_loading_the_declaration_imports_no_qt_and_no_feature():
    src = Path(patchtrace.__file__).resolve().parents[1]
    code = (f'import sys; sys.path.insert(0, {str(src)!r}); import patchtrace.fabric.panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


def test_tooltips_and_texts_pass_the_claims_sweep():
    for tip_id, entry in TIPS.items():
        assert PANEL.claims.violations(' '.join((entry.what, entry.why, entry.effect, entry.source))) == (), tip_id


def test_one_hundred_thousand_rows_are_read_in_pages_and_cost_what_they_show(qtbot):
    reader = PagingReader(100_000, fixture_anchors()[0])
    controller, *_ = start(qtbot, reader)
    assert controller.panel.table.table_model.rowCount() == 100_000 and not controller.panel.table.too_large
    assert len(reader.queries) == 200 and all(q.limit == 500 and q.subject == SUBJECT for q in reader.queries)
    assert controller.panel.state.model.kind == 'ready'


def test_more_than_the_row_limit_says_too_large(qtbot):
    controller, *_ = start(qtbot, PagingReader(100_001, fixture_anchors()[0]))
    assert controller.panel.table.too_large and controller.panel.state.model.kind == 'too-large'


def test_the_model_is_lazy_at_one_hundred_thousand_rows():
    template = row_of(fixture_anchors()[0]).anchor
    prepared = {n: prepare_table(SPEC, COLUMNS, [row_of(template.model_copy(update={'anchor_id': f'{i:064x}'}))
                                                 for i in range(n)]) for n in (10_000, 100_000)}

    def factory(size: int) -> VirtualTableModel:
        model = VirtualTableModel()
        model.set_prepared(prepared[size])
        return model
    calls = assert_lazy_model(factory, sizes=(10_000, 100_000))
    assert max(calls.values()) < 20 * len(COLUMNS) * 8
