"""WB3-S7b Strings dock: states, hostile text, accessibility, late results, shutdown, declaration (offscreen Qt).

The controller is driven through fake panel ports; the loader is injected so no file is read except in the one
test of the real built-in scan, which reads small synthetic files and runs nothing."""
from __future__ import annotations

import hashlib
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

from PySide6.QtWidgets import QApplication
from qt_support import a11y_audit, join_gui_threads, top_level_windows  # noqa: F401
from test_strings_view_model import change, delta

from patchtrace.gui import registry
from patchtrace.gui.anchors import AnchorRef
from patchtrace.gui.projection import ProjectKey
from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.gui.registry import PanelContext
from patchtrace.panel_manifest import MANIFEST
from patchtrace.strings import copy
from patchtrace.strings.panel import PANEL
from patchtrace.strings.qt_panel import Loaded, Request, StringsController, scan_builtin
from patchtrace.strings.view_model import build_rows

HOSTILE = '<b>x</b>&amp; javascript:alert(1)\u202e\nforged line\x1b[31m'


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def key(revision: int = 1, project: str = 'p') -> ProjectKey:
    return ProjectKey('root', project, revision, 'run-1', sha('o'), sha('n'))


class FakeProject:
    def __init__(self, current: ProjectKey | None = None) -> None:
        self.current = current if current is not None else key()

    def key(self):
        return self.current

    def busy(self) -> bool:
        return False

    def artifact_paths(self):
        return ('older.bin', 'newer.bin', sha('o'), sha('n'))


class FakeNav:
    def __init__(self) -> None:
        self.anchors, self.offsets = [], []

    def navigate(self, anchor):
        self.anchors.append(anchor)
        return SimpleNamespace(status='shown', message='')

    def show_raw_offset(self, side, offset) -> None:
        self.offsets.append((side, offset))


class FakeShell:
    def __init__(self) -> None:
        self.tasks = TaskRunner(reraise=True)
        self.announced, self.copied, self.statuses = [], [], []

    def announce(self, text, *, assertive=False) -> None:
        self.announced.append((text, assertive))

    def copy_text(self, text) -> bool:
        self.copied.append(text)
        return True

    def status(self, text) -> None:
        self.statuses.append(text)


def loaded_of(*changes, comparable=True, notes=(), partial=()) -> Loaded:
    d = delta(*changes, comparable=comparable, notes=notes)
    return Loaded(d, build_rows(d), {c.id: c for c in d.changes}, partial)


SAMPLE = loaded_of(change('alpha text', tier=3), change(HOSTILE, status='only-older', tier=2),
                   change('same', status='both'))


def start(qtbot, loader=None, *, project=None, scan=True):
    project = project or FakeProject()
    shell, nav = FakeShell(), FakeNav()
    ctx = PanelContext(PANEL, project, SimpleNamespace(), nav, shell)
    controller = StringsController(ctx, loader=loader or (lambda *_: SAMPLE))
    qtbot.addWidget(controller.widget())
    controller.widget().resize(1100, 600)
    controller.widget().show()
    controller.project_changed(project.key())
    if scan:
        controller.scan()
        settle(qtbot, controller)
    return controller, nav, shell, project


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and controller.progress is None, timeout=5000)
    QApplication.processEvents()


def status(controller) -> str:
    return controller.view.status_label().full_text()


def table_texts(controller) -> list[tuple[str, ...]]:
    model = controller.panel.table.table_model
    return [model.texts_at(i) for i in range(model.rowCount())]


# ---- states ------------------------------------------------------------------------------------------------------

def test_no_project_and_idle(qtbot):
    controller, *_ = start(qtbot, scan=False)
    controller.project_changed(None)
    assert controller.view.kind == 'no-project' and status(controller) == copy.STATES['no-project']
    assert not controller.panel.buttons['scan'].isEnabled()
    controller.project_changed(key())
    assert controller.view.kind == 'idle' and status(controller) == copy.STATES['no-data']
    assert controller.panel.buttons['scan'].isEnabled()


def test_ready_lists_differences_in_review_order(qtbot):
    controller, *_ = start(qtbot)
    assert controller.view.kind == 'ready'
    assert status(controller) == copy.STATES['ready'].format(n=2)
    assert len(table_texts(controller)) == 2  # 'both' is not a difference
    assert controller.panel.table.isVisibleTo(controller.widget())


def test_ready_without_differences_says_what_is_not_covered(qtbot):
    controller, *_ = start(qtbot, lambda *_: loaded_of(change('same', status='both')))
    assert controller.view.kind == 'ready' and status(controller) == copy.STATES['ready-none']
    assert table_texts(controller) == []


def test_blocked_hides_the_table_and_gives_the_reason(qtbot):
    controller, *_ = start(qtbot, lambda *_: loaded_of(comparable=False, notes=('min length differs',)))
    assert controller.view.kind == 'blocked' and 'min length differs' in status(controller)
    assert not controller.panel.table.isVisibleTo(controller.widget())
    assert controller.panel.buttons['scan'].isEnabled()


def test_partial_keeps_the_rows_and_names_the_side(qtbot):
    controller, *_ = start(qtbot, lambda *_: loaded_of(change('x' * 8, tier=2), partial=(('older', '200000'),)))
    assert controller.view.kind == 'partial'
    assert status(controller) == copy.STATES['incomplete'].format(side='older', limit='200000')
    assert controller.panel.table.isVisibleTo(controller.widget()) and len(table_texts(controller)) == 1


def test_error_keeps_earlier_results_and_offers_retry_and_copy(qtbot):
    calls = []

    def loader(request, token, report):
        calls.append(request)
        if len(calls) == 2:
            return 'PT-STR-INPUT', 'the artifact cannot be read'
        return SAMPLE
    controller, _, shell, _ = start(qtbot, loader)
    controller.scan()
    settle(qtbot, controller)
    assert controller.view.kind == 'error' and 'PT-STR-INPUT' in status(controller)
    assert 'Earlier results were not changed' in status(controller)
    assert len(table_texts(controller)) == 2 and controller.panel.table.isVisibleTo(controller.widget())
    assert controller.view.action_button('retry').isVisibleTo(controller.widget())
    controller.view.action_button('copy').click()
    assert 'PT-STR-INPUT' in shell.copied[-1]


def test_unexpected_exception_crosses_as_class_only(qtbot):
    def loader(*_):
        raise RuntimeError('C:\\secret\\path.bin')
    controller, *_ = start(qtbot, loader)
    assert controller.view.kind == 'error' and 'RuntimeError' in status(controller)
    assert 'secret' not in status(controller)


def test_loading_then_cancel_keeps_earlier_state(qtbot):
    release = threading.Event()

    def loader(request, token, report):
        report('older', 1, 2)
        release.wait(5)
        return SAMPLE
    controller, *_ = start(qtbot, loader, scan=False)
    controller.scan()
    qtbot.waitUntil(lambda: controller.view.kind == 'loading', timeout=5000)
    assert status(controller).startswith('Reading strings from the older build (1 of 2)')
    assert controller.panel.buttons['cancel'].isEnabled() and not controller.panel.buttons['scan'].isEnabled()
    controller.cancel()
    release.set()
    settle(qtbot, controller)
    assert controller.view.kind == 'cancelled' and controller.loaded is None


def test_stale_when_the_same_project_changes_revision(qtbot):
    controller, _, _, project = start(qtbot)
    controller.project_changed(key(revision=2))
    assert controller.view.kind == 'stale' and status(controller) == copy.STATES['stale']
    assert len(table_texts(controller)) == 2 and controller.view.action_button('refresh').isVisibleTo(
        controller.widget())
    assert not controller.panel.buttons['hex'].isEnabled()  # never open bytes of a file that was not scanned


def test_too_large_is_said_in_words(qtbot, monkeypatch):
    monkeypatch.setattr('patchtrace.gui.table_spec.MAX_ROWS', 1)
    controller, *_ = start(qtbot)
    assert controller.view.kind == 'too-large' and status(controller).startswith('Too many strings to display')


# ---- filters and text --------------------------------------------------------------------------------------------

def test_change_filter_and_text_filter_narrow_the_list(qtbot):
    controller, *_ = start(qtbot)
    panel = controller.panel
    panel.change.setCurrentIndex(panel.change.findData('only-older'))
    qtbot.waitUntil(lambda: len(table_texts(controller)) == 1, timeout=5000)
    panel.change.setCurrentIndex(panel.change.findData('changed'))
    qtbot.waitUntil(lambda: len(table_texts(controller)) == 2, timeout=5000)
    panel.search.setText('alpha')
    assert len(table_texts(controller)) == 1


def test_hostile_text_is_escaped_bounded_and_never_markup(qtbot):
    controller, _, shell, _ = start(qtbot)
    rows = table_texts(controller)
    cells = ' '.join(c for row in rows for c in row)
    for bad in ('\u202e', '\n', '\x1b'):
        assert bad not in cells
    assert '<b>x</b>' in cells  # plain text sink: shown literally, never interpreted
    controller.panel.table.selectAll()
    controller.copy_escaped()
    copied = shell.copied[-1]
    assert '\u202e' not in copied and '\x1b' not in copied and len(copied.splitlines()) == 2
    controller.panel.table.selectRow(0)
    detail = controller.panel.detail.toPlainText()
    assert len(detail) <= 8_192 and '\u202e' not in detail and '\x1b' not in detail
    long = loaded_of(change('A' * 256, tier=1, length=900))
    controller.loader = lambda *_: long
    controller.scan()
    settle(qtbot, controller)
    assert all(len(c) <= 1_000 for row in table_texts(controller) for c in row)


def test_new_window_is_never_opened(qtbot):
    before = top_level_windows()
    controller, *_ = start(qtbot)
    controller.panel.table.selectRow(0)
    assert [w for w in top_level_windows() if w not in before and w is not controller.widget()] == []


# ---- accessibility -----------------------------------------------------------------------------------------------

def test_a11y_audit_is_clean_in_every_state(qtbot):
    controller, *_ = start(qtbot)
    allowed = 'QHeaderView#?: not keyboard focusable'
    for state in ('ready', 'blocked', 'partial', 'error', 'idle'):
        if state == 'blocked':
            controller.loader = lambda *_: loaded_of(comparable=False, notes=('x',))
        elif state == 'partial':
            controller.loader = lambda *_: loaded_of(change('abcd', tier=1), partial=(('newer', '9'),))
        elif state == 'error':
            controller.loader = lambda *_: ('PT-STR-INPUT', 'bad')
        if state == 'idle':
            controller.project_changed(None)
            controller.project_changed(key())
        elif state != 'ready':
            controller.scan()
            settle(qtbot, controller)
        assert [p for p in a11y_audit(controller.widget()) if p != allowed] == [], state
    for button in controller.panel.buttons.values():
        assert button.accessibleName() and button.toolTip()


# ---- epochs, late results, shutdown -----------------------------------------------------------------------------

def test_late_result_is_dropped_after_a_project_switch(qtbot):
    release = threading.Event()
    started = threading.Event()

    def loader(request, token, report):
        started.set()
        release.wait(5)
        return SAMPLE
    controller, *_ = start(qtbot, loader, scan=False)
    controller.scan()
    assert started.wait(5)
    controller.project_changed(key(project='other'))
    release.set()
    qtbot.wait(100)
    settle(qtbot, controller)
    assert controller.loaded is None and table_texts(controller) == [] and controller.view.kind == 'idle'


def test_late_result_is_dropped_when_a_newer_scan_replaced_it(qtbot):
    release = threading.Event()
    order = []

    def loader(request, token, report):
        order.append(len(order))
        if len(order) == 1:
            release.wait(5)
            return loaded_of(change('old scan', tier=1))
        return SAMPLE
    controller, *_ = start(qtbot, loader, scan=False)
    controller.scan()
    qtbot.waitUntil(lambda: bool(order), timeout=5000)
    controller.scan()
    release.set()
    settle(qtbot, controller)
    assert len(table_texts(controller)) == 2 and controller.loaded is SAMPLE


def test_shutdown_cancels_the_running_work_and_is_idempotent(qtbot):
    seen = {}
    started = threading.Event()

    def loader(request, token, report):
        seen['token'] = token
        started.set()
        token.wait(5)
        return SAMPLE
    controller, *_ = start(qtbot, loader, scan=False)
    controller.scan()
    assert started.wait(5)
    controller.shutdown()
    controller.shutdown()
    assert seen['token'].is_set()
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    assert controller.loaded is None
    controller.scan()  # a closed panel starts nothing
    assert not controller.tasks.busy()


# ---- navigation --------------------------------------------------------------------------------------------------

def test_open_hex_uses_the_scanned_side_offset(qtbot):
    controller, nav, shell, _ = start(qtbot)
    controller.panel.table.selectRow(0)
    assert controller.panel.buttons['hex'].isEnabled()
    controller.open_hex()
    assert nav.offsets and nav.offsets[0][0] in ('older', 'newer')
    assert 'different place' in shell.announced[-1][0]


def test_open_function_needs_exactly_one_supported_link(qtbot):
    from test_strings_view_model import link
    linked = loaded_of(change('linked text', tier=1, links=[link()]))
    controller, nav, *_ = start(qtbot, lambda *_: linked)
    controller.panel.table.selectRow(0)
    assert controller.panel.buttons['function'].isEnabled()
    controller.open_function()
    anchor = nav.anchors[0]
    assert (anchor.kind, anchor.key, anchor.run_id) == ('function', 'm1', 'run-1')
    other, *_ = start(qtbot)
    other.panel.table.selectRow(0)
    assert not other.panel.buttons['function'].isEnabled()


def test_string_anchor_selects_misses_and_is_ambiguous(qtbot):
    controller, *_ = start(qtbot)
    shown = next(r for r in controller.loaded.rows if r.status == 'only-older')
    hidden = next(r for r in controller.loaded.rows if r.status == 'both')
    assert controller.show_anchor(AnchorRef('string', shown.value_sha256, 'older')).status == 'shown'
    assert controller.current_row().id == shown.id
    assert controller.show_anchor(AnchorRef('string', hidden.value_sha256)).status == 'blocked'
    assert controller.show_anchor(AnchorRef('string', sha('nothing'))).status == 'not-found'
    assert controller.show_anchor(AnchorRef('cve', 'CVE-2099-0001')).status == 'blocked'


# ---- the real built-in scan and the declaration -----------------------------------------------------------------

def test_builtin_scan_reads_two_files_without_running_them(tmp_path):
    older, newer = tmp_path / 'a.bin', tmp_path / 'b.bin'
    older.write_bytes(b'\x00\x01common text\x00removed message\x00')
    newer.write_bytes(b'\x00\x01common text\x00added message\x00')
    request = Request(key(), older, newer, hashlib.sha256(older.read_bytes()).hexdigest(),
                      hashlib.sha256(newer.read_bytes()).hexdigest())
    reported = []
    loaded = scan_builtin(request, threading.Event(), lambda *a: reported.append(a))
    assert reported == [('older', 1, 2), ('newer', 2, 2)]
    assert {c.display for c in loaded.delta.changes} == {'removed message', 'added message'}
    assert {r.status for r in loaded.rows} == {'only-older', 'only-newer'}


def test_the_panel_declaration_matches_its_manifest_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'strings'])
    assert loaded.specs['strings'] is PANEL and not loaded.errors and not loaded.forbidden
    assert (PANEL.area, PANEL.tabify_with, PANEL.shortcut, PANEL.title) == ('bottom', 'graph', 'Ctrl+Shift+T',
                                                                           'Strings')
    report = registry.lint(MANIFEST, loaded)
    assert [f for f in report.findings if f.panel == 'strings'] == []


def test_loading_the_declaration_imports_no_qt():
    code = (f'import sys; sys.path.insert(0, {str(Path(registry.__file__).parents[2])!r}); '
            'import patchtrace.strings.panel as p; '
            'bad = [m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui_", "patchtrace.gui.qt"))]; '
            'sys.exit(1 if bad else 0)')
    assert subprocess.run([sys.executable, '-I', '-c', code], check=False).returncode == 0


# ---- function pairing --------------------------------------------------------------------------------------------

def paired_loaded(*changes, reason=None):
    d = delta(*changes)
    return Loaded(d, build_rows(d, unknown_reason=reason), {c.id: c for c in d.changes}, (), reason)


def function_column(controller) -> list[str]:
    return [texts[5] for texts in table_texts(controller)]


def test_function_column_says_unknown_with_the_reason_when_no_pairing_exists(qtbot):
    reason = 'the project has no completed analysis with matched functions'
    controller, *_ = start(qtbot, lambda *_: paired_loaded(change('alpha text', tier=3), reason=reason))
    assert function_column(controller) == [f'Unknown: {reason}']
    assert reason in controller.panel.pairing.full_text()


def test_function_column_names_a_linked_function_and_its_pair_state(qtbot):
    from test_strings_view_model import record_link
    linked = paired_loaded(change('linked text', tier=1, links=[record_link('newer', 'fn-1', 'm7')]),
                           change('plain text', tier=3))
    controller, *_ = start(qtbot, lambda *_: linked)
    assert function_column(controller) == ['ParseHeader (modified)', 'No supported function link']
    assert controller.panel.pairing.full_text() == '1 of 2 strings have a function link.'


def test_open_function_opens_the_function_record_of_a_unique_match(qtbot):
    from test_strings_view_model import record_link
    both = [record_link('older', 'fo', 'm9'), record_link('newer', 'fn', 'm9')]
    controller, nav, *_ = start(qtbot, lambda *_: paired_loaded(change('shared text', status='edited', links=both)))
    controller.panel.table.selectRow(0)
    assert controller.panel.buttons['function'].isEnabled()
    controller.open_function()
    anchor = nav.anchors[0]
    assert (anchor.kind, anchor.key, anchor.side) == ('function', 'fo', 'older')


def test_open_function_stays_disabled_when_two_functions_use_the_string(qtbot):
    from test_strings_view_model import record_link
    split = [record_link('newer', 'f1', 'm1'), record_link('newer', 'f2', 'm2')]
    controller, nav, *_ = start(qtbot, lambda *_: paired_loaded(change('split text', links=split)))
    controller.panel.table.selectRow(0)
    assert not controller.panel.buttons['function'].isEnabled()
    controller.open_function()
    assert nav.anchors == []


def test_linked_only_filter_hides_unlinked_strings_and_changes_no_store(qtbot):
    from test_strings_view_model import record_link
    linked = paired_loaded(change('linked text', tier=1, links=[record_link('newer', 'fn-1', 'm7')]),
                           change('plain text', tier=3))
    controller, *_ = start(qtbot, lambda *_: linked)
    assert len(table_texts(controller)) == 2
    controller.panel.linked.setChecked(True)
    qtbot.waitUntil(lambda: len(table_texts(controller)) == 1, timeout=5000)
    assert table_texts(controller)[0][1] == 'linked text' and len(controller.loaded.rows) == 2


def test_the_scan_reads_the_project_snapshot_and_root_for_pairing(qtbot):
    seen = []
    project = FakeProject()
    snapshot = SimpleNamespace(id='p', matches=[], runs=[])
    project.project = lambda: snapshot
    project.service = SimpleNamespace(root='/the/root')

    def loader(request, token, report):
        seen.append(request)
        return SAMPLE
    controller, *_ = start(qtbot, loader, project=project)
    assert seen[0].project is snapshot and Path(seen[0].root) == Path('/the/root')


def test_the_real_scan_links_a_literal_to_its_function_and_leaves_the_rest_unlinked(tmp_path):
    from strings_pe import synergy_pair
    from test_strings_links import project as make_project
    from test_strings_links import record
    pair = synergy_pair()
    older, newer = tmp_path / 'older.bin', tmp_path / 'newer.bin'
    older.write_bytes(pair.older)
    newer.write_bytes(pair.newer)
    code_old = 'void ParseHeader(void)\n{\n  log("bad header (%s)\\n");\n}\n'
    code_new = 'void ParseHeader(void)\n{\n  log("bad header (%.64s)\\n");\n}\n'
    matches, *_ = make_project([record('older', 'ParseHeader', code_old)], [record('newer', 'ParseHeader', code_new)])
    snapshot = SimpleNamespace(id='p', matches=matches,
                               runs=[SimpleNamespace(id='r', status='completed', raw_path=None, raw_sha256=None)])
    request = Request(key(), older, newer, hashlib.sha256(pair.older).hexdigest(),
                      hashlib.sha256(pair.newer).hexdigest(), root=tmp_path, project=snapshot)
    loaded = scan_builtin(request, threading.Event(), lambda *a: None)
    assert loaded.pairing_reason is None
    by_text = {row.text: row for row in loaded.rows}
    assert by_text['bad header (%.64s)'].function_cell == 'ParseHeader (modified)'
    assert by_text['debug dump of internal state'].function_cell == 'No supported function link'


def test_the_real_scan_without_a_project_reports_pairing_unknown(tmp_path):
    older, newer = tmp_path / 'a.bin', tmp_path / 'b.bin'
    older.write_bytes(b'\x00\x01common text\x00removed message\x00')
    newer.write_bytes(b'\x00\x01common text\x00added message\x00')
    request = Request(key(), older, newer, hashlib.sha256(older.read_bytes()).hexdigest(),
                      hashlib.sha256(newer.read_bytes()).hexdigest())
    loaded = scan_builtin(request, threading.Event(), lambda *a: None)
    assert loaded.pairing_reason and 'analysis' in loaded.pairing_reason
    assert all(r.function_cell.startswith('Unknown: ') for r in loaded.rows)
