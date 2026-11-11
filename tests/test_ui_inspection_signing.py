"""The "Version and signing" tab (SPEC-51 D2-5), offscreen: exact copy, plain text for hostile file text, TSV copy,
the signature tree, the worker thread and the Files controller wiring."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from pe_meta_builder import dual_signature, flip, meta_pe
from PySide6.QtCore import QModelIndex, QObject, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtTest import QAbstractItemModelTester, QTest
from PySide6.QtWidgets import QPlainTextEdit

from patchtrace import ui_inspection
from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.artifact_inspection import inspect_project_artifacts
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview import signing_view as sv
from patchtrace.pe_overview.authenticode import TrustResult
from patchtrace.pe_overview.metadata import inspect_metadata
from patchtrace.service import ProjectService
from patchtrace.ui_inspection import FilesController, MetadataThread, SigningTab


def metadata_of(tmp_path, data, name):
    path = tmp_path / name
    path.write_bytes(data)
    with VerifiedArtifactReader.open_path(path) as reader:
        return inspect_metadata(reader, inspect_pe(reader))


@pytest.fixture
def metas(tmp_path):
    older = metadata_of(tmp_path, meta_pe('1.0.0.0', 'asInvoker')[0], 'a.bin')
    newer = metadata_of(tmp_path, meta_pe('1.0.1.0', 'requireAdministrator', signed=False, sections_extra=b'\xCC')[0],
                        'b.bin')
    return {'older': older, 'newer': newer}


def cells(tab):
    model = tab.model
    return {model.rows[r].values[0]: model.rows[r].values for r in range(len(model.rows))}


def test_copy_strings_are_exact():
    assert sv.LOADING == 'Reading version, manifest and signature (read-only)...'
    assert sv.EMPTY == 'This file has no version resource.'
    assert sv.NO_MANIFEST == 'No embedded manifest was found. Sidecar .manifest files are not read.'
    assert sv.BLOCKED == ('Certificate chain trust is only evaluated on Windows. This platform reports the '
                          'signature structure and whether the file digest matches the signature.')
    assert sv.error_text('PT-PE-INPUT') == 'Could not read this section: PT-PE-INPUT. Other sections are unaffected.'


def test_loading_and_error_states(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    assert tab.status.full_text() == sv.LOADING
    tab.set_error('PT-PE-INPUT')
    assert tab.status.full_text() == sv.error_text('PT-PE-INPUT') and tab.model.rowCount() == 0


def test_result_fills_table_manifest_and_tree(qtbot, metas):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result(metas)
    found = cells(tab)
    assert found['File version (fixed)'][:4] == ('File version (fixed)', '1.0.0.0', '1.0.1.0', 'changed')
    assert found['Requested execution level'][1:3] == ('asInvoker', 'requireAdministrator')
    assert tab.model.rows[0].bold and tab.model.rows[0].values[3] == 'changed'
    text = tab.manifest.toPlainText()
    assert 'OLDER' in text and 'requireAdministrator' in text and 'asInvoker' in text
    assert tab.tree_model.rowCount() == 2
    older = tab.tree_model.index(0, 0)
    assert tab.tree_model.index(0, 1).data() == (
        'Signature present, digest matches file; trust not evaluated on this platform')
    assert tab.tree_model.index(1, 1).data() == 'Not signed'
    assert tab.tree_model.rowCount(older) == 1
    assert tab.status.full_text() == ''


def test_blocked_note_shows_off_windows(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.show()
    assert tab.note.isVisible() is (sys.platform != 'win32')
    assert tab.note.full_text() == sv.BLOCKED


def test_empty_state_when_no_side_has_a_version(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    empty = ui_inspection.PeMetadata('ok')
    tab.set_result({'older': empty, 'newer': empty})
    assert tab.status.full_text() == sv.EMPTY
    assert 'No embedded manifest was found' in tab.manifest.toPlainText()


def test_file_text_is_plain_text_everywhere(qtbot, tmp_path):
    evil = '<b>Evil</b> &amp; Co'
    data = meta_pe('1.0.0.0', company=evil, signed=False)[0]
    other = metadata_of(tmp_path, meta_pe('1.0.0.0', signed=False)[0], 'a.bin')
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result({'older': other, 'newer': metadata_of(tmp_path, data, 'b.bin')})
    row = cells(tab)['CompanyName']
    assert row[2] == evil
    index = tab.model.index(list(cells(tab)).index('CompanyName'), 2)
    assert tab.model.data(index) == evil
    assert tab.status.textFormat() == Qt.TextFormat.PlainText and tab.note.textFormat() == Qt.TextFormat.PlainText
    assert isinstance(tab.manifest, QPlainTextEdit) and tab.manifest.isReadOnly()


def test_names_and_object_ids(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    assert (tab.table.objectName(), tab.manifest.objectName(), tab.tree.objectName()) == (
        'pe.version.table', 'pe.manifest.view', 'pe.signature.tree')
    for widget in (tab.table, tab.manifest, tab.tree):
        assert widget.accessibleName() and 'pe.' not in widget.accessibleName()
        assert widget.toolTip() or widget.accessibleDescription()
    assert tab.focusProxy() is tab.table


def test_ctrl_c_copies_selected_rows_as_tsv(qtbot, metas):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result(metas)
    tab.show()
    tab.table.selectRow(0)
    QGuiApplication.clipboard().clear()
    QTest.keyClick(tab.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert QGuiApplication.clipboard().text() == '\t'.join(tab.model.rows[0].values)
    tab.table.selectAll()
    QTest.keyClick(tab.table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    lines = QGuiApplication.clipboard().text().split('\n')
    assert len(lines) == tab.model.rowCount() and all(line.count('\t') == 4 for line in lines)


def test_ctrl_c_copies_tree_nodes(qtbot, metas):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result(metas)
    tab.show()
    tab.tree.setCurrentIndex(tab.tree_model.index(0, 0))
    QTest.keyClick(tab.tree, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert QGuiApplication.clipboard().text() == (
        'OLDER\tSignature present, digest matches file; trust not evaluated on this platform')


def test_tsv_flattens_cells():
    assert sv.tsv([['a\tb', 'c\nd'], ['e', 'f']]) == 'a b\tc d\ne\tf'


def test_tree_model_is_consistent_and_nested_signatures_nest(qtbot, tmp_path):
    data, _info = dual_signature()
    nested = metadata_of(tmp_path, data, 'a.bin')
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result({'older': nested, 'newer': nested})
    QAbstractItemModelTester(tab.tree_model, QAbstractItemModelTester.FailureReportingMode.Fatal)
    top = tab.tree_model.index(0, 0)
    labels = [tab.tree_model.index(r, 0, top).data() for r in range(tab.tree_model.rowCount(top))]
    assert labels == ['Signature 1']
    first = tab.tree_model.index(0, 0, top)
    inner = [tab.tree_model.index(r, 0, first).data() for r in range(tab.tree_model.rowCount(first))]
    assert 'Signature 1 (nested, level 1)' in inner and 'Signer 1' in inner
    assert 'Certificate chain' in inner and 'Claimed signing time (not verified)' not in inner


def test_tooltips_on_chain_and_timestamp_rows(qtbot, metas):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result(metas)
    top = tab.tree_model.index(0, 0)
    sig = tab.tree_model.index(0, 0, top)
    tips = {tab.tree_model.index(r, 0, sig).data(): tab.tree_model.index(r, 0, sig).data(Qt.ItemDataRole.ToolTipRole)
            for r in range(tab.tree_model.rowCount(sig))}
    assert 'Source:' in tips['Digest vs file'] and 'Not evaluated' in tips['Certificate chain']


def test_no_label_claims_validity(qtbot, metas):
    tab = SigningTab()
    qtbot.addWidget(tab)
    tab.set_result(metas)
    import re
    shown = [v for row in tab.model.rows for v in row.values[1:3]]
    shown += [tab.tree_model.index(r, 1).data() for r in range(tab.tree_model.rowCount())]
    for text in shown:
        assert not re.search(r'\b(valid|verified publisher|safe)\b', text, re.I)


def test_repeated_builds_do_not_abort(qtbot, metas):
    for _ in range(20):
        tab = SigningTab()
        tab.set_result(metas)
        tab.set_loading()
        tab.set_result(metas, {'older': 'trusted_no_revocation_check', 'newer': None})
        tab.deleteLater()
    assert True


# --- worker thread and controller --------------------------------------------------------------------------------

@pytest.fixture
def project(tmp_path):
    older = meta_pe('1.0.0.0', 'asInvoker')[0]
    newer = flip(meta_pe('1.0.1.0', 'requireAdministrator', sections_extra=b'\xCC')[0], 0x800)
    (tmp_path / 'older.exe').write_bytes(older)
    (tmp_path / 'newer.exe').write_bytes(newer)
    service = ProjectService.create(tmp_path / 'older.exe', tmp_path / 'newer.exe', 'case', tmp_path / 'case')
    yield service.project, service.root
    service.close()


def inspection_of(project):
    value, root = project
    return inspect_project_artifacts(value.id, value.artifacts, root,
                                     verify_trust=lambda p: TrustResult('unavailable', None, 'test'))


def test_thread_reads_both_sides_off_the_gui_thread(qtbot, project):
    inspection = inspection_of(project)
    thread = MetadataThread(inspection, 'key')
    try:
        with qtbot.waitSignal(thread.metadata_ready, timeout=15000) as blocker:
            thread.start()
        found, key = blocker.args
        assert key == 'key' and set(found) == {'older', 'newer'}
        assert found['older'].version.blocks[0].fixed.file_version == (1, 0, 0, 0)
    finally:
        thread.wait(5000)
        inspection.close()


def test_thread_without_readers_gives_unavailable_sides(qtbot, project):
    inspection = inspection_of(project)
    inspection.close()
    thread = MetadataThread(inspection)
    with qtbot.waitSignal(thread.metadata_ready, timeout=15000) as blocker:
        thread.start()
    assert blocker.args[0] == {'older': None, 'newer': None}
    thread.wait(5000)


def test_cancelled_thread_emits_nothing(qtbot, project):
    inspection = inspection_of(project)
    thread = MetadataThread(inspection)
    thread.cancel.set()
    seen = []
    thread.metadata_ready.connect(lambda *a: seen.append(a))
    thread.start()
    assert thread.wait(10000)
    QTest.qWait(50)
    assert seen == []
    inspection.close()


class FakeWindow(QObject):
    inspection_status = Signal(str)

    def __init__(self, inspection):
        super().__init__()
        self.inspection = inspection
        self.started = 0

    def _current_inspection(self):
        return self.inspection

    def start_inspection(self):
        self.started += 1


def make_controller(project, inspection):
    window = FakeWindow(inspection)
    ctx = SimpleNamespace(project=SimpleNamespace(window=window, project=lambda: project[0]))
    return FilesController(ctx), window


def test_controller_adds_the_tab_and_fills_it(qtbot, project):
    inspection = inspection_of(project)
    controller, window = make_controller(project, inspection)
    root = controller.widget()
    qtbot.addWidget(root)
    try:
        assert [controller.tabs.tabText(i) for i in range(controller.tabs.count())] == ['Files', sv.TITLE]
        controller.refresh()
        qtbot.waitUntil(lambda: controller.signing.model.rowCount() > 0, timeout=15000)
        rows = cells(controller.signing)
        assert rows['File version (fixed)'][1:3] == ('1.0.0.0', '1.0.1.0')
        # the newer image was tampered after signing: both signed sides are reported honestly
        assert rows['Signature (embedded)'][2] == 'Signature present, digest does NOT match file'
        assert controller.pe_view.model().rowCount() > 0  # the existing PE table is untouched
    finally:
        controller.shutdown()
        inspection.close()


def test_controller_starts_one_read_per_inspection(qtbot, project):
    inspection = inspection_of(project)
    controller, _window = make_controller(project, inspection)
    qtbot.addWidget(controller.widget())
    try:
        controller.refresh()
        first = controller._signing_thread
        controller._inspection_status('again')
        assert controller._signing_thread is first
        qtbot.waitUntil(lambda: controller.signing.model.rowCount() > 0, timeout=15000)
    finally:
        controller.shutdown()
        inspection.close()


def test_controller_shutdown_joins_the_thread(qtbot, project):
    inspection = inspection_of(project)
    controller, _window = make_controller(project, inspection)
    qtbot.addWidget(controller.widget())
    controller.refresh()
    controller.shutdown()
    assert controller._signing_thread is None
    assert not [t for t in ui_inspection._LIVE_THREADS if t.isRunning()]
    inspection.close()


def test_stale_result_is_ignored(qtbot, project):
    inspection = inspection_of(project)
    controller, _window = make_controller(project, inspection)
    qtbot.addWidget(controller.widget())
    controller._signing_ready({'older': None, 'newer': None}, object())
    controller._signing_failed('X', object())
    assert controller.signing.status.full_text() == sv.LOADING
    inspection.close()


def test_model_index_roundtrip_for_empty_tree(qtbot):
    tab = SigningTab()
    qtbot.addWidget(tab)
    assert tab.tree_model.parent(QModelIndex()) == QModelIndex() and tab.tree_model.rowCount() == 0
