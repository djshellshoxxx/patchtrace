"""Paired raw windows: actual TaskRunner, provenance, invalidation and layout regressions."""
from __future__ import annotations

import os
import subprocess
import sys
import threading

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QPoint, QSettings, Qt
from PySide6.QtGui import QContextMenuEvent
from PySide6.QtWidgets import QApplication
from shiboken6 import isValid

from patchtrace import ui_raw_alignment
from patchtrace.raw_alignment_view import build_alignment_view
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    win = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(win)
    win.show()
    win.mode.setCurrentIndex(3)
    qtbot.waitUntil(lambda: win._current_inspection() is not None, timeout=10000)
    yield win
    win.close()


def align(window, qtbot):
    controller = window.raw_alignment
    controller.toggle.setChecked(True)
    qtbot.waitUntil(lambda: controller.result is not None, timeout=10000)
    return controller


def test_opt_in_copy_binary_base64_and_span_navigation(window, qtbot):
    controller = window.raw_alignment
    assert not controller.active() and controller.result is None
    assert window.views['older'].toPlainText().startswith('00000000')
    controller = align(window, qtbot)
    result = controller.result
    assert not window.raw_page.isVisibleTo(window)
    assert controller.spans.count() == len(result.spans)
    if controller.spans.count() > 1:
        qtbot.mouseClick(controller.next, Qt.MouseButton.LeftButton)
        assert controller.spans.currentIndex() == 1
        assert window.views['older'].textCursor().blockNumber() == result.spans[1].line
        window.render_match()
        assert controller.spans.currentIndex() == 1
        assert window.views['older'].textCursor().blockNumber() == result.spans[1].line
        assert window.views['newer'].textCursor().blockNumber() == result.spans[1].line
        qtbot.mouseClick(controller.previous, Qt.MouseButton.LeftButton)
        assert controller.spans.currentIndex() == 0
    before = tuple(field.text() for field in controller.offsets.values())
    window.copy_code('older')
    assert QApplication.clipboard().text().endswith(result.older.copy_text)
    assert 'display-only gap' not in QApplication.clipboard().text()
    QApplication.clipboard().setText('sentinel')
    qtbot.keyClick(window.views['older'], Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    assert QApplication.clipboard().text().endswith(result.older.copy_text)
    assert before == tuple(field.text() for field in controller.offsets.values())
    viewport = window.views['older'].viewport()
    event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(5, 5), viewport.mapToGlobal(QPoint(5, 5)))
    QCoreApplication.sendEvent(viewport, event)
    assert controller.menus['older'].isVisible()
    QApplication.clipboard().setText('context sentinel')
    controller.menus['older'].actions()[0].trigger()
    assert QApplication.clipboard().text().endswith(result.older.copy_text)
    window.mode.setCurrentIndex(4)
    qtbot.waitUntil(lambda: controller.result is not None, timeout=10000)
    assert '01001101' in controller.result.older.copy_text
    window.mode.setCurrentIndex(5)
    assert not controller.active() and controller.result is None
    assert not controller.menus['older'].isVisible()
    assert window.views['older'].toPlainText().startswith('TVo')
    assert window.raw_page.isVisibleTo(window)


def test_public_raw_navigation_exits_paired_mode(window, qtbot):
    controller = align(window, qtbot)
    controller.offsets['older'].setText('200')
    controller.request()
    qtbot.waitUntil(lambda: controller.result is not None)
    window.panels.port.show_raw_offset('older', 0)
    assert not controller.active() and controller.result is None
    assert window.views['older'].toPlainText().startswith('00000000')


def test_paired_tooltip_replaces_and_invalidates_prior_window_provenance(window, qtbot):
    fixed_tooltip = window.match_label.toolTip()
    controller = align(window, qtbot)
    controller.offsets['older'].setText('200')
    assert window.match_label.toolTip() == 'No current paired window bytes.'
    controller.request()
    qtbot.waitUntil(lambda: controller.result is not None)
    result = controller.result
    assert window.match_label.toolTip() == result.older.caption + '\n\n' + result.newer.caption
    assert window.match_label.toolTip() != fixed_tooltip
    assert '0x200' in window.match_label.toolTip()
    controller.offsets['newer'].setText('20')
    assert window.match_label.toolTip() == 'No current paired window bytes.'
    assert controller.copy_text('older') is None


def test_invalid_window_and_inspection_failure_remain_visible(window, qtbot):
    controller = align(window, qtbot)
    controller.size.setValue(17)
    controller.request()
    assert 'multiple of 16' in controller.status.text()
    assert not controller.pending and controller.result is None
    controller.size.setValue(16)
    controller.offsets['older'].setText('fffffffffffffff')
    controller.request()
    assert 'Physical offsets' in controller.status.text()
    window._clear_inspection()
    window._inspection_failed('FixtureInspectionFailure', window._project_inspection_key())
    assert 'FixtureInspectionFailure' in controller.status.text()
    controller.request()
    assert not controller.pending and 'FixtureInspectionFailure' in controller.status.text()


@pytest.mark.parametrize('change', ['mode', 'input', 'size', 'selection', 'inspection', 'orientation', 'hide', 'project'])
def test_context_changes_reject_old_results_and_copy(window, qtbot, tmp_path, change):
    controller = align(window, qtbot)
    old_result, generation, key = controller.result, controller.generation, controller._key()
    if change == 'mode':
        window.mode.setCurrentIndex(0)
    elif change == 'input':
        controller.offsets['older'].setText('20')
    elif change == 'size':
        controller.size.setValue(32)
    elif change == 'selection':
        window.navigator.setCurrentRow((window.navigator.currentRow() + 1) % window.navigator.count())
    elif change == 'inspection':
        window._clear_inspection()
    elif change == 'orientation':
        window.service.swap_orientation()
        window.refresh()
    elif change == 'hide':
        controller.pane.hide()
    else:
        window.set_service(ProjectService.sample(tmp_path / 'replacement'))
    controller._ready(old_result, generation, key)
    assert controller.result is not old_result
    assert controller.copy_text('older') is None


def test_worker_snapshot_and_pending_cancellation(window, qtbot, monkeypatch):
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    captures = []

    def blocked(request, cancel):
        captures.append((request, threading.get_ident()))
        started.set()
        assert release.wait(5)
        try:
            # Deliberately ignore cancellation to exercise TaskRunner's stale-generation discard.
            return build_alignment_view(request)
        finally:
            finished.set()

    monkeypatch.setattr(ui_raw_alignment, 'build_alignment_view', blocked)
    controller = window.raw_alignment
    controller.toggle.setChecked(True)
    qtbot.waitUntil(started.is_set)
    token = controller.tasks._tokens[controller.CHANNEL]
    assert captures[0][1] != threading.get_ident()
    assert set(vars(captures[0][0])) == {'older', 'newer', 'older_offset', 'newer_offset', 'window', 'representation'}
    window.mode.setCurrentIndex(0)
    assert token.is_set()
    release.set()
    qtbot.waitUntil(finished.is_set)
    qtbot.waitUntil(lambda: not controller.tasks._running)
    assert controller.result is None
    assert 'return' in window.views['older'].toPlainText()


@pytest.mark.parametrize('initial_width', [1440, 1100])
def test_summary_allocated_immediately_and_after_narrow_resize(window, qtbot, initial_width):
    window.resize(initial_width, 900)
    controller = align(window, qtbot)
    reader = window._current_inspection().reader('older')
    controller.offsets['older'].setText(f'{reader.size:x}')
    controller._status('Pending one-line result')
    controller.pane.layout().activate()
    controller.controls.layout().activate()
    generation, key = controller.generation, controller._key()
    pair = window._current_inspection()
    from patchtrace.raw_alignment_view import WindowRequest
    from patchtrace.representations import Representation
    result = build_alignment_view(WindowRequest(pair.reader('older'), pair.reader('newer'), reader.size, 0,
                                                4096, Representation.HEX))
    controller._ready(result, generation, key)
    # No processEvents/wait between delivery and the first allocation assertion.
    assert '\n' in controller.status.text()
    assert controller.status.height() >= controller.status.heightForWidth(controller.status.width())
    assert controller.controls.rect().contains(controller.status.geometry())
    window.resize(960, 740)
    qtbot.waitUntil(lambda: window.width() == 960)
    assert controller.status.height() >= controller.status.heightForWidth(controller.status.width())
    assert controller.controls.rect().contains(controller.status.geometry())


def test_reaped_current_inspection_pointer_is_cleared_before_cpp_deletion(window, qtbot):
    qtbot.waitUntil(lambda: not any(t.isRunning() for t in window._inspection_threads))
    window._reap_inspection_threads()
    assert window._inspection_thread is None
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    window._clear_inspection()
    window.start_inspection()
    qtbot.waitUntil(lambda: window._current_inspection() is not None)


def test_reaping_old_thread_preserves_current_live_pointer(window):
    class Thread:
        def __init__(self, running):
            self.running = running
            self.deleted = False

        def isRunning(self):  # noqa: N802
            return self.running

        def deleteLater(self):  # noqa: N802
            self.deleted = True

    old, current = Thread(False), Thread(True)
    window._inspection_threads = [old, current]
    window._inspection_thread = current
    try:
        window._reap_inspection_threads()
        assert old.deleted and not current.deleted
        assert window._inspection_thread is current
    finally:
        window._inspection_threads = []
        window._inspection_thread = None


def test_actual_application_quit_cancels_in_isolated_process(tmp_path):
    script = r'''
import sys, threading
from pathlib import Path
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QApplication
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow
from patchtrace import ui_raw_alignment
app = QApplication([])
root = Path(sys.argv[1])
window = MainWindow(ProjectService.sample(root / 'project'), QSettings(str(root / 'ui.ini'), QSettings.IniFormat))
window.show()
started = threading.Event()
def blocked(request, cancel):
    started.set()
    while not cancel():
        threading.Event().wait(.001)
    return None
ui_raw_alignment.build_alignment_view = blocked
def ready():
    if window._current_inspection() is None:
        QTimer.singleShot(10, ready)
        return
    window.raw_alignment.toggle.setChecked(True)
    QTimer.singleShot(10, quit_when_started)
def quit_when_started():
    if not started.is_set():
        QTimer.singleShot(10, quit_when_started)
        return
    app.quit()
window.mode.setCurrentIndex(3)
QTimer.singleShot(0, ready)
QTimer.singleShot(10000, app.exit)
app.exec()
assert started.is_set()
assert window.raw_alignment.closed
assert window.panels.tasks._closed
assert not window.panels.tasks._threads
window.close()
print('actual QApplication.quit cancellation passed')
'''
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)], capture_output=True, text=True,
                            timeout=20, env={**os.environ, 'QT_QPA_PLATFORM': 'offscreen'})
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'actual QApplication.quit cancellation passed' in result.stdout


def test_close_cancels_and_keeps_qt_object_ownership(window, qtbot):
    controller = align(window, qtbot)
    old_result, generation, key = controller.result, controller.generation, controller._key()
    window.close()
    controller._ready(old_result, generation, key)
    assert controller.closed and controller.result is None
    assert isValid(controller)


@pytest.mark.parametrize('font_pixels', [12, 14, 18, 24, 28])
def test_summary_allocates_wrapped_lines_and_releases_short_text(window, qtbot, font_pixels):
    window.resize(1100, 750)
    controller = align(window, qtbot)
    controller.status.setStyleSheet(f'font-size: {font_pixels}px')
    # Real EOF/unavailable summary, with a platform-independent font-size control.
    pair = window._current_inspection()
    from patchtrace.raw_alignment_view import WindowRequest
    from patchtrace.representations import Representation
    result = build_alignment_view(WindowRequest(pair.reader('older'), pair.reader('newer'),
                                                pair.reader('older').size, 0, 4096, Representation.HEX))
    controller._status(result.summary)
    assert controller.status.height() >= controller.status.heightForWidth(controller.status.width())
    tall = controller.status.height()
    window.resize(960, 740)
    qtbot.waitUntil(lambda: window.width() == 960)
    assert controller.status.height() >= controller.status.heightForWidth(controller.status.width())
    assert controller.controls.rect().contains(controller.status.geometry())
    controller._status('Reading verified windows…')
    assert controller.status.height() < tall
    assert controller.status.height() >= controller.status.heightForWidth(controller.status.width())
