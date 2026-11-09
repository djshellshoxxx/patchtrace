"""Files status events and focus using authored data; no screen-reader acceptance claim."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from PySide6.QtCore import QObject, Signal
from qt_support import RecordingAnnouncer

from patchtrace.artifact_inspection import ProjectInspection, SideInspection
from patchtrace.gui.registry import PanelContext
from patchtrace.pe_overview.panel import PANEL
from patchtrace.sample import create_sample
from patchtrace.ui_inspection import RUNNING_STATUS, FilesController


class InspectionWindow(QObject):
    inspection_status = Signal(str)

    def __init__(self):
        super().__init__()
        self.inspection = None
        self._inspection_error = None
        self.started = 0
        self.key = ('sample', 'project')

    def _current_inspection(self):
        return self.inspection

    def _project_inspection_key(self):
        return self.key

    def start_inspection(self):
        self.started += 1


class RunningInspection(QObject):
    def __init__(self, key):
        super().__init__()
        self.key = key

    def isRunning(self):
        return True


@pytest.fixture
def files(qtbot, tmp_path):
    service = create_sample(tmp_path / 'sample')
    window = InspectionWindow()
    announcer = RecordingAnnouncer()
    project = SimpleNamespace(window=window, project=lambda: service.project)
    ctx = PanelContext(PANEL, project, None, None, announcer)
    controller = FilesController(ctx)
    root = controller.widget()
    qtbot.addWidget(root)
    root.resize(900, 650)
    root.show()
    root.activateWindow()
    controller.pe_view.setFocus()
    qtbot.waitUntil(controller.pe_view.hasFocus)
    yield controller, window, announcer
    controller.shutdown()
    if window.inspection is not None:
        window.inspection.close()
    service.close()


def test_loading_failure_are_announced_once_and_keep_focus(files, qtbot):
    controller, window, announcer = files
    controller.refresh()
    controller.refresh()
    assert announcer.messages == [(RUNNING_STATUS, False)]
    window.inspection_status.emit('File inspection failed: ValueError')
    window.inspection_status.emit('File inspection failed: ValueError')
    assert len(announcer.messages) == 2
    text, assertive = announcer.messages[-1]
    assert text == 'File inspection failed. Review Logs, then choose File overview to retry.'
    assert assertive
    assert 'ValueError' in controller.status.full_text()
    assert 'File overview' in controller.status.full_text()
    assert controller.pe_view.hasFocus()
    qtbot.waitUntil(lambda: controller.status.isVisible())
    assert 'File inspection failed:' in controller.status.full_text()


def test_project_refresh_retains_current_failure_until_explicit_retry(files):
    controller, window, announcer = files
    window._inspection_error = (window.key, 'ValueError')
    controller.project_changed(window.key)
    assert window.started == 0
    assert controller.status.full_text().startswith('File inspection failed: ValueError')
    assert announcer.messages[-1][1]
    controller.refresh()  # the File overview action's existing explicit retry route
    assert window.started == 1
    assert controller.status.full_text() == RUNNING_STATUS
    assert announcer.messages[-1] == (RUNNING_STATUS, False)


def test_previous_project_failure_does_not_block_loading(files):
    controller, window, announcer = files
    window._inspection_error = (('other', 'project'), 'ValueError')
    controller.project_changed(window.key)
    assert window.started == 1
    assert announcer.messages == [(RUNNING_STATUS, False)]


def test_retry_stays_loading_when_project_updates_before_it_finishes(files):
    controller, window, announcer = files
    window._inspection_error = (window.key, 'ValueError')
    controller.project_changed(window.key)
    controller.refresh()
    window._inspection_thread = RunningInspection(window.key)
    controller.project_changed(window.key)
    assert controller.status.full_text() == RUNNING_STATUS
    assert len(announcer.messages) == 2
    window._inspection_thread = None
    window.inspection_status.emit('File inspection failed: OSError')
    assert 'OSError' in controller.status.full_text()
    assert announcer.messages[-1][1]
    assert len(announcer.messages) == 3


def test_opening_same_project_from_a_different_root_announces_new_load(files):
    controller, window, announcer = files
    controller.project_changed(window.key)
    window.key = ('copied-sample', 'project')
    controller.project_changed(window.key)
    assert announcer.messages == [(RUNNING_STATUS, False), (RUNNING_STATUS, False)]


def test_completion_and_metadata_failure_are_announced_without_focus_change(files, qtbot):
    controller, window, announcer = files
    controller.refresh()
    window.inspection = ProjectInspection('project', {
        side: SideInspection(side, 'a' * 64, error_code='unavailable') for side in ('older', 'newer')})
    window.inspection_status.emit('File inspection complete · OLDER: unavailable · NEWER: unavailable')
    qtbot.waitUntil(lambda: any('Version and signing read complete.' in text for text, _ in announcer.messages))
    assert ('File inspection complete. Review Files for per-file status and warnings.', False) in announcer.messages
    assert ('Reading version, manifest and signature (read-only)...', False) in announcer.messages
    count = len(announcer.messages)
    window.inspection_status.emit('File inspection complete · OLDER: unavailable · NEWER: unavailable')
    assert len(announcer.messages) == count
    assert 'unavailable' in controller.status.full_text()
    assert controller.pe_view.hasFocus()
    controller._signing_failed('unreadable', object())
    assert len(announcer.messages) == count  # superseded result
    controller._signing_failed('unreadable', window.inspection)
    controller._signing_failed('unreadable', window.inspection)
    assert len(announcer.messages) == count + 1
    assert announcer.messages[-1] == (
        'Version and signing read failed. Review the section status; other file sections are unaffected.', True)
    assert 'unreadable' in controller.signing.status.full_text()
    assert controller.pe_view.hasFocus()


def test_focus_target_uses_the_visible_files_tab(files):
    controller, _window, _announcer = files
    assert controller.focus_target() is controller.pe_view
    controller.tabs.setCurrentWidget(controller.signing)
    target = controller.focus_target()
    assert target is controller.signing.table
    assert target.isVisible()
    target.setFocus()
    assert target.hasFocus()
