"""Independent offscreen lifecycle controls; synthetic inputs, no source edits."""
from __future__ import annotations

import threading

import pytest
from PySide6.QtCore import QTimer
from qt_support import join_gui_threads  # noqa: F401
from test_ui_strings_panel import SAMPLE, start, table_texts


def test_queued_filter_before_shutdown_still_changes_visible_rows(qtbot, monkeypatch):
    controller, _, shell, _ = start(qtbot)
    channels = []
    submit = shell.tasks.submit

    def recording(channel, *args, **kwargs):
        channels.append(channel)
        return submit(channel, *args, **kwargs)

    monkeypatch.setattr(shell.tasks, 'submit', recording)
    try:
        assert len(table_texts(controller)) == 2
        QTimer.singleShot(0, lambda: controller.panel.change.setCurrentIndex(
            controller.panel.change.findData('only-older')))
        qtbot.waitUntil(lambda: len(table_texts(controller)) == 1, timeout=5000)
        assert channels == ['strings-view']
        assert controller.loaded is SAMPLE
    finally:
        controller.shutdown()
        shell.tasks.shutdown()


@pytest.mark.parametrize('closure', ['open', 'controller', 'controller-and-runner'])
def test_filter_result_queued_before_close_respects_controller_lifetime(qtbot, monkeypatch, closure):
    controller, nav, shell, project = start(qtbot)
    before = table_texts(controller)
    prepared = controller.prepared
    loaded_key = controller.loaded_key
    by_id = controller.by_id
    current_project = project.current
    pending = []
    submit = shell.tasks.submit

    def delayed_delivery(channel, fn, on_result=None, on_error=None, on_progress=None):
        if channel == 'strings-view':
            def hold_result(result):
                # The real worker has completed; retain only its GUI delivery.
                pending.append(lambda: on_result(result))
            return submit(channel, fn, hold_result, on_error, on_progress)
        return submit(channel, fn, on_result, on_error, on_progress)

    monkeypatch.setattr(shell.tasks, 'submit', delayed_delivery)
    delivered = threading.Event()
    try:
        controller.panel.change.setCurrentIndex(controller.panel.change.findData('only-older'))
        qtbot.waitUntil(lambda: len(pending) == 1, timeout=5000)
        assert table_texts(controller) == before

        def queued_delivery():
            pending.pop()()
            delivered.set()

        QTimer.singleShot(0, queued_delivery)
        if closure != 'open':
            controller.shutdown()
        if closure == 'controller-and-runner':
            shell.tasks.shutdown()

        with qtbot.captureExceptions() as errors:
            qtbot.waitUntil(delivered.is_set, timeout=5000)
        assert errors == []
        if closure == 'open':
            assert len(table_texts(controller)) == 1
            assert controller.prepared is not prepared
        else:
            assert table_texts(controller) == before
            assert controller.prepared is prepared
        assert controller.loaded is SAMPLE
        assert controller.loaded_key == loaded_key
        assert controller.by_id is by_id
        assert project.current is current_project
        assert not nav.anchors and not nav.offsets and not shell.copied

        if closure == 'controller':
            sibling_result = []
            shell.tasks.submit('peer-panel', lambda _token, _report: 'still open', sibling_result.append)
            qtbot.waitUntil(lambda: sibling_result == ['still open'], timeout=5000)
    finally:
        controller.shutdown()
        shell.tasks.shutdown()
