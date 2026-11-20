"""Real-reader failure and pending-task boundaries for paired physical windows."""
from __future__ import annotations

import os
import threading

import pytest
from PySide6.QtWidgets import QApplication
from test_ui_raw_alignment import align, window  # noqa: F401


def test_modified_verified_artifact_refuses_alignment_and_copy(window, qtbot):  # noqa: F811
    controller = align(window, qtbot)
    artifact = next(item for item in window.project.artifacts if item.side == 'older')
    path = window.service.root / artifact.relative_path
    original = path.read_bytes()
    before = path.stat()
    path.chmod(0o600)
    altered = bytearray(original)
    altered[0x200] ^= 1
    path.write_bytes(altered)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    controller.request()
    qtbot.waitUntil(lambda: not controller.pending)
    assert controller.result is None
    assert 'ArtifactBytesError' in controller.status.text()
    assert str(path) not in controller.status.text()
    QApplication.clipboard().setText('preserved clipboard')
    window.copy_code('older')
    assert QApplication.clipboard().text() == 'preserved clipboard'
    assert controller.copy_text('older') is None


def test_clearing_inspection_during_worker_discards_closed_reader_error(window, qtbot, monkeypatch):  # noqa: F811
    from patchtrace import ui_raw_alignment

    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    build = ui_raw_alignment.build_alignment_view

    def blocked(request, _cancel):
        started.set()
        try:
            assert release.wait(5)
            return build(request)  # deliberately reach the now-closed real readers
        finally:
            finished.set()

    monkeypatch.setattr(ui_raw_alignment, 'build_alignment_view', blocked)
    controller = window.raw_alignment
    controller.toggle.setChecked(True)
    try:
        qtbot.waitUntil(started.is_set)
        token = controller.tasks._tokens[controller.CHANNEL]
        window._clear_inspection()
        status = controller.status.text()
        assert token.is_set() and not controller.pending
    finally:
        release.set()
    qtbot.waitUntil(finished.is_set)
    qtbot.waitUntil(lambda: not controller.tasks._running)
    assert controller.result is None and controller.copy_text('older') is None
    assert controller.status.text() == status
    assert 'ArtifactBytesError' not in status


@pytest.mark.parametrize('side', ['older', 'newer'])
def test_independent_exact_eof_window_keeps_empty_original_bytes(window, qtbot, side):  # noqa: F811
    controller = align(window, qtbot)
    reader = window._current_inspection().reader(side)
    controller.offsets[side].setText(f'{reader.size:x}')
    controller.request()
    qtbot.waitUntil(lambda: controller.result is not None)
    result = controller.result
    assert result.alignment is None and result.spans == ()
    assert 'Alignment unavailable' in result.summary
    assert getattr(result, side).byte_count == 0
    assert 'EOF' in getattr(result, f'{side}_text')
    window.copy_code(side)
    assert QApplication.clipboard().text().endswith(getattr(result, side).copy_text)
    assert 'display-only gap' not in QApplication.clipboard().text()
