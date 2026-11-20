"""Independent paired-window review controls, explicitly pinned to a reviewed source tree.

Run with PATCHTRACE_REVIEW_SOURCE, PATCHTRACE_REVIEW_SHA, and PYTHONPATH pointing
to the same clean implementation checkout. These controls do not import donor tests.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
from pathlib import Path

import pytest
from PySide6.QtCore import QCoreApplication, QPoint, QSettings, Qt
from PySide6.QtGui import QContextMenuEvent
from PySide6.QtWidgets import QApplication

from patchtrace import ui_raw_alignment
from patchtrace.artifact_bytes import ArtifactBytesError
from patchtrace.models import AnalysisRun
from patchtrace.raw_alignment_view import GAP
from patchtrace.sample import sample_diff, synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture(scope='session', autouse=True)
def reviewed_source():
    root = Path(os.environ['PATCHTRACE_REVIEW_SOURCE']).resolve()
    assert Path(ui_raw_alignment.__file__).resolve() == root / 'src/patchtrace/ui_raw_alignment.py'
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=root, capture_output=True,
                          text=True, check=True).stdout.strip()
    assert head == os.environ['PATCHTRACE_REVIEW_SHA']
    dirty = subprocess.run(['git', 'diff', '--name-only', 'HEAD', '--', 'src', 'tests', 'docs/specs'],
                           cwd=root, capture_output=True, text=True, check=True).stdout
    assert not dirty, f'Reviewed implementation changed after its commit: {dirty}'


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'project')
    win = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(win)
    win.show()
    win.mode.setCurrentIndex(3)
    qtbot.waitUntil(lambda: win._current_inspection() is not None, timeout=10000)
    yield win
    win.close()


@pytest.mark.parametrize('late_outcome', ['result', 'error'])
def test_adopted_project_survives_completed_old_work_and_owns_its_readers(
        window, qtbot, tmp_path, monkeypatch, late_outcome):
    """Old bytes are already read; replace the project, finish new work, then release the old outcome."""
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    captured = []
    build = ui_raw_alignment.build_alignment_view
    first = True

    class PriorProjectFailure(Exception):
        pass

    def delayed_delivery(request, cancel):
        nonlocal first
        if not first:
            return build(request, cancel)
        first = False
        result = build(request, cancel)
        captured.append((request, result))
        started.set()
        try:
            assert release.wait(10), 'Review harness did not release the old worker'
            if late_outcome == 'error':
                raise PriorProjectFailure('/private/old-project-path')
            return result  # Deliberately ignores cancellation after reading the real bytes.
        finally:
            finished.set()

    monkeypatch.setattr(ui_raw_alignment, 'build_alignment_view', delayed_delivery)
    controller = window.raw_alignment
    old_project_id = window.project.id
    controller.toggle.setChecked(True)
    try:
        qtbot.waitUntil(started.is_set, timeout=10000)
        old_request, old_result = captured[0]
        old_token = controller.tasks._tokens[controller.CHANNEL]
        replacement = ProjectService.sample(tmp_path / 'replacement')
        replacement_id = replacement.project.id
        window.set_service(replacement)
        assert old_token.is_set()
        for reader in (old_request.older, old_request.newer):
            with pytest.raises(ArtifactBytesError) as error:
                reader.read(0, 0)
            assert error.value.code == 'closed'
        qtbot.waitUntil(lambda: controller.result is not None, timeout=10000)
        current_result = controller.result
        assert current_result is not old_result
        assert window.project.id == replacement_id != old_project_id
        current_readers = tuple(window._current_inspection().reader(side) for side in ('older', 'newer'))
        current_text = tuple(view.toPlainText() for view in window.views.values())
        current_status = controller.status.text()
        window.copy_code('older')
        copied = QApplication.clipboard().text()
        assert f'project {replacement_id} /' in copied
        assert old_project_id not in copied
        assert copied.endswith(current_result.older.copy_text)
    finally:
        release.set()
    qtbot.waitUntil(finished.is_set, timeout=10000)
    qtbot.waitUntil(lambda: not controller.tasks._running, timeout=10000)
    assert controller.result is current_result
    assert tuple(view.toPlainText() for view in window.views.values()) == current_text
    assert controller.status.text() == current_status
    assert 'PriorProjectFailure' not in window.logs.toPlainText()
    for reader in current_readers:
        assert reader.read(0, 2) == b'MZ'
    window.copy_code('older')
    assert QApplication.clipboard().text() == copied


def _overlay_service(root):
    """Append harmless deterministic bytes while retaining the sample's valid PE headers and match records."""
    payload = bytes(range(1, 193))
    offsets, expected, inputs = {}, {}, {}
    for side, variant in (('older', 0), ('newer', 1)):
        prefix = b'o' * 35 if side == 'older' else b'n' * 71
        body = payload if side == 'older' else b'\xfe\xff' + payload
        path = root.parent / f'{side}-input.dll'
        original = synthetic_pe(variant)
        offsets[side] = len(original) + len(prefix)
        contents = original + prefix + body
        path.write_bytes(contents)
        inputs[side] = path
        expected[side] = body[:128]
    service = ProjectService.create(inputs['older'], inputs['newer'], 'Synthetic overlay review', root)
    raw = root.parent / 'sample.ghidriff.json'
    raw.write_text(json.dumps(sample_diff(service.project)), encoding='utf-8')
    service.apply_analysis(raw, AnalysisRun(status='completed', backend='synthetic-sample',
                                            backend_version='1', settings={'synthetic': True}))
    service.project.sample = True
    service.save()
    return service, offsets, expected


def _decode_copied_bytes(text, binary):
    """Independent decoding of the displayed byte columns, without production formatters."""
    rows = [line for line in text.splitlines() if re.match(r'^[0-9a-f]{8,}  ', line)]
    assert rows
    result = bytearray()
    for line in rows:
        columns = line.split('  ', 1)[1].split('|', 1)[0].split()
        width = 8 if binary else 2
        assert all(len(column) == width for column in columns)
        result.extend(int(column, 2 if binary else 16) for column in columns)
    return bytes(result), int(rows[0].split()[0], 16)


@pytest.mark.parametrize('mode', [3, 4], ids=['hex', 'binary'])
@pytest.mark.parametrize('route', ['keyboard', 'context_menu'])
def test_display_gap_selection_copies_original_overlay_and_refuses_stale_action(
        qtbot, tmp_path, mode, route):
    service, offsets, expected = _overlay_service(tmp_path / 'overlay-project')
    window = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    window.show()
    controller = window.raw_alignment
    try:
        window.mode.setCurrentIndex(mode)
        qtbot.waitUntil(lambda: window._current_inspection() is not None, timeout=10000)
        for side, value in offsets.items():
            controller.offsets[side].setText(f'{value:x}')
        controller.size.setValue(128)
        controller.toggle.setChecked(True)
        qtbot.waitUntil(lambda: controller.result is not None, timeout=10000)
        assert GAP in window.views['older'].toPlainText()
        assert controller.result.alignment.spans[0].kind == 'insert'
        for side in ('older', 'newer'):
            view = window.views[side]
            view.selectAll()  # Selected display text includes span labels and, on older, a gap.
            if side == 'older':
                assert GAP in view.textCursor().selectedText()
            QApplication.clipboard().setText('unchanged sentinel')
            if route == 'keyboard':
                qtbot.keyClick(view, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
            else:
                viewport = view.viewport()
                event = QContextMenuEvent(QContextMenuEvent.Reason.Mouse, QPoint(4, 4),
                                          viewport.mapToGlobal(QPoint(4, 4)))
                QCoreApplication.sendEvent(viewport, event)
                assert controller.menus[side].isVisible()
                controller.menus[side].actions()[0].trigger()
                controller.menus[side].hide()
            copied = QApplication.clipboard().text()
            data, start = _decode_copied_bytes(copied, binary=mode == 4)
            assert data == expected[side]
            assert start == offsets[side]
            assert hashlib.sha256(data).hexdigest() in copied
            artifact = next(item for item in window.project.artifacts if item.side == side)
            assert artifact.sha256 in copied
            assert f'project {window.project.id} / revision {window.project.revision}' in copied
            assert GAP not in copied and '[insert' not in copied

        stale_action = controller.menus['older'].actions()[0]
        controller.offsets['older'].setText('not-hex')
        controller.request()
        assert controller.result is None and not controller.pending
        QApplication.clipboard().setText('preserved after invalidation')
        stale_action.trigger()
        assert QApplication.clipboard().text() == 'preserved after invalidation'
    finally:
        window.close()
