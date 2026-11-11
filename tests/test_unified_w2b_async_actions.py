"""GUI-10: copy_provenance and explain read the sidecar on the task runner, never on the GUI thread."""
from __future__ import annotations

import threading
import time

from PySide6.QtCore import QTimer
from qt_support import join_gui_threads, main_window, settings  # noqa: F401
from test_ui_unified import loaded_controller, unified, wait_for  # noqa: F401, F811  (fixture reuse)

from patchtrace import ui_unified
from patchtrace.unified import read_model


def block_records(monkeypatch):
    gate, entered = threading.Event(), threading.Event()
    real = read_model.records_for

    def slow(vm, rows):
        entered.set()
        assert gate.wait(10)
        return real(vm, rows)

    monkeypatch.setattr(read_model, 'records_for', slow)
    return gate, entered


def test_copy_provenance_returns_at_once_and_the_gui_thread_stays_responsive(unified, monkeypatch):  # noqa: F811
    _, controller = loaded_controller(unified)
    gate, entered = block_records(monkeypatch)
    copied, ticks = [], []
    controller._copy_text = lambda text: copied.append(text) or True
    start = time.monotonic()
    controller.copy_provenance(controller.vm.rows[:1])
    assert time.monotonic() - start < 2 and not copied
    QTimer.singleShot(0, lambda: ticks.append(1))
    wait_for(lambda: ticks and entered.is_set())
    assert not copied
    gate.set()
    wait_for(lambda: copied)
    assert copied[0].startswith('PatchTrace unified comparison')


def test_a_superseded_request_writes_no_clipboard_and_opens_no_dialog(unified, monkeypatch):  # noqa: F811
    _, controller = loaded_controller(unified)
    gate, entered = block_records(monkeypatch)
    copied, dialogs = [], []
    controller._copy_text = lambda text: copied.append(text) or True
    monkeypatch.setattr(ui_unified.ExplainDialog, 'exec', lambda self: dialogs.append(1))
    row = next(r for r in controller.vm.rows if r.ghidriff_match_id is None)
    controller.copy_provenance([row])
    wait_for(entered.is_set)
    controller.explain(row)                      # the newer request supersedes the copy
    gate.set()
    wait_for(lambda: dialogs)
    assert copied == [] and dialogs == [1]


def test_project_change_drops_a_pending_copy(unified, monkeypatch):  # noqa: F811
    _, controller = loaded_controller(unified)
    gate, entered = block_records(monkeypatch)
    copied = []
    controller._copy_text = lambda text: copied.append(text) or True
    controller.copy_provenance(controller.vm.rows[:1])
    wait_for(entered.is_set)
    controller.project_changed(None)
    gate.set()
    wait_for(lambda: not controller.tasks.busy(ui_unified.ACTION_CHANNEL))
    assert copied == []


def test_a_failing_read_shows_a_status_line(unified, monkeypatch):  # noqa: F811
    _, controller = loaded_controller(unified)
    status = []
    controller._status = status.append
    monkeypatch.setattr(read_model, 'provenance_block', lambda vm, rows: (_ for _ in ()).throw(RuntimeError('boom')))
    controller.copy_provenance(controller.vm.rows[:1])
    wait_for(lambda: len(status) > 1)
    assert status[-1].startswith('Could not read the unified result')
