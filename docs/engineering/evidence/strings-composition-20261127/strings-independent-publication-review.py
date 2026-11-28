"""Independent replacement-publication boundaries; repository source remains untouched."""
from __future__ import annotations

import pytest
from qt_support import join_gui_threads  # noqa: F401
from test_strings_view_model import change
from test_ui_strings_composition import choose
from test_ui_strings_panel import key, loaded_of, start

from patchtrace.gui.qt.tasks import CancelToken, TaskFailure


def pending_comparison(qtbot, monkeypatch):
    value = change('independent publication value')
    old = loaded_of(value)
    new = loaded_of(value.model_copy(update={
        'newer': value.newer.model_copy(update={'offsets': (0x950,)})}))
    controller, nav, _shell, project = start(qtbot, loader=lambda *_: old)
    assert controller._select(value.id)
    pending, submit = [], controller.tasks.submit

    def defer(channel, fn, on_result, *args, **kwargs):
        if channel == 'strings-view':
            pending.append((fn, on_result, args[0]))
            return None
        return submit(channel, fn, on_result, *args, **kwargs)

    monkeypatch.setattr(controller.tasks, 'submit', defer)
    controller.loader = lambda *_: new
    controller.scan()
    qtbot.waitUntil(lambda: bool(pending), timeout=5000)
    return controller, nav, project, old, new, value.id, pending[0]


@pytest.mark.parametrize('supersede', ['cancel', 'source', 'revision'])
def test_superseded_prepared_comparison_never_replaces_visible_owner(qtbot, monkeypatch, supersede):
    controller, _nav, project, old, _new, _identity, pending = pending_comparison(qtbot, monkeypatch)
    assert controller.loaded is old
    before = controller.current_row()
    if supersede == 'cancel':
        controller.cancel()
    elif supersede == 'source':
        choose(controller, 'builtin')
    else:
        project.current = key(revision=2)
        controller.project_changed(project.current)
    fn, accept, _failure = pending
    accept(fn(CancelToken(), lambda *_: None))
    assert controller.loaded is old and controller.current_row() is before


def test_successful_replacement_publishes_row_metadata_and_actions_together(qtbot, monkeypatch):
    controller, nav, _project, old, new, identity, pending = pending_comparison(qtbot, monkeypatch)
    assert controller.loaded is old and controller.current_row().newer == '0x640'
    fn, accept, _failure = pending
    accept(fn(CancelToken(), lambda *_: None))
    assert controller.loaded is new and controller._select(identity)
    assert controller.current_row().newer == '0x950'
    controller.open_hex()
    assert nav.offsets == [('newer', 0x950)]


def test_failed_preparation_preserves_complete_previous_display_receipt(qtbot, monkeypatch):
    controller, _nav, _project, old, _new, _identity, pending = pending_comparison(qtbot, monkeypatch)
    before = controller.current_row()
    pending[2](TaskFailure('AuthoredViewFailure'))
    assert controller.loaded is old and controller.current_row() is before
    assert controller.by_id == {row.id: row for row in old.rows}
    assert controller.view.kind == 'error'
