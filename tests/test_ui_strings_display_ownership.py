"""Displayed comparison and table publish together; authored values, no extraction."""
from __future__ import annotations

import pytest
from qt_support import join_gui_threads  # noqa: F401
from test_strings_view_model import change, link
from test_ui_strings_composition import choose
from test_ui_strings_panel import key, loaded_of, start

from patchtrace.gui.qt.tasks import CancelToken, TaskFailure


def replacements():
    original = change('retained visible string', links=[link(name='OldFunction', match='old-match')])
    replacement = original.model_copy(update={
        'newer': original.newer.model_copy(update={'offsets': (0x950,)}),
        'links': (link(name='NewFunction', match='new-match'),)})
    return loaded_of(original), loaded_of(replacement)


def defer_views(controller, monkeypatch):
    pending, submit = [], controller.tasks.submit

    def defer(channel, fn, on_result, *args, **kwargs):
        if channel == 'strings-view':
            pending.append((fn, on_result, args[0]))
            return None
        return submit(channel, fn, on_result, *args, **kwargs)
    monkeypatch.setattr(controller.tasks, 'submit', defer)
    return pending


def finish(view):
    view[1](view[0](CancelToken(), lambda *_args: None))


def refresh(qtbot, controller, replacement, pending):
    choose(controller, 'builtin')
    controller.loader = lambda *_args: replacement
    controller.scan()
    qtbot.waitUntil(lambda: bool(pending), timeout=5000)


@pytest.mark.parametrize('completion', ['pending', 'failed'])
def test_visible_receipt_detail_footer_and_actions_survive_view_preparation(qtbot, monkeypatch, completion):
    old, replacement = replacements()
    c, nav, shell, _ = start(qtbot, loader=lambda *_args: old)
    assert c._select(old.rows[0].id)
    c.copy_escaped()
    copied = shell.copied[-1]
    before = c.current_row(), c.prepared, c.by_id, c.panel.detail.toPlainText(), c.panel.footer.full_text()
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, replacement, pending)
    if completion == 'failed':
        pending[0][2](TaskFailure('AuthoredViewFailure'))
    c._selection()
    c.copy_escaped()
    assert c.loaded is old and c.current_row() is before[0]
    assert c.prepared is before[1] and c.by_id is before[2]
    assert c.panel.detail.toPlainText() == before[3] and c.panel.footer.full_text() == before[4]
    assert shell.copied[-1] == copied
    c.open_hex()
    c.open_function()
    assert nav.offsets in ([], [('newer', 0x640)])
    assert not nav.anchors or nav.anchors[-1].key == 'old-match'
    assert c.stale


def test_removed_id_still_copies_from_its_visible_receipt(qtbot, monkeypatch):
    old, _ = replacements()
    c, _nav, shell, _ = start(qtbot, loader=lambda *_args: old)
    assert c._select(old.rows[0].id)
    c.copy_escaped()
    copied = shell.copied.pop()
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, loaded_of(change('replacement has a different identifier')), pending)
    c.copy_escaped()
    assert shell.copied == [copied]


def test_successful_view_publishes_matching_receipt_and_selection(qtbot, monkeypatch):
    old, replacement = replacements()
    c, nav, _shell, _ = start(qtbot, loader=lambda *_args: old)
    assert c._select(old.rows[0].id)
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, replacement, pending)
    assert c.loaded is old and c.panel.buttons['cancel'].isEnabled()
    finish(pending[0])
    assert c.loaded is replacement and not c.stale
    assert c.current_row() is replacement.rows[0] and c.current_row().newer == '0x950'
    assert 'NewFunction' in c.panel.detail.toPlainText() and 'OldFunction' not in c.panel.detail.toPlainText()
    c.open_hex()
    c.open_function()
    assert nav.offsets == [('newer', 0x950)] and nav.anchors[-1].key == 'new-match'


@pytest.mark.parametrize('event', ['source', 'cancel', 'project', 'shutdown'])
def test_superseded_view_never_publishes_any_candidate_part(qtbot, monkeypatch, event):
    old, replacement = replacements()
    c, _nav, _shell, _port = start(qtbot, loader=lambda *_args: old)
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, replacement, pending)
    if event == 'source':
        choose(c, 'floss')
    elif event == 'cancel':
        c.cancel()
    elif event == 'project':
        c.project_changed(key(project='other-project'))
    else:
        c.shutdown()
    finish(pending[0])
    assert c.loaded is (None if event == 'project' else old)


def test_late_filter_view_does_not_replace_current_filter(qtbot, monkeypatch):
    old, replacement = replacements()
    c, *_ = start(qtbot, loader=lambda *_args: old)
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, replacement, pending)
    c.panel.change.setCurrentIndex(c.panel.change.findData('only-older'))
    assert len(pending) == 2
    finish(pending[1])
    assert c.loaded is replacement and c.panel.table.table_model.rowCount() == 0
    finish(pending[0])
    assert c.panel.table.table_model.rowCount() == 0


def test_model_reset_actions_never_cross_comparison_receipts(qtbot, monkeypatch):
    old, replacement = replacements()
    c, nav, shell, _ = start(qtbot, loader=lambda *_args: old)
    pending = defer_views(c, monkeypatch)
    refresh(qtbot, c, replacement, pending)
    observed = []

    def during_reset():
        c.panel.table.selectRow(0)
        observed.append(c.current_row())
        c.copy_escaped()
        c.open_hex()
    c.panel.table.table_model.modelReset.connect(during_reset)
    finish(pending[0])
    assert len(observed) == 1 and (observed[0] is None or observed[0].newer == '0x950')
    assert nav.offsets in ([], [('newer', 0x950)])
    assert not shell.copied or 'NewFunction' in shell.copied[-1]
    assert c.loaded is replacement
