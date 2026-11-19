"""Behavioral bounds at Qt's bulk-load callback boundary; no native timing claim."""
from __future__ import annotations

import pytest
from PySide6.QtGui import QSyntaxHighlighter
from PySide6.QtWidgets import QPlainTextEdit

from patchtrace import tooltips
from patchtrace.codetext import CodeTextModel
from patchtrace.codetext_view import DISABLED_AFTER_ERROR
from patchtrace.gui.pair_text import align_pair
from patchtrace.ui_codetext import CodeTextController


@pytest.fixture
def display(qtbot, qapp, monkeypatch):
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))
    panes = (QPlainTextEdit(), QPlainTextEdit())
    for pane in panes:
        qtbot.addWidget(pane)
        pane.resize(600, 240)
        pane.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        pane.show()
    qapp.processEvents()
    controller = CodeTextController(*panes)
    try:
        yield controller, panes
    finally:
        controller.shutdown()


def pair(rows=2000):
    older = [f'int value_{index} = 0x10;' for index in range(rows)]
    newer = [f'int value_{index} = 0x20;' for index in range(rows)]
    return align_pair(older, newer, [('replace', 0, rows, 0, rows)])


def install(controller, panes, value, language='c'):
    controller.begin(value, language)
    for pane, text in zip(panes, (value.older, value.newer), strict=True):
        pane.setPlainText(text)
    controller.finish()


def record_dispatch(monkeypatch, controller):
    calls = []
    spans = controller.spans

    def observed(side, row, text):
        calls.append((side, row, controller._windows[side]))
        return spans(side, row, text)

    monkeypatch.setattr(controller, 'spans', observed)
    return calls


@pytest.mark.parametrize('colors,marks', [(True, False), (False, True), (True, True)])
def test_bulk_install_dispatches_only_active_window_on_both_sides(display, monkeypatch, qapp, colors, marks):
    controller, panes = display
    controller.configure(colors, marks)
    calls = record_dispatch(monkeypatch, controller)
    value = pair()
    install(controller, panes, value)
    qapp.processEvents()
    assert calls and {side for side, _, _ in calls} == {'older', 'newer'}
    assert all(first <= row <= last for _, row, (first, last) in calls)
    assert len(calls) < 1000  # 4,000 document blocks; dispatch is limited to the two windows.
    for pane, text in zip(panes, (value.older, value.newer), strict=True):
        assert pane.toPlainText() == text
        assert pane.document().findBlockByNumber(0).layout().formats()
        assert not pane.document().findBlockByNumber(1500).layout().formats()
        assert {pane.document().findBlockByNumber(row).userState() for row in range(2000)} == {-1}


def test_no_model_mode_load_never_dispatches_spans(display, monkeypatch):
    controller, panes = display
    controller.configure(True, True)
    install(controller, panes, pair(30))
    calls = record_dispatch(monkeypatch, controller)
    value = pair(60)
    install(controller, panes, value, language=None)
    assert calls == []
    assert controller._model is None and not controller._failed
    for pane in panes:
        assert not any(pane.document().findBlockByNumber(row).layout().formats() for row in range(60))


def test_failed_session_stops_dispatch_before_deferred_detach(display, monkeypatch, qtbot):
    controller, panes = display
    controller.configure(True, True)
    calls = record_dispatch(monkeypatch, controller)
    notices = []
    controller.notice.connect(notices.append)

    def fail_model(*_args):
        raise RuntimeError('authored model failure')

    monkeypatch.setattr(CodeTextModel, 'spans', fail_model)
    value = pair(80)
    install(controller, panes, value)
    assert len(calls) == 1
    assert notices == [DISABLED_AFTER_ERROR]
    assert controller._failed and controller._model is None
    qtbot.waitUntil(lambda: all(not pane.document().findChildren(QSyntaxHighlighter) for pane in panes))
    assert [pane.toPlainText() for pane in panes] == [value.older, value.newer]


def test_now_outside_rehighlight_clears_formats_without_span_dispatch(display, monkeypatch):
    controller, panes = display
    controller.configure(True, False)
    install(controller, panes, pair())
    pane = panes[0]
    original = pane.toPlainText()
    block = pane.document().findBlockByNumber(0)
    assert block.layout().formats()
    pane.verticalScrollBar().setValue(1000)
    assert controller._windows['older'][0] > 0
    assert pane.document().findBlockByNumber(1000).layout().formats()
    calls = record_dispatch(monkeypatch, controller)
    controller._highlighters['older'].rehighlightBlock(block)
    assert calls == []
    assert not block.layout().formats()
    assert pane.toPlainText() == original and block.userState() == -1


def test_unexpected_window_access_failure_stays_inside_qt_failure_boundary(display, monkeypatch, qtbot):
    controller, panes = display
    controller.configure(True, False)
    install(controller, panes, pair(10))
    notices = []
    controller.notice.connect(notices.append)

    class BrokenWindow(dict):
        def __getitem__(self, key):
            raise RuntimeError('authored window access failure')

    monkeypatch.setattr(controller, '_windows', BrokenWindow())
    controller._highlighters['older'].rehighlightBlock(panes[0].document().firstBlock())
    assert notices == [DISABLED_AFTER_ERROR]
    qtbot.waitUntil(lambda: not controller.enabled and not controller._highlighters)
    assert panes[0].toPlainText() == pair(10).older
