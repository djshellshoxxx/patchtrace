"""PlainLabel, SafeTextView and labelled (GUI plan 8.4, 8.7, 8.11; slice F3). Offscreen, hermetic."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLineEdit, QWidget
from qt_support import HOSTILE_PARAMS, a11y_audit, join_gui_threads  # noqa: F401

from patchtrace.gui.qt.labels import PlainLabel, SafeTextView, labelled
from patchtrace.gui.text import LABEL_LIMIT, VIEW_LIMIT, sanitize_text


@pytest.fixture
def label(qtbot):
    widget = PlainLabel()
    qtbot.addWidget(widget)
    return widget


@pytest.mark.parametrize('text', [pytest.param('<b>bold</b>', id='bold'), pytest.param('<a href="x">l</a>', id='link')])
def test_markup_stays_text(label, text):
    label.setText(text)
    assert label.text() == text and label.textFormat() == Qt.TextFormat.PlainText
    assert not label.openExternalLinks()
    assert label.textInteractionFlags() == Qt.TextInteractionFlag.NoTextInteraction


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_every_value_is_sanitized_on_set(label, text):
    label.setText(text)
    assert label.full_text() == sanitize_text(text) and label.text() == label.full_text()
    assert not any(char in label.text() for char in '\x00\x1b\u202e\u2028')


def test_a_label_is_bounded_and_none_is_empty(label):
    label.setText('x' * 1000)
    assert len(label.full_text()) == LABEL_LIMIT and label.full_text().endswith('...')
    label.setText(None)
    assert label.full_text() == ''


def test_a_longer_limit_is_honoured(qtbot):
    widget = PlainLabel('y' * 500, limit=300)
    qtbot.addWidget(widget)
    assert len(widget.full_text()) == 300


def test_selectable_only_by_flag(qtbot):
    widget = PlainLabel('text', selectable=True)
    qtbot.addWidget(widget)
    flags = widget.textInteractionFlags()
    assert flags & Qt.TextInteractionFlag.TextSelectableByMouse
    assert not flags & Qt.TextInteractionFlag.LinksAccessibleByMouse


def test_a_narrow_label_elides_in_the_middle_with_an_escaped_tooltip(qtbot):
    widget = PlainLabel()
    qtbot.addWidget(widget)
    widget.resize(120, 24)
    widget.setText('C:/very/long/path/<b>to</b>/the/file/name.bin')
    widget.show()
    assert widget.text() != widget.full_text() and '\u2026' in widget.text()
    assert widget.text()[0] == 'C' and widget.text()[-1] == 'n'
    assert '&lt;b&gt;' in widget.toolTip() and '<b>' not in widget.toolTip()


def test_widening_restores_the_text_and_drops_the_tooltip(qtbot):
    widget = PlainLabel('some moderately long label text')
    qtbot.addWidget(widget)
    widget.resize(60, 24)
    widget.show()
    assert widget.text() != widget.full_text() and widget.toolTip()
    widget.resize(600, 24)
    assert widget.text() == widget.full_text() and widget.toolTip() == ''


def test_elision_never_clears_a_foreign_tooltip(qtbot):
    widget = PlainLabel('short')
    qtbot.addWidget(widget)
    widget.setToolTip('mine')
    widget.resize(400, 24)
    widget.show()
    widget.setText('still short')
    assert widget.toolTip() == 'mine'


def test_the_size_hint_wants_the_full_text_and_the_minimum_is_small(qtbot):
    widget = PlainLabel('a long line of text that wants room')
    qtbot.addWidget(widget)
    assert widget.sizeHint().width() >= widget.fontMetrics().horizontalAdvance(widget.full_text())
    assert widget.minimumSizeHint().width() < widget.sizeHint().width() // 2


def test_a_wrapping_label_never_elides(qtbot):
    widget = PlainLabel('word ' * 30, wrap=True)
    qtbot.addWidget(widget)
    widget.resize(120, 200)
    widget.show()
    assert widget.text() == widget.full_text() and widget.wordWrap()


@pytest.fixture
def view(qtbot):
    widget = SafeTextView('Details')
    qtbot.addWidget(widget)
    return widget


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_the_view_sanitizes_and_shows_text_not_markup(view, text):
    view.setPlainText(text)
    assert view.toPlainText() == sanitize_text(text, VIEW_LIMIT, multiline=True)


def test_the_view_is_read_only_bounded_and_keeps_newlines(view):
    view.setPlainText('one\r\ntwo\tcolumn\n' + 'z' * 5000)
    assert view.isReadOnly() and view.accessibleName() == 'Details'
    assert view.toPlainText().startswith('one\ntwo\tcolumn\n') and len(view.toPlainText()) == VIEW_LIMIT


def test_labelled_creates_a_named_buddy_pair_in_one_parent(qtbot):
    parent = QWidget()
    qtbot.addWidget(parent)
    field = QLineEdit(parent)
    label = labelled(field, 'Function name filter:')
    assert label.parentWidget() is parent and label.buddy() is field
    assert label.text() == 'Function name filter:' and field.accessibleName() == 'Function name filter'
    assert a11y_audit(parent) == []


def test_labelled_sanitizes_its_text(qtbot):
    parent = QWidget()
    qtbot.addWidget(parent)
    field = QLineEdit(parent)
    labelled(field, 'A\u202eB')
    assert field.accessibleName() == 'AB'


def test_multiline_keeps_line_breaks_only_when_asked(qtbot):
    plain, multi = PlainLabel(wrap=True), PlainLabel(wrap=True, multiline=True)
    for widget in (plain, multi):
        qtbot.addWidget(widget)
        widget.setText('one\ntwo')
    assert '\n' not in plain.text() and multi.text() == 'one\ntwo'
