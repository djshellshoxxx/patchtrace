"""Stress: CodeDiffView with oversized sides, a 2,000-hunk walk, theme and highlighter churn, and a copy (GUI plan 8.4,
8.9, slice F6a). Plus one xfail that records a real alignment bug (QA-GUI-1) with its repro.

Every expected value is computed from the input, so an off-by-one row fails the test instead of passing silently."""
from __future__ import annotations

import dataclasses
import difflib

import pytest
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads  # noqa: F401

from patchtrace.gui.pair_text import PairText, align_pair
from patchtrace.gui.qt.codediff import MAX_VIEW_CHARS, TRUNCATION_NOTICE, CodeDiffView
from patchtrace.gui.qt.theme import DARK


def aligned(old: list[str], new: list[str]) -> PairText:
    opcodes = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    return align_pair(old, new, opcodes)


class Words(QSyntaxHighlighter):
    def highlightBlock(self, text: str) -> None:  # noqa: N802 (Qt name)
        self.setFormat(0, len(text), QTextCharFormat())


@pytest.fixture
def view(qtbot):
    made = CodeDiffView()
    qtbot.addWidget(made)
    made.resize(1000, 500)
    made.show()
    return made


def test_a_side_over_the_view_limit_is_cut_with_a_notice_and_stays_addressable(view):
    old = [f'line {index:06d} {"x" * 20}' for index in range(15_000)]  # about 330 KB, over the 200,000 character cap
    new = list(old)
    new[7_000] = 'changed'
    view.set_pair(aligned(old, new), ('old.c', 'new.c'))
    older = view.pane('older').toPlainText()
    assert older.endswith(TRUNCATION_NOTICE) and len(older) <= MAX_VIEW_CHARS + len(TRUNCATION_NOTICE) + 2
    assert view.reveal('older', 1, 1) and not view.reveal('older', 14_999, 14_999)
    assert all(hunk.start + hunk.length <= view.pane('older').blockCount() for hunk in view.hunks)


def test_walking_two_thousand_hunks_visits_each_once_and_stops_at_both_ends(view):
    old = [f'a{index}' for index in range(4_000)]
    new = [line if index % 2 else f'{line}!' for index, line in enumerate(old)]
    view.set_pair(aligned(old, new))
    total = len(view.hunks)
    assert total == 2_000
    seen = []
    while view.next_hunk():
        seen.append(view.current_hunk)
    assert seen == list(range(total)) and view.next_hunk() is False
    assert view.current_hunk == total - 1
    back = []
    while view.previous_hunk():
        back.append(view.current_hunk)
    assert back == list(range(total - 2, -1, -1)) and view.current_hunk == 0


def test_theme_and_highlighter_churn_keeps_both_panes_on_the_current_tokens(view, qtbot):
    old = [f'word {index} alpha' for index in range(2_000)]
    new = [line.replace('alpha', 'beta') if index % 9 == 0 else line for index, line in enumerate(old)]
    view.set_pair(aligned(old, new))
    light = dataclasses.replace(DARK, text='#101010', surface_alt='#fafafa')
    for step in range(30):
        tokens = light if step % 2 else DARK
        view.set_tokens(tokens)
        highlighter = view.attach_highlighter('older', Words)
        assert highlighter.document() is view.pane('older').document()
        if step % 5 == 4:
            view.detach_highlighter('older')
        QApplication.processEvents()
        assert view.pane('older').palette().color(view.pane('older').palette().ColorRole.Text).name() == tokens.text
    assert view.hunks  # the hunks survive every swap
    view.select_hunk(len(view.hunks) - 1)
    assert view.current_hunk == len(view.hunks) - 1


def test_copying_a_cut_side_is_bounded_and_carries_its_provenance(view, qtbot):
    old = ['q' * 100 for _ in range(4_000)]
    new = old[:-1] + ['z']
    view.set_pair(aligned(old, new), ('artifacts/old.bin', 'artifacts/new.bin'))
    from PySide6.QtGui import QGuiApplication
    view.copy_side('older')
    text = QGuiApplication.clipboard().text()
    assert text.startswith('artifacts/old.bin\n\n')
    assert len(text.encode('utf-8')) <= MAX_VIEW_CHARS + 200 + len(TRUNCATION_NOTICE.encode())


@pytest.mark.xfail(strict=True, reason='QA-GUI-1: a form feed, vertical tab, NEL or lone CR in a source line splits '
                                       'the pane row but not the PairText row, so later hunks and anchors shift by one')
def test_a_form_feed_inside_a_line_does_not_shift_later_rows(view):
    old = ['int a;\fint b;', 'static void f(void)', '{', 'return;', '}']
    new = ['int a;\fint b;', 'static void f(void)', '{', 'return 1;', '}']
    pair = align_pair(old, new, [('equal', 0, 3, 0, 3), ('replace', 3, 4, 3, 4), ('equal', 4, 5, 4, 5)])
    view.set_pair(pair, ('old.c', 'new.c'))
    rows = view.pane('newer').toPlainText().split('\n')
    assert rows[view.hunks[0].start].startswith('return 1;')
    assert view.reveal('newer', 4, 4)
    selected = view.pane('newer').extraSelections()
    assert selected and view.pane('newer').document().findBlock(
        selected[0].cursor.position()).text().startswith('return 1;')
