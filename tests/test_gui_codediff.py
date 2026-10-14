"""CodeDiffView and compose_selections (GUI plan 8.4, 8.9, 8.11; slice F6a). Offscreen, hermetic."""
from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCursor, QTextDocument
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QTextBrowser, QTextEdit
from qt_support import HOSTILE_PARAMS, a11y_audit, join_gui_threads  # noqa: F401

from patchtrace.gui.pair_text import PairHunk, PairText, align_pair
from patchtrace.gui.qt.codediff import (
    LAYERS,
    MAX_VIEW_CHARS,
    TRUNCATION_NOTICE,
    CodeDiffView,
    clear_selections,
    compose_selections,
    hunk_background,
)
from patchtrace.gui.qt.theme import DARK


def selection(view: QPlainTextEdit, row: int, color: str) -> QTextEdit.ExtraSelection:
    item = QTextEdit.ExtraSelection()
    item.cursor = QTextCursor(view.document().findBlockByNumber(row))
    item.format.setBackground(QColor(color))
    return item


def colors(view: QPlainTextEdit) -> list[str]:
    return [item.format.background().color().name() for item in view.extraSelections()]


SAMPLE = align_pair(['a', 'b', 'c', 'd', 'e'], ['a', 'X', 'c', 'd', 'e', 'f'],
                    [('equal', 0, 1, 0, 1), ('replace', 1, 2, 1, 2), ('equal', 2, 5, 2, 5), ('insert', 5, 5, 5, 6)])


@pytest.fixture
def plain(qtbot):
    view = QPlainTextEdit()
    qtbot.addWidget(view)
    view.setPlainText('\n'.join(f'line {i}' for i in range(10)))
    return view


@pytest.fixture
def diff(qtbot):
    view = CodeDiffView()
    qtbot.addWidget(view)
    view.resize(900, 400)
    return view


# --- compose_selections ---

def test_layers_are_applied_in_order_whatever_the_call_order(plain):
    for layer, color in (('mark', '#000004'), ('diff', '#000001'), ('anchor', '#000003'), ('search', '#000002')):
        compose_selections(plain, layer, [selection(plain, 1, color)])
    assert LAYERS == ('diff', 'search', 'anchor', 'mark')
    assert colors(plain) == ['#000001', '#000002', '#000003', '#000004']


def test_replacing_a_layer_keeps_the_others_and_empty_clears_it(plain):
    compose_selections(plain, 'diff', [selection(plain, 0, '#000001')])
    compose_selections(plain, 'search', [selection(plain, 2, '#000002'), selection(plain, 3, '#000002')])
    compose_selections(plain, 'search', [selection(plain, 4, '#000005')])
    assert colors(plain) == ['#000001', '#000005']
    compose_selections(plain, 'search', [])
    assert colors(plain) == ['#000001']
    clear_selections(plain)
    assert plain.extraSelections() == []


def test_views_do_not_share_layers(qtbot, plain):
    other = QPlainTextEdit()
    qtbot.addWidget(other)
    other.setPlainText('x\ny')
    compose_selections(plain, 'diff', [selection(plain, 0, '#000001')])
    compose_selections(other, 'search', [selection(other, 0, '#000002')])
    assert colors(plain) == ['#000001'] and colors(other) == ['#000002']


def test_an_unknown_layer_is_rejected_and_changes_nothing(plain):
    compose_selections(plain, 'diff', [selection(plain, 0, '#000001')])
    with pytest.raises(ValueError):
        compose_selections(plain, 'hover', [])
    assert colors(plain) == ['#000001']


def test_the_layer_list_is_copied(plain):
    items = [selection(plain, 0, '#000001')]
    compose_selections(plain, 'diff', items)
    items.clear()
    compose_selections(plain, 'mark', [])
    assert colors(plain) == ['#000001']


# --- the view ---

def test_panes_carry_the_kept_names_and_are_plain_read_only(diff):
    assert diff.pane('older').accessibleName() == 'Older artifact code'
    assert diff.pane('newer').accessibleName() == 'Newer artifact code'
    assert all(p.isReadOnly() and not isinstance(p, QTextBrowser) for p in diff.panes.values())
    assert a11y_audit(diff) == []


def test_set_pair_shows_aligned_rows_and_tints_the_hunks_on_both_panes(diff):
    diff.set_pair(SAMPLE, ('older.dll', 'newer.dll'))
    assert diff.pane('older').toPlainText().split('\n') == ['a', 'b', 'c', 'd', 'e', '']
    assert diff.hunks == (PairHunk(1, 1, 'replace'), PairHunk(5, 1, 'insert'))
    for side in ('older', 'newer'):
        assert colors(diff.pane(side)) == ['#263a43', '#33392b']
    assert diff.current_hunk == -1


def test_hunk_navigation_does_not_wrap_and_emits(diff):
    diff.set_pair(SAMPLE)
    seen = []
    diff.hunk_changed.connect(seen.append)
    assert diff.next_hunk() and diff.next_hunk() and not diff.next_hunk()
    assert diff.current_hunk == 1
    assert diff.previous_hunk() and not diff.previous_hunk()
    assert seen == [0, 1, 0] and diff.pane('newer').textCursor().blockNumber() == 1


def test_previous_from_nothing_selects_the_last_hunk_and_no_hunks_means_false(diff):
    diff.set_pair(SAMPLE)
    assert diff.previous_hunk() and diff.current_hunk == 1
    diff.set_pair(PairText('same', 'same'))
    assert not diff.next_hunk() and not diff.previous_hunk() and diff.current_hunk == -1


def test_search_layer_rides_on_hunks_and_set_pair_resets_it(diff):
    diff.set_pair(SAMPLE)
    pane = diff.pane('older')
    compose_selections(pane, 'search', [selection(pane, 0, '#000002')])
    assert colors(pane) == ['#263a43', '#33392b', '#000002']
    diff.set_pair(SAMPLE)
    assert colors(pane) == ['#263a43', '#33392b']


def test_reveal_uses_original_line_numbers_through_the_map(diff):
    diff.set_pair(SAMPLE)
    assert diff.reveal('older', 2, 3)
    assert diff.pane('older').textCursor().blockNumber() == 1
    assert len(diff.pane('older').extraSelections()) == 3
    assert diff.reveal('newer', 6, 6) and diff.pane('newer').textCursor().blockNumber() == 5


@pytest.mark.parametrize('side,start,end', [pytest.param('older', 0, 1, id='zero'), pytest.param('older', 3, 2, id='back'),
                                            pytest.param('older', 6, 6, id='past'), pytest.param('newer', 7, 7, id='far')])
def test_reveal_refuses_lines_that_are_not_shown(diff, side, start, end):
    diff.set_pair(SAMPLE)
    before = len(diff.pane(side).extraSelections())
    assert not diff.reveal(side, start, end) and len(diff.pane(side).extraSelections()) == before


def test_reveal_rejects_an_unknown_side(diff):
    with pytest.raises(ValueError):
        diff.reveal('left', 1, 1)


def test_each_side_is_capped_with_an_explicit_notice(diff):
    lines = ['x' * 99] * 3000  # 299,999 characters
    ops = [('equal', 0, 3000, 0, 3000), ('insert', 3000, 3000, 3000, 3001)]
    diff.set_pair(align_pair(lines, [*lines, 'tail'], ops))
    for side in ('older', 'newer'):
        text = diff.pane(side).toPlainText()
        assert text.endswith(TRUNCATION_NOTICE) and len(text) <= MAX_VIEW_CHARS + len(TRUNCATION_NOTICE) + 1
    assert diff.hunks == () and not diff.reveal('older', 3000, 3000) and diff.reveal('older', 1, 1)
    assert not diff._notice.isHidden()
    diff.set_pair(SAMPLE)
    assert diff._notice.isHidden()


def test_a_hunk_cut_by_the_cap_is_clipped_not_dropped(diff):
    old, new = ['y' * 99] * 2500, ['z' * 99] * 2500
    diff.set_pair(align_pair(old, new, [('replace', 0, 2500, 0, 2500)]))
    rows = diff.hunks[0].length
    assert rows == 2000 and diff.pane('older').document().blockCount() == rows + 2  # the cut line and the notice


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_code_is_text_and_sanitized(diff, text):
    diff.set_pair(PairText(f'a{text}b', f'c{text}d'), (text, text))
    shown = diff.pane('older').toPlainText()
    assert not any(char in shown for char in '\x1b‮\x00 ')
    assert shown.startswith('a') and not diff.findChildren(QTextBrowser)


def test_copy_puts_provenance_and_the_shown_code_on_the_clipboard(diff):
    diff.set_pair(SAMPLE, ('older.dll sha256 aa', 'newer.dll'))
    diff.copy_side('older')
    assert QApplication.clipboard().text() == 'older.dll sha256 aa\n\n' + diff.pane('older').toPlainText()
    diff.copy_side('newer')
    assert QApplication.clipboard().text().startswith('newer.dll\n\n')


def test_set_message_resets_everything(diff):
    diff.set_pair(SAMPLE)
    diff.next_hunk()
    diff.set_message('No matching function selected.')
    assert diff.hunks == () and diff.current_hunk == -1
    assert diff.pane('older').toPlainText() == 'No matching function selected.'
    assert diff.pane('older').extraSelections() == []


def test_scroll_is_linked_until_switched_off(diff):
    lines = [f'row {i}' for i in range(400)]
    diff.set_pair(align_pair(lines, lines, [('equal', 0, 400, 0, 400)]))
    diff.show()
    older, newer = diff.pane('older').verticalScrollBar(), diff.pane('newer').verticalScrollBar()
    assert diff.sync_scroll and older.maximum() > 10
    older.setValue(30)
    assert newer.value() == 30
    diff.sync_scroll = False
    older.setValue(60)
    assert newer.value() == 30


# --- theme ---

def test_hunk_tints_pass_the_text_guard_on_dark_and_fall_back_when_unreadable():
    assert hunk_background('replace', DARK) == '#263a43' and hunk_background('delete', DARK) == '#33392b'
    assert hunk_background('replace', replace(DARK, text='#2a3d46')) == DARK.surface_alt


def test_set_tokens_repaints_the_panes_and_hunks(diff):
    diff.set_pair(SAMPLE)
    diff.set_tokens(replace(DARK, surface_alt='#101010', text='#2a3d46'))
    assert colors(diff.pane('older'))[0] == '#101010'
    assert diff.pane('older').palette().base().color().name() == '#101010'


# --- highlighter slot ---

class WindowedStub(QSyntaxHighlighter):
    """Stands in for the WBQ windowed highlighter: constant block state, records the blocks it is asked about."""

    def __init__(self, document):
        super().__init__(document)
        self.blocks: list[str] = []

    def highlightBlock(self, text):  # noqa: N802
        self.blocks.append(text)
        self.setCurrentBlockState(-1)


def test_a_stub_highlighter_attaches_before_the_text_and_survives_set_pair(diff):
    stub = diff.attach_highlighter('older', WindowedStub)
    diff.set_pair(SAMPLE)
    assert stub.document() is diff.pane('older').document() and stub.parent() is diff.pane('older').document()
    assert 'b' in stub.blocks
    diff.set_pair(PairText('p\nq', 'p\nq'))
    assert stub.document() is not None and 'q' in stub.blocks


def test_attaching_again_replaces_the_highlighter_and_detach_releases_it(diff):
    first = diff.attach_highlighter('newer', WindowedStub)
    second = diff.attach_highlighter('newer', WindowedStub)
    assert second is not first and first.document() is None and second.document() is diff.pane('newer').document()
    diff.detach_highlighter('newer')
    assert second.document() is None
    diff.detach_highlighter('newer')


def test_a_highlighter_not_parented_to_the_document_is_refused(diff):
    holder = QTextDocument()
    with pytest.raises(ValueError):
        diff.attach_highlighter('older', lambda _document: WindowedStub(holder))
    assert 'older' not in diff._highlighters
