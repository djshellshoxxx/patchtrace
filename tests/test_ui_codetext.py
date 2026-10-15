"""Code colours and token marks (WBQ S9): windowed highlighter, lifetime and fail-closed rules, F8, label, budgets."""
from __future__ import annotations

import difflib
import re
import time
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QTextOption
from PySide6.QtWidgets import QPlainTextEdit
from qt_support import a11y_audit, join_gui_threads  # noqa: F401

from patchtrace import codetext_view as cv
from patchtrace import tooltips
from patchtrace.codetext import CodeTextModel, Palette, StyleKey, contrast_ratio
from patchtrace.gui.pair_text import PairText, align_pair
from patchtrace.gui.qt.codediff import CodeDiffView
from patchtrace.ui_codetext import CodeHighlighter, CodeTextController

SOURCE = Path(__file__).resolve().parent.parent / 'src' / 'patchtrace' / 'ui_codetext.py'


def pair_of(old: list[str], new: list[str]) -> PairText:
    return align_pair(old, new, difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes())


def body(count: int, edit_every: int = 0, edit: str = '0x40') -> list[str]:
    lines = []
    for n in range(count):
        value = edit if edit_every and n % edit_every == 0 else '0x20'
        lines.append(f'  int v{n} = {value}; // line {n}')
    return lines


def small_pair() -> PairText:
    old = ['int f(int a) {', '  if (a > 0x20) {', '    return FUN_140001000(a);', '  }', '  return a;', '}']
    new = ['int f(int a) {', '  if (a > 0x40) {', '    return FUN_140001040(a);', '  }', '  return a;', '}']
    return pair_of(old, new)


@pytest.fixture(autouse=True)
def private_tips(monkeypatch):
    monkeypatch.setattr(tooltips, 'REGISTRY', dict(tooltips.REGISTRY))


@pytest.fixture
def panes(qtbot):
    older, newer = QPlainTextEdit(), QPlainTextEdit()
    for pane in (older, newer):
        qtbot.addWidget(pane)
        pane.resize(600, 400)
        pane.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
    older.show()
    return older, newer


@pytest.fixture
def controller(panes):
    announced: list[str] = []
    made = CodeTextController(*panes, announce=announced.append)
    made.announced = announced
    yield made
    made.shutdown()


def load(controller, panes, pair: PairText, language: str = 'c') -> None:
    controller.begin(pair, language)  # the model first, then the text (the order is the contract)
    panes[0].setPlainText(pair.older)
    panes[1].setPlainText(pair.newer)
    controller.finish()


def formatted(pane: QPlainTextEdit, first: int, last: int) -> list[int]:
    out = []
    for number in range(first, last + 1):
        block = pane.document().findBlockByNumber(number)
        if block.isValid() and block.layout().formats():
            out.append(number)
    return out


def underline_styles(pane: QPlainTextEdit) -> set:
    return {fmt.format.underlineStyle() for block in range(pane.document().blockCount())
            for fmt in pane.document().findBlockByNumber(block).layout().formats()}


# ---- pure ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize('first,visible,rows,expected', [
    pytest.param(0, 20, 1000, (0, 100), id='top'), pytest.param(500, 20, 1000, (420, 600), id='middle'),
    pytest.param(990, 20, 1000, (910, 999), id='bottom'), pytest.param(0, 20, 0, (0, -1), id='empty'),
    pytest.param(5, 20, 3, (0, 2), id='short')])
def test_window_bounds(first, visible, rows, expected):
    assert cv.window_bounds(first, visible, rows) == expected


def test_language_by_mode():
    assert [cv.language_for_mode(m) for m in range(6)] == ['c', 'asm', None, None, None, None]


def test_model_pairs_only_replace_rows_with_a_line_on_both_sides():
    pair = pair_of(['a = 1;', 'b = 2;', 'c = 3;'], ['a = 1;', 'b = 9;', 'c = 3;', 'd = 4;'])
    model = cv.model_for_pair(pair, 'c')
    assert model.paired_rows == (1,)
    assert model.rows == 4


def test_palette_text_looks_reach_contrast_on_all_three_backgrounds():
    palette = Palette('dark')
    for role in ('keyword', 'number', 'string', 'comment', 'address', 'register', 'stack', 'symbol'):
        color = cv.look(StyleKey(role, None), palette, palette.backgrounds).color
        assert color == palette.style(role).color
        assert all(contrast_ratio(color, ground) >= 4.5 for ground in palette.backgrounds)


def test_guard_falls_back_to_the_text_colour_on_a_hostile_background():
    palette = Palette('dark')
    result = cv.look(StyleKey('number', None), palette, ['#e9a93a'])
    assert result.color == palette.style('text').color


def test_marks_keep_their_underline_style_without_colours():
    result = cv.look(StyleKey('keyword', 'address-only'), Palette('dark'), (), colors=False)
    assert (result.color, result.underline, result.italic) == (None, 'dotted', True)


# ---- highlighter --------------------------------------------------------------------------------------------------


def test_windowed_highlighter_formats_only_the_window(controller, panes):
    controller.configure(True, True)
    pair = pair_of(body(3000), body(3000, edit_every=50))
    load(controller, panes, pair)
    near = formatted(panes[0], 0, 60)
    far = formatted(panes[0], 400, 2999)
    assert len(near) > 40
    assert far == []


def test_scroll_updates_window_within_budget(controller, panes):
    controller.configure(True, True)
    load(controller, panes, pair_of(body(6500), body(6500, edit_every=40)))
    assert formatted(panes[0], 3000, 3100) == []
    start = time.perf_counter()
    panes[0].verticalScrollBar().setValue(3000)
    elapsed = time.perf_counter() - start
    assert len(formatted(panes[0], 3000, 3040)) > 20
    assert elapsed <= 0.03 * 4, f'a scroll jump took {elapsed:.3f}s'  # the plan's 30 ms gate, 4x for shared CI CPUs


def test_highlighter_is_parented_to_its_document_and_state_is_constant(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    for pane in panes:
        highlighters = pane.document().findChildren(CodeHighlighter)
        assert len(highlighters) == 1
        assert highlighters[0].parent() is pane.document()
        assert {pane.document().findBlockByNumber(n).userState() for n in range(6)} == {-1}


def test_source_never_calls_rehighlight():
    text = SOURCE.read_text(encoding='utf-8')
    assert not re.search(r'\.rehighlight\(', text)
    assert re.search(r'rehighlightBlock', text)


def test_marks_are_drawn_with_underline_and_syntax_with_colour(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    assert QTextCharFormat.UnderlineStyle.SingleUnderline in underline_styles(panes[0])  # changed constant
    assert QTextCharFormat.UnderlineStyle.DotLine in underline_styles(panes[0])  # address-only
    colors = {fmt.format.foreground().color().name() for fmt in panes[0].document().findBlockByNumber(1).layout().formats()}
    assert Palette('dark').style('number').color in colors


def test_colours_only_draws_no_underline(controller, panes):
    controller.configure(True, False)
    load(controller, panes, small_pair())
    assert underline_styles(panes[0]) <= {QTextCharFormat.UnderlineStyle.NoUnderline}
    assert formatted(panes[0], 0, 5)


def test_a_live_base_that_hides_a_colour_falls_back_to_the_text_colour(panes):
    controller = CodeTextController(*panes, live_base=lambda: '#ffffff')
    controller.configure(True, False)
    load(controller, panes, small_pair())
    colors = {fmt.format.foreground().color().name() for fmt in panes[0].document().findBlockByNumber(1).layout().formats()}
    assert colors == {Palette('dark').style('text').color}  # every role is unreadable on white: no colour is lost to it
    controller.shutdown()


def test_marks_only_draws_no_syntax_colour(controller, panes):
    controller.configure(False, True)
    load(controller, panes, small_pair())
    layout = panes[0].document().findBlockByNumber(1).layout()
    assert layout.formats()
    assert all(not fmt.format.hasProperty(QTextCharFormat.Property.ForegroundBrush) for fmt in layout.formats())


def test_format_never_sets_family_or_size(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    for block in range(6):
        for fmt in panes[0].document().findBlockByNumber(block).layout().formats():
            assert not fmt.format.hasProperty(QTextCharFormat.Property.FontFamilies)
            assert not fmt.format.hasProperty(QTextCharFormat.Property.FontPointSize)
            assert not fmt.format.hasProperty(QTextCharFormat.Property.FontPixelSize)


def test_toggle_off_restores_plain_text(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    assert formatted(panes[0], 0, 5)
    text = panes[0].toPlainText()
    controller.configure(False, False)
    assert formatted(panes[0], 0, 5) == []
    assert panes[0].toPlainText() == text
    assert not panes[0].document().findChildren(QSyntaxHighlighter)


def test_toggle_on_after_text_formats_without_setting_text_again(controller, panes):
    load(controller, panes, small_pair())  # off: nothing drawn, but the pair is remembered
    assert formatted(panes[0], 0, 5) == []
    controller.configure(True, True)
    assert formatted(panes[0], 0, 5)


def test_mode_and_orientation_swap_replace_the_model(controller, panes):
    controller.configure(True, True)
    first = small_pair()
    load(controller, panes, first)
    old_model = controller._model
    swapped = pair_of(first.newer.split('\n'), first.older.split('\n'))  # the orientation swap
    load(controller, panes, swapped)
    assert controller._model is not old_model
    assert controller.label.full_text() == ''
    controller.begin(swapped, None)  # a mode without a language
    assert controller._model is None


def test_row_model_matches_document_blocks(controller, panes):
    controller.configure(True, True)
    pair = small_pair()
    load(controller, panes, pair)
    assert controller._model.rows == panes[0].document().blockCount() == panes[1].document().blockCount()


def test_a_stale_model_cannot_colour_other_text(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    panes[0].setPlainText('completely different text 0x99')
    assert formatted(panes[0], 0, 0) == []  # the model's row text no longer matches the block


def test_failure_in_the_model_fails_closed_with_the_notice(controller, panes, qtbot, monkeypatch):
    controller.configure(True, True)
    notices: list[str] = []
    controller.notice.connect(notices.append)

    def boom(self, side, row, text):
        raise RuntimeError('boom')
    monkeypatch.setattr(CodeTextModel, 'spans', boom)
    load(controller, panes, small_pair())
    qtbot.waitUntil(lambda: not controller.enabled and not panes[0].document().findChildren(QSyntaxHighlighter),
                    timeout=3000)
    assert notices == [cv.DISABLED_AFTER_ERROR]
    assert panes[0].toPlainText() == small_pair().older


def test_suppress_colors_keeps_underline(controller, panes):
    suppress = QTextOption.Flag.SuppressColors
    controller.configure(True, True)
    load(controller, panes, small_pair())
    controller.set_suppress_colors(True)
    assert panes[0].document().defaultTextOption().flags() & suppress
    assert QTextCharFormat.UnderlineStyle.SingleUnderline in underline_styles(panes[0])
    controller.set_suppress_colors(False)
    assert not panes[0].document().defaultTextOption().flags() & suppress


def test_extra_selections_from_hunks_are_untouched(qtbot):
    view = CodeDiffView()
    qtbot.addWidget(view)
    view.show()
    controller = CodeTextController(view.pane('older'), view.pane('newer'))
    controller.configure(True, True)
    pair = small_pair()
    controller.show_pair(view, pair, 'c')
    selections = view.pane('older').extraSelections()
    assert selections, 'the hunk background is still drawn'
    assert formatted(view.pane('older'), 0, 5)
    colors = {fmt.format.foreground().color().name() for fmt in view.pane('older').document().findBlockByNumber(1).layout().formats()}
    assert Palette('dark').style('number').color in colors  # syntax foreground survives on a hunk row
    controller.shutdown()


# ---- label and F8 -------------------------------------------------------------------------------------------------


def test_line_changes_label_text(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    cursor = panes[0].textCursor()
    cursor.setPosition(panes[0].document().findBlockByNumber(1).position())
    panes[0].setTextCursor(cursor)
    assert controller.label.full_text().startswith('Line 2 of 6: 1 change: ')
    assert '0x20 -> 0x40' in controller.label.full_text()
    assert controller.announced[-1] == controller.label.full_text()
    cursor.setPosition(panes[0].document().findBlockByNumber(3).position())
    panes[0].setTextCursor(cursor)
    assert controller.label.full_text() == ''


def test_address_only_row_never_reads_as_unchanged(controller, panes):
    controller.configure(True, True)
    load(controller, panes, small_pair())
    cursor = panes[0].textCursor()
    cursor.setPosition(panes[0].document().findBlockByNumber(2).position())
    panes[0].setTextCursor(cursor)
    text = controller.label.full_text()
    assert 'address-only difference (FUN_140001000 -> FUN_140001040)' in text


def test_f8_walks_changed_marks_only(controller, panes):
    controller.configure(True, True)
    pair = pair_of(body(40, 10), body(40, 10, '0x41'))
    # rows 0, 10, 20, 30 differ by a constant; add an address-only row between them
    old = pair.older.split('\n')
    new = pair.newer.split('\n')
    old[5], new[5] = '  call FUN_140001000', '  call FUN_140001040'
    pair = pair_of(old, new)
    load(controller, panes, pair)
    controller.walked.connect(lambda row: visited.append(row))
    visited: list[int] = []
    cursor = panes[0].textCursor()
    cursor.setPosition(0)
    panes[0].setTextCursor(cursor)
    for _ in range(3):
        assert controller.step_change(1)
    assert visited == [10, 20, 30]  # row 5 is address-only: not a stop
    assert controller.step_change(-1) and visited[-1] == 20
    assert controller.step_change(1) and controller.step_change(1) is False
    assert controller.announced[-1] == cv.NO_CHANGE_STOP


def test_step_without_marks_is_a_no_op(controller, panes):
    controller.configure(True, False)
    load(controller, panes, small_pair())
    assert controller.step_change(1) is False


def test_accessible_name_and_audit(controller, panes):
    assert controller.label.accessibleName() == 'Line changes'
    assert controller.label.textFormat() == Qt.TextFormat.PlainText
    assert 'What' in tooltips.plain_description('viewer.line_changes')
    assert a11y_audit(controller.label) == []


# ---- budgets (the plan's gates, already 3x the measurement) ---------------------------------------------------------


def test_install_at_65k_lines_stays_inside_the_budget(controller, panes):
    controller.configure(True, True)
    pair = pair_of(body(65_000), body(65_000, edit_every=97))
    start = time.perf_counter()
    load(controller, panes, pair)
    elapsed = time.perf_counter() - start
    assert elapsed <= 450 / 1000 * 4, f'install + first paint took {elapsed:.3f}s'
    assert formatted(panes[0], 400, 64_999) == []


def test_tokenizing_200k_chars_in_the_model_stays_inside_the_budget():
    lines = body(5000)
    assert 160_000 < sum(len(line) + 1 for line in lines) < 260_000
    model = CodeTextModel(lines, lines, 'c', colors=True, marks=False)
    start = time.perf_counter()
    for row, line in enumerate(lines):
        model.spans('older', row, line)
    assert time.perf_counter() - start <= 0.15 * 4
