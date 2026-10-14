"""Status chips: ChipLabel, ChipDelegate and the shared painter (GUI plan 8.4, 8.6; slice F3). Offscreen, hermetic."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import QStyleOptionViewItem, QTableView
from qt_support import HOSTILE_PARAMS, join_gui_threads  # noqa: F401

from patchtrace.gui.qt import chips
from patchtrace.gui.qt.chips import (
    CHIP_ROLE,
    ChipDelegate,
    ChipLabel,
    chip_accessible_text,
    chip_size,
    paint_chip,
)
from patchtrace.gui.qt.theme import DARK
from patchtrace.gui.state import CHIP_SHAPES, CHIP_TOKENS, ChipSpec


@pytest.fixture(autouse=True)
def _application(qapp):
    """Font metrics and painters need the application object even in the tests that build no widget."""


def spec(token: str = 'ok', shape: str = 'round', glyph: str = '=', text: str = 'Agree') -> ChipSpec:
    return ChipSpec('k', glyph, text, shape, token)


def render(chip: ChipSpec, tokens=DARK) -> QImage:
    font = QFont()
    size = chip_size(font, chip)
    image = QImage(size, QImage.Format.Format_ARGB32)
    image.fill(QColor(tokens.surface))
    painter = QPainter(image)
    paint_chip(painter, QRect(0, 0, size.width(), size.height()), chip, tokens, font)
    painter.end()
    return image


def test_the_chip_shows_its_glyph_and_words_and_reads_as_the_words():
    chip = spec(glyph='!', text='Contested')
    assert chips.chip_text(chip) == '! Contested'
    assert chip_accessible_text('Verdict', chip) == 'Verdict: Contested'
    assert chip_accessible_text('', chip) == 'Contested'


@pytest.mark.parametrize('token', CHIP_TOKENS)
def test_the_interior_is_the_token_fill_and_plain_has_none(token):
    image = render(spec(token))
    middle = image.height() // 2
    expected = DARK.surface if token == 'plain' else DARK.chip(token).fill
    assert image.pixelColor(2 + image.height() // 4, middle).name() == expected


@pytest.mark.parametrize('shape', CHIP_SHAPES)
def test_every_shape_draws_an_edge_in_the_token_colour(shape):
    image = render(spec('info', shape))
    edge = QColor(DARK.chip('info').edge).name()
    assert any(image.pixelColor(x, 0).name() == edge for x in range(image.width() // 3, 2 * image.width() // 3))


def test_the_shapes_are_distinguishable_without_colour():
    images = {shape: render(spec('muted', shape)) for shape in CHIP_SHAPES}
    names = list(images)
    for index, first in enumerate(names):
        for second in names[index + 1:]:
            assert images[first] != images[second], (first, second)


def test_a_dashed_edge_has_gaps_and_a_solid_one_has_none():
    def top_edge(shape):
        image = render(spec('muted', shape, text='A wide chip text'))
        edge = QColor(DARK.chip('muted').edge).name()
        row = [image.pixelColor(x, 0).name() == edge for x in range(image.width() // 4, 3 * image.width() // 4)]
        return row
    assert all(top_edge('square')) and not all(top_edge('dashed')) and any(top_edge('dashed'))


def test_the_size_grows_with_the_text_and_the_shape():
    assert chip_size(QFont(), spec(text='Long text here')).width() > chip_size(QFont(), spec(text='Hi')).width()
    assert chip_size(QFont(), spec(shape='round')).width() > chip_size(QFont(), spec(shape='square')).width()
    plain = chip_size(QFont(), spec('plain', text='KEV'))
    assert plain.height() == chip_size(QFont(), spec('ok', text='KEV')).height()


def test_chip_label_sets_name_size_and_paints(qtbot):
    chip = spec('caution', 'diamond', '!', 'Contested')
    widget = ChipLabel(chip, prefix='Verdict')
    qtbot.addWidget(widget)
    widget.show()
    assert widget.accessibleName() == 'Verdict: Contested' and widget.sizeHint() == chip_size(widget.font(), chip)
    widget.resize(widget.sizeHint())
    image = widget.grab().toImage()
    assert not image.isNull() and image.width() == widget.sizeHint().width()
    widget.set_spec(spec('ok', text='Agree'))
    assert widget.accessibleName() == 'Verdict: Agree' and widget.spec.text == 'Agree'


@pytest.mark.parametrize('text', HOSTILE_PARAMS)
def test_hostile_chip_text_is_sanitized_before_it_is_named(qtbot, text):
    widget = ChipLabel(spec(text=text), prefix='Verdict')
    qtbot.addWidget(widget)
    name = widget.accessibleName()
    assert not any(char in name for char in '\x00\x1b‮ ')


def test_the_tooltip_goes_through_an_escaping_template(qtbot):
    widget = ChipLabel(spec(), prefix='Verdict')
    qtbot.addWidget(widget)
    widget.set_tip('evidence.badge', verdict='<b>Agree</b>', meaning='x', reason='y')
    assert '<b>' not in widget.toolTip().replace('<br>', '') and '&lt;b&gt;' in widget.toolTip()
    assert widget.accessibleDescription() == '<b>Agree</b>: x'  # data, shown as text by every plain-text sink


def test_tokens_can_change_at_runtime(qtbot):
    widget = ChipLabel(spec())
    qtbot.addWidget(widget)
    widget.set_tokens(DARK)
    assert widget.sizeHint().width() > 0


@pytest.fixture
def table(qtbot):
    model = QStandardItemModel(3, 2)
    for row, chip in enumerate((spec('ok'), spec('error', 'square', '#', 'Failed'), None)):
        item = QStandardItem('=' if chip is None else chip.text)
        if chip is not None:
            item.setData(chip, CHIP_ROLE)
        model.setItem(row, 0, item)
        model.setItem(row, 1, QStandardItem(f'cell {row}'))
    view = QTableView()
    view.setModel(model)
    view.verticalHeader().hide()
    view.setItemDelegateForColumn(0, ChipDelegate(view))
    view.resize(400, 200)
    qtbot.addWidget(view)
    view.show()
    return view


def test_the_delegate_paints_a_chip_in_the_cell_and_leaves_other_cells_alone(table):
    image = table.viewport().grab().toImage()
    fills = {DARK.chip('ok').fill, DARK.chip('error').fill}
    found = {image.pixelColor(x, y).name() for x in range(0, 60) for y in range(0, 2 * table.rowHeight(0))}
    assert fills <= found
    plain_row = table.rowViewportPosition(2) + table.rowHeight(2) // 2
    assert {image.pixelColor(x, plain_row).name() for x in range(0, 40)}.isdisjoint(fills)


def test_the_delegate_size_hint_follows_the_chip(table):
    delegate = table.itemDelegateForColumn(0)
    option = QStyleOptionViewItem()
    option.font = table.font()
    first = delegate.sizeHint(option, table.model().index(0, 0))
    second = delegate.sizeHint(option, table.model().index(1, 0))
    assert first.width() == chip_size(option.font, spec()).width() + 8
    assert second.width() == chip_size(option.font, spec('error', 'square', '#', 'Failed')).width() + 8
    assert delegate.sizeHint(option, table.model().index(2, 0)).width() > 0


def test_the_delegate_survives_a_selected_row_and_new_tokens(table):
    table.selectRow(1)
    table.itemDelegateForColumn(0).set_tokens(DARK)
    assert not table.viewport().grab().toImage().isNull()
    assert table.model().index(0, 0).data(Qt.ItemDataRole.DisplayRole) == 'Agree'
