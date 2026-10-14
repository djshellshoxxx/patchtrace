"""Pure table description and preparation (GUI plan 8.4, slice F4). No Qt."""
from __future__ import annotations

import pytest

from patchtrace.gui.table_spec import (
    COPY_LIMIT,
    MAX_ROWS,
    TRUNCATED_NOTICE,
    Cancelled,
    ColumnSpec,
    TableSpec,
    build_tsv,
    order_by,
    prepare_table,
)

COLUMNS = (ColumnSpec('name', 'Name', lambda r: r[0]),
           ColumnSpec('score', 'Score', lambda r: '' if r[1] is None else r[1], unit='milli', sort_key=lambda r: r[1]))
SPEC = TableSpec(row_key=lambda r: r[0], search_text=lambda r: f'{r[0]} {r[1]}', default_order=lambda r: r[2])
ROWS = (('b', 5, 2), ('a', None, 1), ('<b>c</b>\n', 7, 0))


def test_prepare_sanitizes_and_orders_by_the_default_key():
    table = prepare_table(SPEC, COLUMNS, ROWS)
    assert table.order == (2, 1, 0)
    assert table.texts[2] == ('<b>c</b> ', '7')
    assert table.keys == ('b', 'a', '<b>c</b> ')
    assert table.searches[0] == 'b 5'
    assert table.sort_keys[0] is None and table.sort_keys[1] == (5, None, 7)
    assert not table.too_large and table.total == 3


def test_prepare_without_a_default_order_keeps_source_order():
    plain = TableSpec(row_key=lambda r: r[0], search_text=lambda r: r[0])
    assert prepare_table(plain, COLUMNS, ROWS).order == (0, 1, 2)


def test_more_than_the_ceiling_is_a_too_large_state_without_rows():
    table = prepare_table(SPEC, COLUMNS, range(MAX_ROWS + 1))
    assert table.too_large and table.total == MAX_ROWS + 1 and table.rows == () and table.order == ()


def test_a_set_token_cancels():
    class Set:
        def checkpoint(self) -> bool:
            return True
    with pytest.raises(Cancelled):
        prepare_table(SPEC, COLUMNS, ROWS, Set())


@pytest.mark.parametrize('descending', [False, True], ids=['asc', 'desc'])
def test_order_by_is_stable_and_puts_none_last(descending):
    keys = [2, None, 1, 2, None, 1]
    result = order_by(range(6), keys, descending)
    assert result == ([0, 3, 2, 5, 1, 4] if descending else [2, 5, 0, 3, 1, 4])


def test_order_by_survives_incomparable_keys():
    assert order_by(range(3), [1, 'a', 2]) == [0, 2, 1]


def test_tsv_header_only_when_nothing_selected():
    assert build_tsv(['A', 'B'], []) == ('A\tB', 0, False)


def test_tsv_is_capped_at_16_kib_with_a_notice():
    lines = ([f'row{n}', 'x' * 100] for n in range(1_000))
    text, copied, truncated = build_tsv(['Name', 'Text'], lines)
    assert truncated and 0 < copied < 1_000
    assert len(text.encode()) <= COPY_LIMIT and text.endswith(TRUNCATED_NOTICE)
    assert text.count('\n') == copied + 1


def test_tsv_cuts_multibyte_text_on_a_character_boundary():
    text, _, _ = build_tsv(['H' * 20_000], [], limit=11)
    assert text == 'H' * 11
    text, _, _ = build_tsv(['é' * 20], [], limit=11)
    assert len(text.encode()) <= 11 and set(text) == {'é'}
