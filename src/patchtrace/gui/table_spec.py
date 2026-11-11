"""Pure description and preparation of a `VirtualTable` (GUI plan 8.4, slice F4). No Qt.

A feature declares `ColumnSpec`s and a `TableSpec`; `prepare_table` runs in the WORKER and turns its rows into
strings, sort keys, search keys and a default order, so the GUI thread only swaps a pointer. Cell text is
untrusted: every string passes `sanitize_text`.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from .text import sanitize_text

MAX_ROWS = 100_000   # above this the table shows the too-large state instead of rows
COPY_LIMIT = 16_384  # bytes of TSV one Ctrl+C may put on the clipboard
CHECKPOINT_EVERY = 2_048
TRUNCATED_NOTICE = '[truncated at 16 KiB]'
Row = Any


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    """One column. `text(row)` is the display string; `sort_key(row)` orders the column (None sorts last in both
    directions; omitted = the display text, case-folded); `chip(row)` is an opaque value for a chip delegate;
    `accessible(row)` replaces the default "{title}: {text}, {unit}" accessible text; `tooltip(row)` replaces the
    default tooltip (the cell text) and must return escaped rich text."""

    key: str
    title: str
    text: Callable[[Row], object]
    unit: str = ''
    width_em: float = 12.0
    sort_key: Callable[[Row], Any] | None = None
    chip: Callable[[Row], Any] | None = None
    accessible: Callable[[Row], str] | None = None
    tooltip: Callable[[Row], str] | None = None


@dataclass(frozen=True, slots=True)
class TableSpec:
    """`row_key(row)` is a unique string identity that survives a refresh (selection follows it); `search_text(row)`
    feeds the filter; `default_order(row)` is the sort key of the untouched table (omitted = source order)."""

    row_key: Callable[[Row], str]
    search_text: Callable[[Row], object]
    default_order: Callable[[Row], Any] | None = None


@dataclass(frozen=True, slots=True)
class PreparedTable:
    """Immutable result of `prepare_table`. `rows` is empty and `too_large` set when `total` exceeds `MAX_ROWS`."""

    columns: tuple[ColumnSpec, ...]
    rows: tuple[Row, ...]
    keys: tuple[str, ...]
    texts: tuple[tuple[str, ...], ...]
    searches: tuple[str, ...]
    sort_keys: tuple[tuple[Any, ...] | None, ...]  # per column: precomputed keys, None = sort by display text
    order: tuple[int, ...]                         # source indexes in default order
    total: int
    too_large: bool = False


class Cancelled(Exception):
    """The worker's token was set while preparing; the caller drops the result."""


def prepare_table(spec: TableSpec, columns: Sequence[ColumnSpec], rows: Iterable[Row], token: Any = None) -> PreparedTable:
    """Strings, keys and order for `rows`. `token` is any object with `checkpoint() -> bool` (a `CancelToken`);
    a set token raises `Cancelled`. Row keys are expected unique (the first row of a repeated key wins lookups)."""
    columns = tuple(columns)
    source = rows if isinstance(rows, tuple) else tuple(rows)
    if len(source) > MAX_ROWS:
        return PreparedTable(columns, (), (), (), (), tuple(None for _ in columns), (), len(source), True)
    texts, keys, searches = [], [], []
    getters = [column.text for column in columns]
    for position, row in enumerate(source):
        if token is not None and position % CHECKPOINT_EVERY == 0 and token.checkpoint():
            raise Cancelled
        texts.append(tuple([sanitize_text(get(row)) for get in getters]))
        keys.append(sanitize_text(spec.row_key(row), 400))
        searches.append(sanitize_text(spec.search_text(row), 1_000).casefold())
    sort_keys = tuple(tuple(column.sort_key(row) for row in source) if column.sort_key else None for column in columns)
    order = order_by(range(len(source)), spec.default_order and [spec.default_order(row) for row in source])
    return PreparedTable(columns, source, tuple(keys), tuple(texts), tuple(searches), sort_keys, tuple(order),
                         len(source))


def order_by(indexes: Iterable[int], keys: Sequence[Any] | None, descending: bool = False) -> list[int]:
    """Stable order of `indexes` by `keys[index]`; None keys last in both directions; incomparable keys fall back
    to their text so one odd value cannot break a sort."""
    if keys is None:
        return list(indexes)
    present = [i for i in indexes if keys[i] is not None]
    absent = [i for i in indexes if keys[i] is None]
    try:
        present.sort(key=keys.__getitem__, reverse=descending)
    except TypeError:
        present.sort(key=lambda i: str(keys[i]), reverse=descending)
    return present + absent


_FORMULA_PREFIXES = ('=', '+', '-', '@')
_PLAIN_NUMBER = re.compile(r'[+-]?\d+(?:\.\d+)?')


def _spreadsheet_safe(cell: str) -> str:
    """A leading apostrophe stops Excel and Calc from evaluating a pasted cell as a formula; plain numbers stay."""
    if cell.startswith(_FORMULA_PREFIXES) and not _PLAIN_NUMBER.fullmatch(cell):
        return "'" + cell
    return cell


def build_tsv(header: Sequence[str], lines: Iterable[Sequence[str]], limit: int = COPY_LIMIT) -> tuple[str, int, bool]:
    """Tab-separated text of the header and as many `lines` as fit in `limit` UTF-8 bytes, notice included.
    Returns (text, rows copied, truncated). Cells are already single-line (`sanitize_text`);
    formula-looking cells get a leading apostrophe."""
    reserve = len(TRUNCATED_NOTICE.encode()) + 1
    out = ['\t'.join(map(_spreadsheet_safe, header))]
    size = len(out[0].encode())
    copied, truncated = 0, False
    for cells in lines:
        line = '\t'.join(map(_spreadsheet_safe, cells))
        cost = len(line.encode()) + 1
        if size + cost > limit - reserve:
            truncated = True
            break
        out.append(line)
        size += cost
        copied += 1
    if truncated:
        out.append(TRUNCATED_NOTICE)
    text = '\n'.join(out)
    return text.encode()[:limit].decode(errors='ignore'), copied, truncated
