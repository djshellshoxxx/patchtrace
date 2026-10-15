"""Strings panel view-model (spec WB3 s8): immutable rows, filters, sentences, states, copy. Pure: no Qt, no I/O.

Rows are built once from a `StringsDelta` in review order; filtering only selects and never reorders. Every
visible field is a precomputed, control-escaped string, so a Qt model can return it without further work.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from ..intelligence.tools.common import display_text
from . import copy
from .contracts import Side, StringChange, StringsDelta
from .rank import sort_key

CLIPBOARD_ROWS = 200
CLIPBOARD_BYTES = 16 * 1024
TOOLTIP_CHARS = 300
CHANGED = frozenset({'only-older', 'only-newer', 'edited', 'representation-changed', 'not-compared', 'indeterminate'})
_FILTER_CHANGES = frozenset({'all', 'changed', 'only-older', 'only-newer', 'edited'})


@dataclass(frozen=True, slots=True)
class StringRowVM:
    id: str
    value_sha256: str
    status: str
    change: str
    text: str
    length: int
    type: str
    types: tuple[str, ...]
    older: str
    newer: str
    function: str
    function_ids: tuple[str, ...]
    cues: tuple[str, ...]
    cue_text: str
    source: str
    tier: int
    sentence: str
    description: str
    tooltip: str
    sides: tuple[Side, ...]

    @property
    def key(self) -> tuple[str, str]:
        """Selection identity that survives a reload: (value hash, first side)."""
        return self.value_sha256, self.sides[0]


@dataclass(frozen=True, slots=True)
class StringsFilter:
    change: str = 'changed'
    types: frozenset[str] = frozenset()
    side: Side | None = None
    cues: frozenset[str] = frozenset()
    min_length: int = 0
    text: str = ''
    function: str | None = None
    scope: str = 'differences'
    hide_noise: bool = False

    def __post_init__(self) -> None:
        if self.change not in _FILTER_CHANGES:
            raise ValueError(f'unknown change filter {self.change!r}')
        if self.scope not in copy.SCOPES:
            raise ValueError(f'unknown scope {self.scope!r}')


@dataclass(frozen=True, slots=True)
class FilterResult:
    rows: tuple[StringRowVM, ...]
    hidden_noise: int


def _hex(values: Sequence[int]) -> str:
    if not values:
        return '-'
    more = f' (+{len(values) - 2})' if len(values) > 2 else ''
    return ', '.join(f'0x{v:X}' for v in values[:2]) + more


def _place(change: StringChange, side: Side) -> str:
    observation = change.older if side == 'older' else change.newer
    if observation is None:
        return '-'
    return _hex(observation.offsets or observation.rvas)


def _function_name(change: StringChange) -> str:
    for link in change.links:
        function = link.function
        if function.name or function.rva is not None:
            label = display_text(function.name, 80) if function.name else f'0x{function.rva:X}'
            return f'{label} (ambiguous)' if function.ambiguous else label
    return ''


def _function_ids(change: StringChange) -> tuple[str, ...]:
    ids = (i for link in change.links for i in (link.function.match_id, link.function.project_function_id) if i)
    return tuple(dict.fromkeys(ids))


def _types(change: StringChange) -> tuple[str, ...]:
    return tuple(dict.fromkeys(t for side in (change.older, change.newer) if side for t in side.types))


def _sentence(change: StringChange, function: str, kind: str) -> str:
    parts = [copy.CHANGE_LABELS[change.status][2:] + '.', f'{copy.TYPE_NOUNS[kind]}, {change.length} characters.']
    if function:
        pair = next((copy.PAIR_LABELS[link.pair_status] for link in change.links if link.pair_status != 'unknown'),
                    None)
        parts.append(f'Function {function}' + (f', {pair}.' if pair else '.'))
    if change.cues:
        parts.append(f'{copy.CUE_LABELS[change.cues[0]]}' + (' with ' + copy.CUE_LABELS[change.cues[1]].lower()
                                                            if len(change.cues) > 1 else '') + '.')
    return ' '.join(parts)


def _description(change: StringChange) -> str:
    reasons = ', '.join(r.replace('-', ' ') for r in change.reasons)
    tiers = ', '.join(dict.fromkeys(link.tier for link in change.links))
    parts = [f'Review tier R{change.review_tier}.']
    if reasons:
        parts.append(f'Reasons: {reasons}.')
    if tiers:
        parts.append(f'Link tiers: {tiers}.')
    return ' '.join(parts)


def _source(change: StringChange, source_of: dict[Side, str]) -> str:
    return ', '.join(source_of[s] for s in ('older', 'newer') if (change.older if s == 'older' else change.newer)
                     and s in source_of)


def row_for(change: StringChange, source_of: dict[Side, str] | None = None) -> StringRowVM:
    text = display_text(change.display)
    function = _function_name(change)
    types = _types(change)
    sentence = _sentence(change, function, types[0] if types else 'static')
    sides = tuple(s for s, o in (('older', change.older), ('newer', change.newer)) if o is not None) \
        or ('newer',)
    return StringRowVM(
        id=change.id, value_sha256=change.value_sha256, status=change.status,
        change=copy.CHANGE_LABELS[change.status], text=text, length=change.length, type=', '.join(copy.TYPE_LABELS[t] for t in types), types=types,
        older=_place(change, 'older'), newer=_place(change, 'newer'), function=function,
        function_ids=_function_ids(change), cues=change.cues,
        cue_text=', '.join(copy.CUE_LABELS[c] for c in change.cues), source=_source(change, source_of or {}),
        tier=change.review_tier, sentence=sentence, description=_description(change),
        tooltip=(sentence + ' ' + text)[:TOOLTIP_CHARS], sides=sides)


def build_rows(delta: StringsDelta, source_of: dict[Side, str] | None = None) -> tuple[StringRowVM, ...]:
    """Rows of a comparable delta in review order; a non-comparable delta has none."""
    return tuple(row_for(c, source_of) for c in sorted(delta.changes, key=sort_key))


def _matches(row: StringRowVM, flt: StringsFilter, needle: str) -> bool:
    if flt.change not in ('all', 'changed') and row.status != flt.change:
        return False
    if (flt.change == 'changed' or flt.scope == 'differences') and row.status not in CHANGED:
        return False
    if (flt.side and flt.side not in row.sides) or row.length < flt.min_length:
        return False
    if flt.types and not flt.types & set(row.types):
        return False
    if flt.cues and not flt.cues & set(row.cues):
        return False
    if flt.function and flt.function not in row.function_ids:
        return False
    return not needle or needle in row.text.casefold()


def apply_filter(rows: Iterable[StringRowVM], flt: StringsFilter) -> FilterResult:
    """Select rows, keeping order. Noise-like rows are hidden only in the inventory scope, and counted."""
    needle = flt.text.casefold()
    kept: list[StringRowVM] = []
    hidden = 0
    for row in rows:
        if not _matches(row, flt, needle):
            continue
        if flt.hide_noise and flt.scope == 'all' and 'noise-like' in row.cues:
            hidden += 1
            continue
        kept.append(row)
    return FilterResult(tuple(kept), hidden)


def differing(rows: Iterable[StringRowVM]) -> int:
    return sum(1 for row in rows if row.status in CHANGED)


def state_text(state: str, **values: object) -> str:
    """Exact panel copy for a state; values are escaped and capped so tool text cannot add markup or controls."""
    return copy.STATES[state].format(**{k: display_text(str(v), 200) for k, v in values.items()})


def delta_state(delta: StringsDelta) -> tuple[str, str]:
    """`(state id, text)` of a loaded delta: blocked, ready or ready-none."""
    if not delta.comparable:
        return 'blocked', state_text('blocked', reason='; '.join(delta.basis_notes) or 'the settings differ')
    count = differing(build_rows(delta))
    return ('ready', state_text('ready', n=count)) if count else ('ready-none', state_text('ready-none'))


def copy_escaped(rows: Iterable[StringRowVM]) -> str:
    """Escaped single-line text of up to 200 rows / 16 KiB. Secret-like rows already hold only their redaction."""
    lines: list[str] = []
    size = 0
    for row in rows:
        line = f'{row.change}\t{row.text}\t{row.type}\t{row.function}'
        size += len(line.encode('utf-8')) + 1
        if len(lines) >= CLIPBOARD_ROWS or size > CLIPBOARD_BYTES:
            break
        lines.append(line)
    return '\n'.join(lines)


def reselect(rows: Sequence[StringRowVM], key: tuple[str, str] | None) -> int | None:
    """Index of the row with the selection key after a reload, else None."""
    return next((i for i, row in enumerate(rows) if row.key == key), None) if key else None
