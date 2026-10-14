"""Older/newer delta of the static import table: which APIs a PE imports now that it did not, and the reverse.

It compares what ``parse_imports`` found and nothing more: delay-load, bound and runtime-resolved imports are
not in that table. An import table that is missing, cut short or partly unreadable gives ``unavailable``;
unknown is never reported as "all removed" or "all added" (WBQ plan section 6, WBQ slice S4).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import PeOverview

PROVENANCE = 'static import table only (delay-load, bound and runtime-resolved imports are not parsed)'

# The only spelling `parse_imports` emits for an ordinal import; any other '#...' text is an ordinary name.
_ORDINAL = re.compile(r'#(?:0|[1-9][0-9]{0,4})')


@dataclass(frozen=True, slots=True)
class ApiChange:
    """`added`: imported only by the newer file. `removed`: imported only by the older file."""

    dll: str  # lower-cased: the loader compares DLL names case-insensitively
    name: str  # as listed in the import table, '#N' for an import by ordinal
    kind: str  # 'name' | 'ordinal'
    change: str  # 'added' | 'removed'


@dataclass(frozen=True, slots=True)
class ApiDelta:
    """`status` uses the FieldComparison vocabulary. `changes` is empty unless `status` is 'changed'. A count is
    the number of distinct (DLL, API) pairs on that side, None when that side's table is unknown."""

    status: str  # 'changed' | 'unchanged' | 'unavailable'
    reason: str
    older_sha256: str
    newer_sha256: str
    older_count: int | None
    newer_count: int | None
    changes: tuple[ApiChange, ...]
    provenance: str = PROVENANCE


def _is_ordinal(name: str) -> bool:
    return _ORDINAL.fullmatch(name) is not None and int(name[1:]) <= 0xFFFF


def _is_placeholder(text: str) -> bool:
    """`parse_imports` stands in `<unreadable ...>` or `<invalid thunk ...>` for entries it could not read.
    Their text carries an RVA, so two builds would 'differ' or 'match' by coincidence."""
    return text.startswith('<') and text.endswith('>')


def _api_set(ov: PeOverview, side: str) -> tuple[frozenset[tuple[str, str]] | None, str]:
    """((dll, api) pairs, '') for a readable table; (None, why) when the side's imports are unknown."""
    info = ov.imports
    if info is None:
        declared = ov.directory('Import')
        if declared is not None and not declared.present:
            return frozenset(), ''  # the headers say the file has no import table: a known, empty one
        return None, f'{side} file: imports could not be read (status {ov.status})'
    if info.truncated or any(dll.truncated for dll in info.dlls):
        return None, f'{side} file: import table was cut short (safety limit or unreadable data)'
    pairs: set[tuple[str, str]] = set()
    for dll in info.dlls:
        if _is_placeholder(dll.name) or any(_is_placeholder(fn) for fn in dll.functions):
            return None, f'{side} file: import table has unreadable entries'
        pairs.update((dll.name.lower(), fn) for fn in dll.functions)
    return frozenset(pairs), ''


def _order(change: ApiChange) -> tuple[str, int, str, int, str]:
    """By DLL, then names (case-insensitive, then exact), then ordinals numerically."""
    if change.kind == 'ordinal':
        return change.dll, 1, '', int(change.name[1:]), ''
    return change.dll, 0, change.name.casefold(), 0, change.name


def _change(pair: tuple[str, str], change: str) -> ApiChange:
    dll, name = pair
    return ApiChange(dll, name, 'ordinal' if _is_ordinal(name) else 'name', change)


def compute_api_delta(*, older: PeOverview, newer: PeOverview) -> ApiDelta:
    """Static-import delta from `older` to `newer`. The sides are keyword-only so they cannot be swapped silently."""
    before, why_before = _api_set(older, 'older')
    after, why_after = _api_set(newer, 'newer')
    counts = (None if before is None else len(before), None if after is None else len(after))
    if before is None or after is None:
        reason = '; '.join(why for why in (why_before, why_after) if why)
        return ApiDelta('unavailable', reason, older.sha256, newer.sha256, *counts, ())
    removed, added = before - after, after - before
    changes = tuple(sorted([*(_change(p, 'removed') for p in removed), *(_change(p, 'added') for p in added)],
                           key=_order))
    if not changes:
        return ApiDelta('unchanged', 'same static import table', older.sha256, newer.sha256, *counts, ())
    reason = f'{len(added)} added, {len(removed)} removed (older to newer)'
    return ApiDelta('changed', reason, older.sha256, newer.sha256, *counts, changes)
