"""Typed, bounded import of a Diaphora `.diaphora` result database (SPEC-DA-01 Mode A). Pure apart from the file read.

Fails closed on structure (missing table or column, unknown category, malformed address, NUL or oversize text);
a missing or unusable ratio stays `None` (never zero). Duplicate (older, newer, category) endpoints keep the first
row and are counted. The source `config.main_db/diff_db` paths are never read into any record.
"""
from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from pathlib import Path

from .address_map import ImageMap, combine, parse_ea
from .contracts import (
    BASE_LIMITATIONS,
    CATEGORIES,
    UNMATCHED_SIDES,
    DiaphoraError,
    DiaphoraMatch,
    DiaphoraMatchSet,
    DiaphoraUnmatched,
    Trust,
)
from .sqlite_guard import MAX_MATCH_ROWS, MAX_UNMATCHED_ROWS, Snapshot, open_snapshot

TEXT_LIMIT = 4096
MAX_BONUS_RATIO = 2.0      # upstream adds MATCHES_BONUS_RATIO (0.01) on top of 1.0; anything beyond is not a ratio


@dataclass(frozen=True)
class Inspection:
    """Everything `diaphora inspect` reports; nothing in it identifies a pair."""
    result_sha256: str
    size: int
    version: str
    date: str
    tables: tuple[str, ...]
    counts: dict[str, int]
    unmatched: int


def _text(value: object, label: str, *, allow_none: bool = False) -> str:
    if value is None and allow_none:
        return ''
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeDecodeError:
            raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} is not UTF-8 text') from None
    if isinstance(value, int | float) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or '\x00' in value:
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} is not plain text')
    if len(value) > TEXT_LIMIT:
        raise DiaphoraError('PT-DIAPHORA-LIMIT', f'{label} exceeds {TEXT_LIMIT} characters')
    return value


def _nodes(value: object, label: str) -> int | None:
    if value is None or value == '':
        return None
    try:
        number = int(str(value).strip())
    except ValueError:
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} is not an integer') from None
    if number < 0 or number > 10**9:
        raise DiaphoraError('PT-DIAPHORA-INPUT', f'{label} is out of range')
    return number


def parse_ratio(value: object) -> tuple[str, int | None, str]:
    """(source text, milli or None, transform). Preserves the source; never turns a missing score into zero."""
    text = _text(value, 'ratio', allow_none=True)
    try:
        number = float(text)
    except ValueError:
        return text, None, 'unavailable'
    if not math.isfinite(number) or number < 0.0 or number > MAX_BONUS_RATIO:
        return text, None, 'unavailable'
    if number > 1.0:
        return text, 1000, 'capped-bonus'
    return text, round(number * 1000), 'direct'


def _read_version(snap: Snapshot) -> tuple[str, str]:
    if 'config' not in snap.tables:
        return '', ''
    for row in snap.rows('config', 1):
        return _text(row[3], 'version', allow_none=True), _text(row[4], 'date', allow_none=True)
    return '', ''


def inspect_result(path: Path, cancel: threading.Event | None = None) -> Inspection:
    with open_snapshot(path, cancel) as snap:
        version, date = _read_version(snap)
        if snap.count('results') > MAX_MATCH_ROWS:
            raise DiaphoraError('PT-DIAPHORA-LIMIT', f'more than {MAX_MATCH_ROWS} match rows')
        counts = dict.fromkeys(CATEGORIES, 0)
        for row in snap.rows('results', MAX_MATCH_ROWS):
            category = _text(row[1], 'type')
            if category not in counts:
                raise DiaphoraError('PT-DIAPHORA-INPUT', f'unknown match category {category[:40]!r}')
            counts[category] += 1
        return Inspection(snap.sha256, snap.size, version, date, tuple(sorted(snap.tables)), counts,
                          snap.count('unmatched'))


def import_result(path: Path, *, older_sha256: str, newer_sha256: str, trust: Trust, older_map: ImageMap,
                  newer_map: ImageMap, expected_result_sha256: str | None = None,
                  cancel: threading.Event | None = None) -> DiaphoraMatchSet:
    """Parse a result into a `DiaphoraMatchSet`. `expected_result_sha256` (from a manifest) is re-checked on the
    private snapshot that is actually parsed, so a file changed after binding cannot be associated."""
    with open_snapshot(path, cancel) as snap:
        if expected_result_sha256 is not None and snap.sha256 != expected_result_sha256:
            raise DiaphoraError('PT-DIAPHORA-PROVENANCE', 'the result file changed after it was bound to the pair')
        version, _date = _read_version(snap)
        if snap.count('results') > MAX_MATCH_ROWS or snap.count('unmatched') > MAX_UNMATCHED_ROWS:
            raise DiaphoraError('PT-DIAPHORA-LIMIT', 'the result database exceeds the row budget')
        matches, seen, duplicates = [], set(), 0
        for index, row in enumerate(snap.rows('results', MAX_MATCH_ROWS)):
            if cancel is not None and cancel.is_set():
                raise DiaphoraError('PT-DIAPHORA-CANCEL', 'import cancelled')
            _rowid, category, _line, a1, n1, a2, n2, ratio, nodes1, nodes2, description = row
            category = _text(category, 'type')
            if category not in CATEGORIES:
                raise DiaphoraError('PT-DIAPHORA-INPUT', f'unknown match category {category[:40]!r}')
            t1, t2 = _text(a1, 'address'), _text(a2, 'address2')
            e1, e2 = parse_ea(t1), parse_ea(t2, 'address2')
            key = (category, e1, e2)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            (r1, s1), (r2, s2) = older_map.rva(e1), newer_map.rva(e2)
            text, milli, transform = parse_ratio(ratio)
            matches.append(DiaphoraMatch(
                index=index, category=category, older_ea_text=t1, newer_ea_text=t2, older_ea=e1, newer_ea=e2,
                older_rva=r1, newer_rva=r2, older_name=_text(n1, 'name', allow_none=True),
                newer_name=_text(n2, 'name2', allow_none=True), ratio_text=text, ratio_milli=milli,
                ratio_transform=transform, older_nodes=_nodes(nodes1, 'nodes1'), newer_nodes=_nodes(nodes2, 'nodes2'),
                heuristic=_text(description, 'description', allow_none=True), address_status=combine(s1, s2)))
        unmatched = []
        for index, row in enumerate(snap.rows('unmatched', MAX_UNMATCHED_ROWS)):
            _rowid, source_side, _line, address, name = row
            source_side = _text(source_side, 'type')
            if source_side not in UNMATCHED_SIDES:
                raise DiaphoraError('PT-DIAPHORA-INPUT', f'unknown unmatched side {source_side[:40]!r}')
            text = _text(address, 'address')
            ea = parse_ea(text)
            primary = source_side == 'primary'          # the first exported database is the older build
            rva, status = (older_map if primary else newer_map).rva(ea)
            unmatched.append(DiaphoraUnmatched(
                index=index, source_side=source_side, side='older' if primary else 'newer', ea_text=text, ea=ea,
                rva=rva, name=_text(name, 'name', allow_none=True), address_status=status))
        notes = list(BASE_LIMITATIONS)
        if any(m.ratio_transform == 'capped-bonus' for m in matches):
            notes.append('Some Diaphora ratios exceeded 1.0 (match bonus); the milli value is capped at 1000, the '
                         'source text is kept.')
        if any(m.address_status != 'verified-rva' for m in matches):
            notes.append('Rows without a verified RVA mapping are listed as Diaphora-only and never count as '
                         'agreeing with Ghidriff.')
        return DiaphoraMatchSet(engine_version=version or 'unknown', older_sha256=older_sha256,
                                newer_sha256=newer_sha256, result_sha256=snap.sha256, trust=trust,
                                matches=tuple(matches), unmatched=tuple(unmatched), duplicate_rows=duplicates,
                                limitations=tuple(notes))
