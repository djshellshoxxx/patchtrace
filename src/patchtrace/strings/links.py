"""String to function links (WB3-S4): tiers L1 ghidra-xref, L4 decompiled-literal, L5 floss-frame. Pure.

FLOSS static mode cannot say which function uses a string, so links come from the Ghidriff pairing's own evidence
and are shown as tier labels, never combined into a number. A link is never inferred from name similarity: a name
resolves only when it is unique (the `evidence._related` rule), a frame only when exactly one project function
starts there, a literal only when its text equals the string's value. What stays unlinked stays unlinked.
"""
from __future__ import annotations

import hashlib
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from ..enrichment.identity import parse_address
from ..intelligence.tools.common import ToolError, display_text, load_json_strict
from ..intelligence.tools.normalize import FunctionPairing, _record_rva
from ..models import FunctionMatch, FunctionRecord
from . import clit
from .contracts import FunctionRef, Side, StringLink, StringsError
from .limits import MAX_CHANGE_LINKS, MAX_GHIDRIFF_STRINGS, NONE_U32
from .table import ENCODINGS, TYPES, StringRow, StringTable

MAX_RAW_BYTES = 100 * 1024 * 1024  # same bound as the Ghidriff raw loader
MAX_CALLING = 64
MAX_NAME = 256
MIN_PREFIX_CHARS = 16  # a truncated literal is a long string by nature; shorter prefixes would link noise
MAX_PREFIX_HITS = 64
_TIER_ORDER = {'L1': 1, 'L2': 2, 'L3': 3, 'L4': 4, 'L5': 5, 'L6': 6}
_STATIC_TYPES = frozenset(TYPES.index(t) for t in ('static', 'language'))
_FRAME_TYPES = frozenset(TYPES.index(t) for t in ('stack', 'tight'))
_WIDE = ENCODINGS.index('UTF-16LE')

LinkKey = tuple[str, bytes]  # (side, value sha256)


@dataclass(frozen=True)
class GhidriffString:
    side: Side
    rva: int
    calling: tuple[str, ...]


@dataclass(frozen=True)
class GhidriffStrings:
    entries: tuple[GhidriffString, ...]
    raw_sha256: str
    notes: tuple[str, ...] = ()

    @property
    def lineage_group(self) -> str:
        return f'ghidra:{self.raw_sha256}'


@dataclass(frozen=True)
class LinkResult:
    links: dict[LinkKey, tuple[StringLink, ...]]
    notes: tuple[str, ...] = ()


def ghidriff_strings(raw: bytes, *, expected_raw_sha256: str, image_bases: Mapping[str, int]) -> GhidriffStrings:
    """The root `strings` {added, deleted} of a raw Ghidriff document. `added` entries live in the newer build and
    `deleted` in the older one. The bytes must hash to the recorded run (`PT-STR-STALE` otherwise)."""
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_raw_sha256:
        raise StringsError('PT-STR-STALE', 'the stored Ghidriff output is not the recorded run')
    try:
        document = load_json_strict(raw, max_bytes=MAX_RAW_BYTES)
    except ToolError:
        raise StringsError('PT-STR-INPUT', 'the stored Ghidriff output is not valid JSON') from None
    section = document.get('strings') if isinstance(document, dict) else None
    if not isinstance(section, dict):
        return GhidriffStrings((), actual, ('the Ghidriff output has no strings section',))
    entries: list[GhidriffString] = []
    skipped = dropped = 0
    for key, side in (('added', 'newer'), ('deleted', 'older')):
        items = section.get(key, [])
        if not isinstance(items, list):
            skipped += 1
            continue
        if len(items) > MAX_GHIDRIFF_STRINGS:
            raise StringsError('PT-STR-LIMIT', f'more than {MAX_GHIDRIFF_STRINGS} Ghidriff strings')
        for item in items:
            entry, cut = _entry(item, side, image_bases.get(side))
            dropped += cut
            if entry is None:
                skipped += 1
            else:
                entries.append(entry)
    notes = []
    if skipped:
        notes.append(f'{skipped} Ghidriff string entries were unusable and skipped')
    if dropped:
        notes.append(f'{dropped} caller names beyond {MAX_CALLING} per string were ignored')
    return GhidriffStrings(tuple(entries), actual, tuple(notes))


def _entry(item: object, side: Side, base: int | None) -> tuple[GhidriffString | None, int]:
    if not isinstance(item, dict) or base is None or not isinstance(item.get('address'), str):
        return None, 0
    address = parse_address(item['address'])
    if address is None or not 0 <= address - base < NONE_U32:
        return None, 0
    calling = item.get('calling', [])
    if not isinstance(calling, list):
        return None, 0
    names = [name for name in calling if isinstance(name, str) and 0 < len(name) <= MAX_NAME]
    return GhidriffString(side, address - base, tuple(dict.fromkeys(names[:MAX_CALLING]))), max(0, len(names) - MAX_CALLING)


@dataclass(frozen=True)
class SideFunctions:
    """The project's function records of one build, indexed by start RVA and by every name `_related` accepts."""
    side: Side
    records: tuple[FunctionRecord, ...]
    rva_of: dict[str, int | None]
    match_of: dict[str, str | None]
    by_rva: dict[int, tuple[FunctionRecord, ...]] = field(default_factory=dict)
    by_name: dict[str, tuple[FunctionRecord, ...]] = field(default_factory=dict)

    @classmethod
    def from_matches(cls, matches: Iterable[FunctionMatch], side: Side, image_base: int,
                     size_of_image: int | None = None) -> SideFunctions:
        records: dict[str, FunctionRecord] = {}
        match_ids: dict[str, set[str]] = {}
        for match in matches:
            for record in getattr(match, side):
                records.setdefault(record.id, record)
                match_ids.setdefault(record.id, set()).add(match.id)
        rva_of = {rid: _record_rva(record, image_base, size_of_image) for rid, record in records.items()}
        by_rva: dict[int, list[FunctionRecord]] = {}
        by_name: dict[str, dict[str, FunctionRecord]] = {}
        for rid, record in records.items():
            if rva_of[rid] is not None:
                by_rva.setdefault(rva_of[rid], []).append(record)
            for name in (record.name, record.metadata.get('upstream_name'), record.metadata.get('fullname')):
                if isinstance(name, str):
                    by_name.setdefault(name, {})[rid] = record
        return cls(side, tuple(records.values()), rva_of,
                   {rid: next(iter(ids)) if len(ids) == 1 else None for rid, ids in match_ids.items()},
                   {rva: tuple(items) for rva, items in by_rva.items()},
                   {name: tuple(items.values()) for name, items in by_name.items()})


def link_strings(tables: Mapping[str, StringTable], *, pairing: FunctionPairing,
                 functions: Mapping[str, SideFunctions], ghidra_group: str,
                 ghidriff: GhidriffStrings | None = None) -> LinkResult:
    """Links per (side, value hash), strongest tier first, at most `MAX_CHANGE_LINKS` each.

    `ghidra_group` is the lineage group of the Ghidra run behind L1 and L4: both read that one run, so downstream
    evidence counts them once."""
    for side, table in tables.items():
        if table.basis.side != side:
            raise StringsError('PT-STR-LINK', f'the {side} string table describes the {table.basis.side} build')
    found: dict[LinkKey, list[StringLink]] = {}
    notes: list[str] = list(ghidriff.notes) if ghidriff else []
    for side, table in tables.items():
        side_functions = functions.get(side)
        if ghidriff is not None and side_functions is not None:
            notes += _link_xrefs(side, table, side_functions, pairing, ghidriff, ghidra_group, found)
        if side_functions is not None:
            notes += _link_literals(side, table, side_functions, pairing, ghidra_group, found)
            _link_frames(side, table, side_functions, pairing, found)
    capped = sum(1 for items in found.values() if len(set(items)) > MAX_CHANGE_LINKS)
    if capped:
        notes.append(f'{capped} strings have more than {MAX_CHANGE_LINKS} links; the strongest are kept')
    links = {key: tuple(sorted(set(items), key=_order)[:MAX_CHANGE_LINKS]) for key, items in found.items()}
    return LinkResult(links, tuple(notes))


def _order(link: StringLink) -> tuple:
    fn = link.function
    return (_TIER_ORDER[link.tier], fn.rva is None, fn.rva or 0, fn.name or '', link.line or 0, link.evidence_ref)


def _ref(side: Side, record: FunctionRecord, functions: SideFunctions) -> FunctionRef:
    return FunctionRef(side=side, rva=functions.rva_of.get(record.id), project_function_id=record.id,
                       match_id=functions.match_of.get(record.id), name=record.name[:MAX_NAME])


def _status(side: str, record: FunctionRecord, functions: SideFunctions, pairing: FunctionPairing) -> str:
    rva = functions.rva_of.get(record.id)
    return 'unknown' if rva is None else pairing.status(side, rva)


def _row_key(side: str, row: StringRow) -> LinkKey:
    return side, row.value_sha256


def _byte_span(row: StringRow) -> int:
    return row.length * (2 if row.encoding == _WIDE else 1)


# ---- L1 ghidra-xref ------------------------------------------------------------------------------------------

def _link_xrefs(side: Side, table: StringTable, functions: SideFunctions, pairing: FunctionPairing,
                ghidriff: GhidriffStrings, group: str, found: dict[LinkKey, list[StringLink]]) -> list[str]:
    located = sorted(((row.rva, _byte_span(row), row) for row in table
                      if row.type in _STATIC_TYPES and row.rva != NONE_U32), key=lambda item: item[:2])
    if not located:
        return []
    starts = [item[0] for item in located]
    ends = [start + span for start, span, _ in located]
    earlier = _previous_longer(ends)
    unjoined = ambiguous = 0
    for entry in ghidriff.entries:
        if entry.side != side:
            continue
        hit, join = _join_row(entry.rva, located, starts, ends, earlier)
        if hit is None:
            ambiguous += join == 'ambiguous'
            unjoined += join != 'ambiguous'
            continue
        for name in entry.calling:
            found.setdefault(_row_key(side, hit), []).append(
                _name_link(side, name, hit, join, functions, pairing, group, entry.rva))
    notes = []
    if ambiguous:
        notes.append(f'{ambiguous} {side} Ghidriff strings fit several extracted strings and were not linked')
    if unjoined:
        notes.append(f'{unjoined} {side} Ghidriff strings match no extracted string and were not linked')
    return notes


def _previous_longer(ends: list[int]) -> list[int]:
    """For each row, the nearest earlier row whose bytes end later (-1 for none): one stack pass."""
    out, stack = [], []
    for index, end in enumerate(ends):
        while stack and ends[stack[-1]] <= end:
            stack.pop()
        out.append(stack[-1] if stack else -1)
        stack.append(index)
    return out


def _join_row(rva: int, located: list, starts: list[int], ends: list[int],
              earlier: list[int]) -> tuple[StringRow | None, str]:
    """Exact start, else the one string whose bytes contain `rva`; several candidates join nothing.

    Rows that start before `rva` are visited newest first, as before, but a row that ends at or before `rva` jumps
    to the nearest earlier row that ends later: every row in between ends earlier still, so none can contain `rva`.
    One very long string therefore no longer makes every lookup walk most of the table (issue #105 BUG-STR-2)."""
    low, high = bisect_left(starts, rva), bisect_right(starts, rva)
    if high > low:
        return _single((item[2] for item in located[low:high]), 'exact')
    inside = []
    index = low - 1
    while index >= 0:
        if ends[index] > rva:
            inside.append(located[index][2])
            if len({row.value_sha256 for row in inside}) > 1:
                break                                   # already ambiguous
            index -= 1
        else:
            index = earlier[index]
    return _single(inside, 'contains')


def _single(rows: Iterable[StringRow], join: str) -> tuple[StringRow | None, str]:
    rows = list(rows)
    if not rows:
        return None, 'none'
    if len({row.value_sha256 for row in rows}) > 1:
        return None, 'ambiguous'
    return rows[0], join


def _name_link(side: Side, name: str, row: StringRow, join: str, functions: SideFunctions,
               pairing: FunctionPairing, group: str, rva: int) -> StringLink:
    candidates = functions.by_name.get(name, ())
    ref_text = f'rva:0x{rva:x}'
    if len(candidates) == 1:
        record = candidates[0]
        return StringLink(tier='L1', join=join, function=_ref(side, record, functions),
                          pair_status=_status(side, record, functions, pairing), lineage_group=group,
                          evidence_ref=ref_text)
    return StringLink(tier='L1', join=join, function=FunctionRef(side=side, name=name, ambiguous=len(candidates) > 1),
                      pair_status='unknown', lineage_group=group, evidence_ref=ref_text)


# ---- L4 decompiled-literal -----------------------------------------------------------------------------------

@dataclass(frozen=True)
class _Hit:
    record: FunctionRecord
    line: int
    prefix: bool


def _link_literals(side: Side, table: StringTable, functions: SideFunctions, pairing: FunctionPairing, group: str,
                   found: dict[LinkKey, list[StringLink]]) -> list[str]:
    exact: dict[tuple[bool, bytes], list[_Hit]] = {}
    prefixes: list[tuple[bool, str, _Hit]] = []
    capped = []
    for record in functions.records:
        if not record.code:
            continue
        scan = clit.extract_literals(record.code)
        if scan.capped:
            capped.append(record.name[:MAX_NAME])
        for literal in scan.literals:
            for segment in clit.segments(literal.body, truncated=literal.truncated):
                if literal.truncated and segment.open_end:
                    if len(segment.text) >= MIN_PREFIX_CHARS:
                        prefixes.append((literal.wide, segment.text, _Hit(record, literal.line, True)))
                else:
                    digest = hashlib.sha256(segment.text.encode('utf-8', 'surrogatepass')).digest()
                    exact.setdefault((literal.wide, digest), []).append(_Hit(record, literal.line, False))
    if exact:
        for row in table:
            for hit in exact.get((row.encoding == _WIDE, row.value_sha256), ()):
                found.setdefault(_row_key(side, row), []).append(_literal_link(side, hit, 'exact', functions,
                                                                               pairing, group))
    if prefixes:
        _link_prefixes(side, table, prefixes, functions, pairing, group, found)
    return [f'literal scan of {name} stopped at its limit' for name in capped]


def _link_prefixes(side: Side, table: StringTable, prefixes: list, functions: SideFunctions,
                   pairing: FunctionPairing, group: str, found: dict[LinkKey, list[StringLink]]) -> None:
    shown = sorted(table, key=lambda row: row.display)    # never compares rows: equal displays are legal (#105)
    displays = [row.display for row in shown]
    for wide, text, hit in prefixes:
        needle = display_text(text, limit=len(text) * 10 + 4)
        index, taken = bisect_left(displays, needle), 0
        while index < len(shown) and displays[index].startswith(needle) and taken < MAX_PREFIX_HITS:
            row = shown[index]
            if (row.encoding == _WIDE) == wide and row.length > len(text):
                found.setdefault(_row_key(side, row), []).append(_literal_link(side, hit, 'contains', functions,
                                                                               pairing, group))
                taken += 1
            index += 1


def _literal_link(side: Side, hit: _Hit, join: str, functions: SideFunctions, pairing: FunctionPairing,
                  group: str) -> StringLink:
    suffix = ':prefix' if hit.prefix else ''
    return StringLink(tier='L4', join=join, function=_ref(side, hit.record, functions),
                      pair_status=_status(side, hit.record, functions, pairing), line=hit.line,
                      lineage_group=group, evidence_ref=f'{hit.record.id}:line:{hit.line}{suffix}'[:256])


# ---- L5 floss-frame ------------------------------------------------------------------------------------------

def _link_frames(side: Side, table: StringTable, functions: SideFunctions, pairing: FunctionPairing,
                 found: dict[LinkKey, list[StringLink]]) -> None:
    run_ids = [part.run_id for part in table.basis.parts if part.source == 'floss' and part.run_id]
    if not run_ids:
        return
    group = f'emulation:{run_ids[0]}'
    for row in table:
        if row.type not in _FRAME_TYPES or row.fn_rva == NONE_U32:
            continue
        candidates = functions.by_rva.get(row.fn_rva, ())
        if len(candidates) == 1:
            ref = _ref(side, candidates[0], functions)
            status = _status(side, candidates[0], functions, pairing)
        elif candidates:
            ref, status = FunctionRef(side=side, rva=row.fn_rva, ambiguous=True), 'ambiguous'
        else:
            continue
        found.setdefault(_row_key(side, row), []).append(StringLink(
            tier='L5', join='exact', function=ref, pair_status=status, lineage_group=group,
            evidence_ref=f'fn:0x{row.fn_rva:x}'))


__all__ = ['GhidriffString', 'GhidriffStrings', 'LinkResult', 'SideFunctions', 'ghidriff_strings', 'link_strings']
