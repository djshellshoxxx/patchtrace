"""The strings delta of an ordered pair of tables (spec WB3 s7, WB3-S5). Pure: no Qt, no I/O.

Identity is the value hash alone, so a string that moved is "in both" and a layout shift adds nothing. What each
side lacks is only claimed where the basis says that type was read completely on both sides (`basis.py`);
otherwise the row says `indeterminate`. Emulation-derived strings keep their heuristic note. Function links come
from `links.py` and are attached, never inferred here; ranking is `rank.py`; edited pairs are `edits.py`.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace

from ..enrichment.identity import domain_id
from ..intelligence.tools.normalize import FunctionPairing
from ..pe_overview.models import SectionInfo
from . import rank
from .basis import EMULATION_TYPES, BasisVerdict, compare_bases
from .contracts import (
    ChangeStatus,
    EditRef,
    PairingInfo,
    Side,
    SideObservation,
    StringChange,
    StringLink,
    StringsDelta,
)
from .cues import CueContext, cues_for, secret_kind
from .edits import Candidate, EditPair, pair_edits
from .limits import MAX_CHANGE_LINKS, MAX_CHANGE_OFFSETS, MAX_DELTA_ROWS, NONE_U32
from .links import LinkResult
from .regions import region_for_rva
from .table import ENCODINGS, FLAG_SECRET, TYPES, StringRow, StringTable

EMULATION_NOTE = 'Found by emulation only: emulation can miss strings, so absence is not evidence.'
_EMULATION = frozenset(TYPES.index(t) for t in EMULATION_TYPES)

Groups = dict[bytes, list[StringRow]]


@dataclass
class _Entry:
    sha: bytes
    older: list[StringRow]
    newer: list[StringRow]
    status: ChangeStatus
    relocated: bool = False
    edit_of: EditPair | None = None


def _group(table: StringTable, verdict: BasisVerdict) -> tuple[Groups, int]:
    """Rows of the readable types at or above the harmonized length, by value hash; and the rows left out."""
    readable = {TYPES.index(t) for t in verdict.readable_types}
    minimum = verdict.harmonized.min_length
    groups: Groups = defaultdict(list)
    left_out = 0
    for row in table:
        if row.type in readable and row.length >= minimum:
            groups[row.value_sha256].append(row)
        elif row.type not in readable:
            left_out += 1
    return groups, left_out


def _location(rows: Sequence[StringRow]) -> set[int]:
    return {r.rva if r.rva != NONE_U32 else r.offset for r in rows} - {NONE_U32}


def _classify(sha: bytes, older: list[StringRow], newer: list[StringRow], verdict: BasisVerdict) -> _Entry:
    if older and newer:
        same = {r.encoding for r in older} == {r.encoding for r in newer}
        moved = bool(_location(older) and _location(newer) and _location(older) != _location(newer))
        return _Entry(sha, older, newer, 'both' if same else 'representation-changed', relocated=moved)
    rows = older or newer
    unsure = {TYPES[r.type] for r in rows} & verdict.indeterminate
    side = 'only-older' if older else 'only-newer'
    return _Entry(sha, older, newer, 'indeterminate' if unsure else side)


def _function_keys(rows: Sequence[StringRow], links: Mapping[tuple[str, bytes], tuple[StringLink, ...]],
                   side: Side) -> frozenset[str]:
    found = links.get((side, rows[0].value_sha256), ())
    return frozenset(link.function.match_id for link in found if link.function.match_id)


def _pair_edits(entries: Sequence[_Entry], links: Mapping) -> tuple[dict[bytes, _Entry], tuple[str, ...]]:
    """Merge each only-older/only-newer edit pair into one `edited` entry keyed by the newer value hash."""
    olds = [Candidate(e.sha, e.older[0].display, _function_keys(e.older, links, 'older'))
            for e in entries if e.status == 'only-older']
    news = [Candidate(e.sha, e.newer[0].display, _function_keys(e.newer, links, 'newer'))
            for e in entries if e.status == 'only-newer']
    result = pair_edits(olds, news)
    by_sha = {e.sha: e for e in entries}
    merged: dict[bytes, _Entry] = {}
    for pair in result.pairs:
        old, new = by_sha[pair.older], by_sha[pair.newer]
        merged[pair.older] = merged[pair.newer] = _Entry(pair.newer, old.older, new.newer, 'edited', edit_of=pair)
    return merged, result.notes


def _observation(rows: Sequence[StringRow], side: Side, region_of: Callable[[Side, int], str | None]
                 ) -> SideObservation | None:
    if not rows:
        return None
    rvas = sorted({r.rva for r in rows} - {NONE_U32})
    return SideObservation(
        types=tuple(t for t in TYPES if any(TYPES[r.type] == t for r in rows)),
        encodings=tuple(e for e in ENCODINGS if any(ENCODINGS[r.encoding] == e for r in rows)),
        offsets=tuple(sorted({r.offset for r in rows} - {NONE_U32})[:MAX_CHANGE_OFFSETS]),
        rvas=tuple(rvas[:MAX_CHANGE_OFFSETS]), region=region_of(side, rvas[0]) if rvas else None)


def _display(row: StringRow) -> str:
    kind = secret_kind(row.display)
    if row.flags & FLAG_SECRET or kind:
        return f'[redacted {kind or "secret"}]'
    return row.display


def _links(entry: _Entry, links: Mapping) -> tuple[StringLink, ...]:
    older_sha = entry.edit_of.older if entry.edit_of else entry.sha
    found = [*links.get(('older', older_sha), ()), *links.get(('newer', entry.sha), ())]
    return tuple(dict.fromkeys(found))[:MAX_CHANGE_LINKS]


def _change(entry: _Entry, links: Mapping, contexts: Mapping[Side, CueContext],
            region_of: Callable[[Side, int], str | None]) -> StringChange:
    rows = entry.newer or entry.older
    pair = entry.edit_of
    side: Side = 'newer' if entry.newer else 'older'
    older = _observation(entry.older, 'older', region_of)
    newer = _observation(entry.newer, 'newer', region_of)
    region = (newer or older).region
    context = replace(contexts.get(side, CueContext()), region=region)
    display = _display(rows[0])
    lookalike = bool(pair and pair.lookalike)
    cues = cues_for(rows[0].display, context, lookalike=lookalike)
    found = _links(entry, links)
    emulation = any(r.type in _EMULATION for r in rows) and entry.status != 'both'
    tier, reasons = rank.review_tier(entry.status, cues, found, emulation=emulation, lookalike=lookalike,
                                     format_spec=bool(pair and pair.format_spec))
    notes = [EMULATION_NOTE] if emulation else []
    edit = EditRef(of=pair.older.hex(), kind=pair.kind) if pair else None
    ident = domain_id('strings.change', 1, {'value': entry.sha.hex(), 'of': pair.older.hex() if pair else None})
    return StringChange(
        id=ident, value_sha256=entry.sha.hex(), display=display, length=rows[0].length, status=entry.status,
        older=older, newer=newer, links=found, cues=cues, review_tier=tier, reasons=reasons, notes=tuple(notes),
        edit=edit, lookalike_of=pair.older.hex() if lookalike else None)


def compute_delta(older: StringTable, newer: StringTable, *, pairing: FunctionPairing,
                  links: LinkResult | None = None, contexts: Mapping[Side, CueContext] | None = None,
                  sections: Mapping[Side, Sequence[SectionInfo]] | None = None) -> StringsDelta:
    """`older` and `newer` must be tables of those sides (`PT-STR-STALE` otherwise). `contexts` carry each build's
    imports and the project's anchors for the cues; `sections` give the region of a string's RVA."""
    verdict = compare_bases(older.basis, newer.basis)
    digests = {'older_basis_digest': older.basis.digest(), 'newer_basis_digest': newer.basis.digest()}
    pairing_info = PairingInfo(available=pairing.available,
                               notes=tuple(n[:256] for n in (*pairing.notes, *(links.notes if links else ()))))
    if not verdict.comparable:
        return StringsDelta(**digests, comparable=False, basis_notes=verdict.block_reasons, pairing=pairing_info)
    link_map = links.links if links else {}
    old_groups, old_left = _group(older, verdict)
    new_groups, new_left = _group(newer, verdict)
    entries = [_classify(sha, old_groups.get(sha, []), new_groups.get(sha, []), verdict)
               for sha in sorted(old_groups.keys() | new_groups.keys())]
    merged, edit_notes = _pair_edits(entries, link_map)
    final = [e for e in entries if e.sha not in merged]
    final += {id(e): e for e in merged.values()}.values()

    def region_of(side: Side, rva: int) -> str | None:
        return region_for_rva(rva, sections[side]) if sections and side in sections else None
    changes = [_change(e, link_map, contexts or {}, region_of) for e in final
               if e.status != 'both' or (e.relocated and _links(e, link_map))]
    changes.sort(key=rank.sort_key)
    counts = _counts(final, old_left + new_left)
    return StringsDelta(
        **digests, comparable=True, harmonized=verdict.harmonized,
        basis_notes=tuple(n[:256] for n in (*verdict.notes, *edit_notes)), counts=counts,
        changes=tuple(changes[:MAX_DELTA_ROWS]), truncated=len(changes) > MAX_DELTA_ROWS, pairing=pairing_info)


def _counts(entries: Sequence[_Entry], left_out: int) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for entry in entries:
        counts[entry.status] += 1
        counts['relocated'] += entry.relocated
    counts['not-compared-rows'] = left_out
    return dict(sorted(counts.items()))
