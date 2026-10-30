"""Symbol-derived labels and tags for one Tier-W pair (SPEC-33 s6.1, s6.2, s6.4). Pure: symbol maps and engine matches
in, strict records out. Names are local-only data (decision O1); they appear only in `tier-w-label-detail/1`.

Truth: a name that is unique and alias-free on both sides, sized on both sides, whose size ratio min/max reaches
`ratio_min`. Every other name is excluded with a reason and never becomes a negative. `no-counterpart` is never derived
from symbols (a C++ rename changes the mangled name); those cases go to human review.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .contracts import DetailSide, Ident, LabelDetail, MatchLine, Symbol, SymbolMap

RATIO_MIN = 0.33
SOURCE = 'symbol-derived'
EXCLUSIONS = ('non-unique', 'alias', 'no-size', 'size-ratio', 'absent-in-newer', 'absent-in-older')

_N2_PREFIX = ('__imp_', '__tailMerge_', '__delayLoadHelper', 'j_')
_N2_PART = ('@ILT+', '??_9', '[thunk]')
_N9_PREFIX = ('__C_specific_handler', '__chkstk', '_alloca_probe', '_guard_', '__guard_', '_RTC_', '__CxxFrameHandler',
              '__security_check_cookie', '__security_init_cookie', '__GSHandlerCheck')
_N9_PART = ('??_E', '??_G', '??__E', '??__F', '$filt$', '$fin$', '?dtor$', '?catch$')
_N10 = re.compile(r'(\.cold$|\$cold\$|_cold_\d+$|\.part\.\d+$)')
_N3_NAMES = frozenset('''memcpy memmove memset memcmp memchr strlen strcpy strncpy strcmp strncmp strcat strncat strchr strrchr
strstr wcslen wcscpy wcsncpy wcscmp wcsncmp wcscat wcsncat wcschr wcsrchr wcsstr _stricmp _wcsicmp _strnicmp _wcsnicmp
RtlCopyMemory RtlMoveMemory RtlZeroMemory RtlFillMemory'''.split())
_N3_PREFIX = ('StringC', '__acrt_', '__vcrt_', '__scrt_', '__std_', 'WPP_', '_tlg', 'TraceLogging', 'McGenEventWrite',
              'McTemplate', 'McGenControlCallback', 'EventWrite')
_N3_PART = ('@std@@', '@wil@@', '@WRL@Microsoft@@', '@ATL@@', '@Concurrency@@')


class LabelRecord(BaseModel):
    """One `<pair>.truth.jsonl` / `<pair>.candidates.jsonl` line (keys of `guard.LABEL_KEYS` plus provenance)."""
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)
    tier: Literal['W']
    pair: Ident
    match_id: str = Field(min_length=1, max_length=200)
    A: Literal['same', 'different']
    source: Literal['symbol-derived']
    stratum: Literal['natural']
    stage: Literal['symbols-hidden']
    p_incl: float = Field(gt=0, le=1)


@dataclass(frozen=True)
class Truth:
    name: str
    older: Symbol
    newer: Symbol

    @property
    def match_id(self) -> str:
        return match_id(self.older.rva, self.newer.rva)


@dataclass(frozen=True)
class Exclusion:
    reason: str
    older: tuple[Symbol, ...]
    newer: tuple[Symbol, ...]


@dataclass(frozen=True)
class Candidate:
    older_rva: int
    newer_rva: int
    engine: str
    answer: Literal['same', 'different'] | None
    rule: str
    match_id: str


def match_id(older_rva: int | None, newer_rva: int | None) -> str:
    fmt = lambda v: 'none' if v is None else f'{v:x}'  # noqa: E731
    return f'sym:{fmt(older_rva)}-{fmt(newer_rva)}'


def _by_name(symbols: Iterable[Symbol]) -> dict[str, list[Symbol]]:
    out: dict[str, list[Symbol]] = defaultdict(list)
    for symbol in symbols:
        out[symbol.name].append(symbol)
    return out


def derive_truth(older: SymbolMap, newer: SymbolMap, ratio_min: float = RATIO_MIN) -> tuple[list[Truth], list[Exclusion]]:
    """(truth sorted by older RVA, exclusions sorted by reason then first RVA). Pure and order independent."""
    if not 0 < ratio_min <= 1:
        raise ValueError('ratio_min must be in (0, 1]')
    old, new = _by_name(older.symbols), _by_name(newer.symbols)
    truth, excluded = [], []
    for name in sorted(old.keys() | new.keys()):
        o, n = old.get(name, []), new.get(name, [])
        reason = _exclusion(o, n, ratio_min)
        if reason:
            excluded.append(Exclusion(reason, tuple(o), tuple(n)))
        else:
            truth.append(Truth(name, o[0], n[0]))
    truth.sort(key=lambda t: t.older.rva)
    excluded.sort(key=lambda e: (e.reason, (e.older or e.newer)[0].rva))
    return truth, excluded


def _exclusion(o: Sequence[Symbol], n: Sequence[Symbol], ratio_min: float) -> str | None:
    if len(o) > 1 or len(n) > 1:
        return 'non-unique'
    if not n:
        return 'absent-in-newer'
    if not o:
        return 'absent-in-older'
    if o[0].aliases or n[0].aliases:
        return 'alias'
    if not o[0].size or not n[0].size:
        return 'no-size'
    if min(o[0].size, n[0].size) / max(o[0].size, n[0].size) < ratio_min:
        return 'size-ratio'
    return None


def label_candidates(truth: Sequence[Truth], matches: Iterable[MatchLine]) -> list[Candidate]:
    """Label one-to-one engine matches from a `symbols-hidden` run (s6.2). Matches with an unpaired side, or from a
    run that had symbols visible (circular), are not candidates."""
    same = {(t.older.rva, t.newer.rva) for t in truth}
    new_of = {t.older.rva: t.newer.rva for t in truth}
    old_of = {t.newer.rva: t.older.rva for t in truth}
    out = []
    for m in matches:
        if m.condition == 'symbols-visible' or m.older_rva is None or m.newer_rva is None:
            continue
        pair = (m.older_rva, m.newer_rva)
        if pair in same:
            answer, rule = 'same', 'truth-pair'
        elif new_of.get(m.older_rva, m.newer_rva) != m.newer_rva or old_of.get(m.newer_rva, m.older_rva) != m.older_rva:
            answer, rule = 'different', 'truth-conflict'
        else:
            answer, rule = None, 'no-truth'
        out.append(Candidate(*pair, m.engine, answer, rule, m.match_id))
    return sorted(out, key=lambda c: (c.engine, c.older_rva, c.newer_rva))


def tags_for(name: str, *, thunk: bool = False, exported: bool = False) -> tuple[str, ...]:
    """`exported` plus the first matching subtype in the order N2 > N9 > N10 > N3 (s6.4)."""
    tags = ['exported'] if exported else []
    if thunk or name.startswith(_N2_PREFIX) or any(p in name for p in _N2_PART):
        tags.append('N2')
    elif name.startswith(_N9_PREFIX) or any(p in name for p in _N9_PART):
        tags.append('N9')
    elif _N10.search(name):
        tags.append('N10')
    elif name in _N3_NAMES or name.startswith(_N3_PREFIX) or any(p in name for p in _N3_PART):
        tags.append('N3')
    return tuple(tags)


def _side(symbol: Symbol, exports: Collection[int]) -> DetailSide:
    exported = symbol.rva in exports
    return DetailSide(rva=symbol.rva, name=symbol.name, size=symbol.size, exported=exported,
                      tags=tags_for(symbol.name, thunk=symbol.thunk, exported=exported))


def _empty() -> DetailSide:
    return DetailSide(rva=None)


def truth_records(pair: str, truth: Sequence[Truth]) -> list[LabelRecord]:
    return [LabelRecord(tier='W', pair=pair, match_id=t.match_id, A='same', source=SOURCE, stratum='natural',
                        stage='symbols-hidden', p_incl=1.0) for t in truth]


def candidate_records(pair: str, candidates: Iterable[Candidate]) -> list[dict]:
    """Labelled candidates only; engine and match id are the engine's own (s6.2)."""
    return [{**LabelRecord(tier='W', pair=pair, match_id=c.match_id, A=c.answer, source=SOURCE, stratum='natural',
                           stage='symbols-hidden', p_incl=1.0).model_dump(), 'engine': c.engine}
            for c in candidates if c.answer]


def detail_records(pair: str, truth: Sequence[Truth], excluded: Sequence[Exclusion],
                   candidates: Sequence[Candidate], older: SymbolMap, newer: SymbolMap,
                   older_exports: Collection[int] = (), newer_exports: Collection[int] = ()) -> list[LabelDetail]:
    """Name-bearing detail lines: one per truth, per excluded RVA (side-wise) and per candidate (labelled or not)."""
    out = [LabelDetail(contract='tier-w-label-detail/1', tier='W', pair=pair, match_id=t.match_id, kind='truth',
                       A='same', rule='name+size', older=_side(t.older, older_exports),
                       newer=_side(t.newer, newer_exports),
                       size_change=(t.newer.size - t.older.size) / t.older.size) for t in truth]
    for e in excluded:
        for s in e.older:
            out.append(LabelDetail(contract='tier-w-label-detail/1', tier='W', pair=pair, kind='truth', A=None,
                                   match_id=match_id(s.rva, None), rule=e.reason,
                                   older=_side(s, older_exports), newer=_empty()))
        for s in e.newer:
            out.append(LabelDetail(contract='tier-w-label-detail/1', tier='W', pair=pair, kind='truth', A=None,
                                   match_id=match_id(None, s.rva), rule=e.reason,
                                   older=_empty(), newer=_side(s, newer_exports)))
    by_old = {s.rva: s for s in older.symbols}
    by_new = {s.rva: s for s in newer.symbols}
    for c in candidates:
        o, n = by_old.get(c.older_rva), by_new.get(c.newer_rva)
        out.append(LabelDetail(
            contract='tier-w-label-detail/1', tier='W', pair=pair, match_id=c.match_id, kind='candidate',
            A=c.answer, rule=c.rule, engine=c.engine,
            older=_side(o, older_exports) if o else DetailSide(rva=c.older_rva),
            newer=_side(n, newer_exports) if n else DetailSide(rva=c.newer_rva),
            size_change=(n.size - o.size) / o.size if o and n and o.size and n.size is not None else None))
    return out
