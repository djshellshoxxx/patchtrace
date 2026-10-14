"""Explained lexicographic ranking (WB1 section 7 'Ordering key'). Nothing here adds, averages or scales.

A lead sorts by `(tier, change class, -independent origins, attention ordinal, table id, native bm25, name,
side, rva, doc id)`: every field is categorical or ordinal, and bm25 is only ever compared between documents
of one table of one segment (the table id precedes it). `sort=change` swaps tier and change class. The same
fields produce the `rank_reasons` text, so the shown order is always explainable.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from patchtrace.models import FunctionMatch
from patchtrace.search.contracts import Origin, SortKey

TIER_TEXT = {0: 'tier 0: exact identity (full name, address, id or hash)',
             1: 'tier 1: every query word is a whole word of the name',
             2: 'tier 2: the query is a name prefix or lies inside the name',
             3: 'tier 3: query words match text (strings, notes, advisories)',
             4: 'tier 4: query words match decompiled code only'}
CHANGE_TEXT = {0: 'change class 0: changed pairing or added/removed string',
               1: 'change class 1: changed pairing without an attention row',
               2: 'change class 2: unchanged or unknown',
               3: 'change class 3: not tied to a function'}
FUNCTION_KINDS = frozenset({'function', 'code', 'asm', 'string', 'capability', 'rule'})
_TOOL_ORIGINS = {'floss': 'floss', 'capa': 'capa', 'diec': 'diec', 'yara': 'yara-x'}


@dataclass(frozen=True, slots=True)
class Candidate:
    """One matched document of one segment."""
    group: str
    digest16: str
    table: str  # fts_name, tri_name, fts_code, fts_text or a lookup name
    doc_id: int
    kind: str
    side: str | None
    subject: str
    display: str
    extra: str
    ref: int
    rva: int | None
    flags: int
    value_sha: str | None
    tier: int
    reason: str  # a contract ReasonCode
    field: str
    detail: str = ''
    bm25: float = 0.0
    snippet: str = ''  # raw FTS5 snippet with STX/ETX highlight markers, '' for names

    @property
    def table_id(self) -> str:
        return f'{self.group}:{self.table}'

    @property
    def origin(self) -> Origin:
        return origin_of(self.group, self.extra)

    def order(self) -> tuple:
        return (self.tier, self.table_id, self.bm25, self.display.casefold(), self.side or '',
                -1 if self.rva is None else self.rva, self.doc_id)


@dataclass(slots=True)
class Lead:
    """Candidates that share one pairing (or one lone document), with the live facts that order them."""
    key: str
    candidates: list[Candidate]
    match: FunctionMatch | None = None
    attention_rank: int | None = None
    attention_of: int = 0
    attention_known: bool = False  # a current ranking exists (a missing row then means "no attention row")
    delta: bool = False  # a string reported added or deleted
    best: Candidate = field(init=False)

    def __post_init__(self) -> None:
        self.candidates.sort(key=Candidate.order)
        self.best = self.candidates[0]

    @property
    def tier(self) -> int:
        return self.best.tier

    @property
    def origins(self) -> tuple[Origin, ...]:
        return tuple(sorted({c.origin for c in self.candidates}))

    @property
    def change_class(self) -> int:
        if self.match is not None:
            if self.match.category == 'unchanged':
                return 2
            return 1 if self.attention_known and self.attention_rank is None else 0
        if self.delta:
            return 0
        return 3 if self.best.kind not in FUNCTION_KINDS else 2


def origin_of(group: str, extra: str = '') -> Origin:
    """The independent origin component of a source group (charter 4: one origin counts once)."""
    head, _, rest = group.partition(':')
    if head in ('fn', 'raw', 'ir'):
        return 'ghidra'
    if head == 'pe':
        return 'pe-parse'
    if head == 'ann':
        return 'analyst'
    if head == 'fnd':
        return 'analyst' if extra.startswith('analyst') else 'model'
    if head == 'tool':
        return _TOOL_ORIGINS.get(rest.partition(':')[0], 'floss')
    if head == 'rule':
        return 'yara-x'
    return 'advisory'


def sort_key(lead: Lead, sort: SortKey) -> tuple:
    best = lead.best
    rank = math.inf if lead.attention_rank is None else lead.attention_rank
    tail = (-len(lead.origins), rank, best.table_id, best.bm25, best.display.casefold(), best.side or '',
            -1 if best.rva is None else best.rva, best.doc_id, lead.key)
    if sort == 'change':
        return (lead.change_class, lead.tier, *tail)
    if sort == 'name':
        return (best.display.casefold(), lead.tier, lead.change_class, *tail)
    if sort == 'address':
        return (math.inf if best.rva is None else best.rva, lead.tier, lead.change_class, *tail)
    return (lead.tier, lead.change_class, *tail)


def order(leads: list[Lead], sort: SortKey) -> list[Lead]:
    return sorted(leads, key=lambda lead: sort_key(lead, sort))


def rank_reasons(lead: Lead, attention_note: str) -> tuple[str, ...]:
    reasons = [TIER_TEXT[lead.tier], CHANGE_TEXT[lead.change_class]]
    if lead.match is not None:
        reasons.append(f'pairing is {lead.match.category}')
    origins = lead.origins
    reasons.append(f'{len(origins)} independent source{"s" if len(origins) != 1 else ""}: {", ".join(origins)}')
    if lead.attention_rank is not None:
        reasons.append(f'attention/1 rank {lead.attention_rank} of {lead.attention_of} (uncalibrated ordering)')
    elif lead.match is not None and lead.match.category != 'unchanged':
        reasons.append(attention_note or 'attention/1 rank unavailable: run Rank changes')
    return tuple(r[:120] for r in reasons)
