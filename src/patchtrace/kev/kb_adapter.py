"""KEV context composed onto a KB worklist, through Protocols only (KEV-integration-plan sections 5 and 9). Pure.

The KB track (``EdgeLike``) and the engine ranking (``RankingLike``) are seen as structural types, so this module
imports neither. KEV decides only which CVE section is read first (opt-in ``kev-first``, a stable partition of the
input order); the candidate functions under every CVE keep the ranking's own order and the ranking is never modified.
"""
from __future__ import annotations

import datetime
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from . import teach
from .contracts import KevCatalog, KevLookup
from .join import KevIndex, freshness, lookup_one
from .view_model import KevCell, age_phrase, cell_for, detail_text, order_indices

Order = Literal['input', 'kev-first']

SUMMARY = ('{n} of {m} CVEs in this KB are listed in CISA KEV (catalog {version}, {age}). '
           f'Not listed {teach.NOT_EXPLOITED_NEGATION}.')
SUMMARY_NO_CATALOG = 'No KEV catalog is loaded. Nothing can be said about these CVEs yet.'
BEFORE = 'Added to KEV {n} {unit} before the update was released ({kb}, {date}).'
SAME_DAY = 'Added to KEV on the day the update was released ({kb}, {date}).'
AFTER = 'Added to KEV {n} {unit} after the update was released ({kb}, {date}).'
ORIENTATION_UNVERIFIED = 'Fix release date not established for this orientation.'
RELEASE_UNKNOWN = 'Update release date unknown.'
NO_DETECTOR = ('PatchTrace has no {cwe} detector in this version, so an empty candidate list here is unknown, '
               'not negative.')


class EdgeLike(Protocol):
    """One KB -> CVE edge as the KB track exposes it; ``released_at`` is the KB's own release date (YYYY-MM-DD)."""

    kb: str
    cve: str
    cwes: Sequence[str]
    released_at: str | None
    orientation_verified: bool


class RankedLike(Protocol):
    """One engine row: ``detectors`` are the detector ids with a supporting signal on the function."""

    match_id: str
    rank: int
    detectors: frozenset[str]


class RankingLike(Protocol):
    entries: Sequence[RankedLike]


@dataclass(frozen=True)
class CveSection:
    """One CVE of the worklist: the KEV cell, the time relation, and the engine candidates (never reordered)."""

    cve_id: str
    kb: str
    cell: KevCell
    lookup: KevLookup
    timeline: str | None
    candidates: tuple[str, ...]
    abstentions: tuple[str, ...]


def _date(text: str | None) -> datetime.date | None:
    if not text or not text.isascii() or len(text) != 10:
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


def timeline_phrase(lookup: KevLookup, edge: EdgeLike) -> str | None:
    """The KEV date relative to the KB release, only for a listed CVE and only with a verified orientation."""
    if lookup.entry is None:
        return None
    if not edge.orientation_verified:
        return ORIENTATION_UNVERIFIED
    released, added = _date(edge.released_at), _date(lookup.entry.date_added)
    if released is None or added is None:
        return RELEASE_UNKNOWN
    delta = (released - added).days
    where = {'kb': edge.kb, 'date': released.isoformat()}
    if delta == 0:
        return SAME_DAY.format(**where)
    template = BEFORE if delta > 0 else AFTER
    return template.format(n=abs(delta), unit='day' if abs(delta) == 1 else 'days', **where)


def _candidates(ranking: RankingLike, wanted: frozenset[str]) -> tuple[str, ...]:
    rows = sorted((row for row in ranking.entries if row.detectors & wanted), key=lambda row: row.rank)
    return tuple(row.match_id for row in rows)


def _section(edge: EdgeLike, result: KevLookup, version: str, ranking: RankingLike,
             cwe_detectors: Mapping[str, tuple[str, ...]]) -> CveSection:
    cwes = sorted(set(edge.cwes))
    wanted = frozenset(d for cwe in cwes for d in cwe_detectors.get(cwe, ()))
    return CveSection(cve_id=result.cve_id, kb=edge.kb, cell=cell_for(result, version), lookup=result,
                      timeline=timeline_phrase(result, edge), candidates=_candidates(ranking, wanted),
                      abstentions=tuple(NO_DETECTOR.format(cwe=cwe) for cwe in cwes if cwe not in cwe_detectors))


def worklist(edges: Iterable[EdgeLike], catalog: KevCatalog | None, ranking: RankingLike,
             cwe_detectors: Mapping[str, tuple[str, ...]], now: datetime.datetime,
             order: Order = 'input') -> tuple[CveSection, ...]:
    """One section per distinct CVE (first edge wins), in input order or listed-first. ``ranking`` is read only."""
    index, version = KevIndex(catalog), catalog.meta.catalog_version if catalog else ''
    sections: dict[str, CveSection] = {}
    for edge in edges:
        result = lookup_one(index, edge.cve, now)
        if result.cve_id not in sections:
            sections[result.cve_id] = _section(edge, result, version, ranking, cwe_detectors)
    ordered = list(sections.values())
    positions = order_indices([s.cell for s in ordered], range(len(ordered)), order)
    return tuple(ordered[i] for i in positions)


def summary_line(sections: Sequence[CveSection], catalog: KevCatalog | None, now: datetime.datetime) -> str:
    """"n of m CVEs in this KB are listed"; a count of CVEs, never a percentage or a score."""
    if catalog is None:
        return SUMMARY_NO_CATALOG
    _, days = freshness(catalog.meta, now)
    listed = sum(s.lookup.status == 'listed' for s in sections)
    return SUMMARY.format(n=listed, m=len(sections), version=catalog.meta.catalog_version, age=age_phrase(days))


def section_text(section: CveSection, catalog: KevCatalog | None, now: datetime.datetime) -> str:
    """Plain-text section: the KEV detail, the time relation, the shared candidates and any explicit abstention."""
    lines = [detail_text(section.lookup, catalog, now)]
    if section.timeline:
        lines.append(section.timeline)
    if section.candidates:
        lines.append('Candidate functions (engine order): ' + ', '.join(section.candidates))
    lines.extend(section.abstentions)
    return '\n'.join(lines)
