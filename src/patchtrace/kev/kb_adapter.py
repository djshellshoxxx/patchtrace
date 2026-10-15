"""KEV composed with the KB view's data: the CVE reading order, a timeline phrase, a summary line and an explicit
abstention (KEV-integration-plan sections 4, 5 and 8). Pure: no Qt, network, sqlite3, clock or ranking code.

The KB side arrives through two small Protocols, so nothing here imports the KB or the ranking: ``EdgeLike`` is a KB to
CVE edge and ``RankingLike`` is the engine's own attention order of match ids. KEV decides which CVE is read first and
nothing else. The candidate functions of every CVE keep the engine's order, no member of either Protocol carries a
score, and a KEV state is never an input to the order of functions. All text read from the KB side is bounded by the
same ASCII patterns the KB contracts use before any sentence contains it.
"""
from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Protocol

from . import limits
from .contracts import KevCatalogMeta, KevError, KevLookup, utc
from .ports import KevLookupPort
from .view_model import SORT_ITEMS, KevCell, banner_text, order_indices

TIMELINE_UNVERIFIED = 'Fix release date not established for this orientation.'
TIMELINE_UNKNOWN = 'Update release date unknown.'
_KB = re.compile(r'KB[0-9]{4,10}')
_CWE = re.compile(r'CWE-[0-9]{1,6}')
_DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
_STAMP = re.compile(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]{1,9})?Z')


class EdgeLike(Protocol):
    """A KB to CVE edge of the KB view; ``kbcorrelation.contracts.KbCveEdge`` has both members."""

    @property
    def kb(self) -> str:
        """The update the edge belongs to, ``KB`` and digits."""

    @property
    def cve(self) -> str:
        """The CVE the update lists, as the KB view holds it."""


class RankedLike(Protocol):
    """One function of the engine's attention order. A position is all that is visible here, never a score."""

    @property
    def match_id(self) -> str:
        """The match the function belongs to."""

    @property
    def rank(self) -> int:
        """Its place in the engine's own order; 1 is read first."""


class RankingLike(Protocol):
    """The engine's attention order (``enrichment.contracts.RankingResult`` has this shape)."""

    @property
    def entries(self) -> Iterable[RankedLike]:
        """Every ranked function, in any order."""


@dataclass(frozen=True, slots=True)
class WorklistSection:
    """One CVE of the work list. ``candidates`` are match ids in the engine's own order. ``note`` is the neutral
    sentence for a CVE the catalog does not list, ``timeline`` relates CISA's date to the update's, and ``abstentions``
    say where an empty candidate list means unknown rather than negative."""
    cve: str
    cell: KevCell
    lookup: KevLookup
    kbs: tuple[str, ...]
    timeline: tuple[str, ...]
    note: str | None
    candidates: tuple[str, ...]
    abstentions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Worklist:
    """The sections in reading order, labelled so that the order is never read as a score."""
    order: str
    order_label: str
    sections: tuple[WorklistSection, ...]
    meta: KevCatalogMeta | None
    summary: str | None
    banner: str | None


# --- fixed sentences ----------------------------------------------------------------------------------------------

def _is_kb_id(value: object) -> bool:
    return type(value) is str and _KB.fullmatch(value) is not None


def _release_day(value: object) -> date | None:
    """The calendar day of a release date ``YYYY-MM-DD`` or of a UTC timestamp; None for anything else."""
    if type(value) is not str:
        return None
    stamp = _STAMP.fullmatch(value)
    try:
        if stamp:
            return utc(stamp.group(1) + 'Z').date()
        return date.fromisoformat(value) if _DAY.fullmatch(value) else None
    except ValueError:
        return None


def _days(count: int) -> str:
    return '1 day' if count == 1 else f'{count} days'


def timeline_phrase(row: KevLookup, kb: str, released: object, *, orientation_verified: bool) -> str | None:
    """How the day CISA added a listed CVE relates to the day the update was released. The date basis is always named
    ("KB5000001, 2099-02-11"). Without a verified orientation the update is not known to be the fix; without a usable
    release date there is nothing to relate. None for a CVE the catalog does not list."""
    if not _is_kb_id(kb):
        raise ValueError('kb must be a KB id: KB and four to ten ASCII digits')
    if row.status != 'listed':
        return None
    if not orientation_verified:
        return TIMELINE_UNVERIFIED
    day = _release_day(released)
    if day is None:
        return TIMELINE_UNKNOWN
    gap, basis = (day - date.fromisoformat(row.entry.date_added)).days, f'({kb}, {day.isoformat()})'
    if gap > 0:
        return f'Added to KEV {_days(gap)} before the update was released {basis}.'
    if gap == 0:
        return f'Added to KEV on the day the update was released {basis}.'
    return f'Added to KEV {_days(-gap)} after the update was released {basis}.'


def not_listed_note(meta: KevCatalogMeta) -> str:
    return f'Not in the KEV catalog {meta.catalog_version}. This does not mean the CVE is unexploited.'


def no_detector_sentence(cwe: str) -> str:
    if _CWE.fullmatch(cwe) is None:
        raise ValueError('cwe must be CWE and one to six ASCII digits')
    return (f'PatchTrace has no {cwe} detector in this version, so an empty candidate list here is unknown, '
            'not negative.')


# --- composition --------------------------------------------------------------------------------------------------

def _engine_positions(ranking: RankingLike) -> dict[str, int]:
    positions: dict[str, int] = {}
    for item in sorted(ranking.entries, key=lambda entry: entry.rank):
        positions.setdefault(item.match_id, len(positions))
    return positions


def _in_engine_order(ids: Iterable[str], positions: Mapping[str, int]) -> tuple[str, ...]:
    """The engine's order; an id the engine did not rank keeps the order it was given, after the ranked ones."""
    return tuple(sorted(dict.fromkeys(ids), key=lambda match: positions.get(match, len(positions))))


def _abstentions(stated: Iterable[object], detector_cwes: Collection[str]) -> tuple[str, ...]:
    gaps = {cwe for cwe in stated if type(cwe) is str and _CWE.fullmatch(cwe) and cwe not in detector_cwes}
    return tuple(no_detector_sentence(cwe) for cwe in sorted(gaps, key=lambda cwe: int(cwe[4:])))


def _timeline(row: KevLookup, kbs: Iterable[str], release_dates: Mapping[str, object],
              verified: bool) -> tuple[str, ...]:
    phrases = (timeline_phrase(row, kb, release_dates.get(kb), orientation_verified=verified) for kb in kbs)
    return tuple(dict.fromkeys(phrase for phrase in phrases if phrase))


def compose_worklist(edges: Iterable[EdgeLike], kev: KevLookupPort, ranking: RankingLike, *,
                     candidates: Mapping[str, Iterable[str]], cwes: Mapping[str, Iterable[object]],
                     detector_cwes: Collection[str], release_dates: Mapping[str, object],
                     orientation_verified: bool, order: str = 'input') -> Worklist:
    """One section per distinct CVE of ``edges`` (first-seen order, or ``kev-first``: listed CVEs first, each group in
    the order seen; a reading order, not a score). The KB view passes what it already knows: ``candidates`` maps a CVE
    to the match ids it attributes to it, ``cwes`` to the CWEs its advisory states, ``detector_cwes`` is the set of
    CWEs the engine has a detector for, and ``release_dates`` maps a KB to its release date or UTC timestamp. Raises
    ``ValueError`` for an unknown ``order`` and ``KevError`` PT-KEV-LIMIT beyond 5,000 distinct CVEs."""
    kbs_of: dict[str, set[str]] = {}
    for edge in edges:
        found = kbs_of.setdefault(edge.cve, set())
        if _is_kb_id(edge.kb):
            found.add(edge.kb)
        if len(kbs_of) > limits.MAX_LOOKUP_CVES:
            raise KevError('PT-KEV-LIMIT', f'more than {limits.MAX_LOOKUP_CVES} CVE IDs at once')
    positions, sections = _engine_positions(ranking), []
    for cve, kb_ids in kbs_of.items():
        cell, row, kbs = kev.cell(cve), kev.lookup(cve), tuple(sorted(kb_ids))
        sections.append(WorklistSection(
            cve=cell.cve, cell=cell, lookup=row, kbs=kbs,
            timeline=_timeline(row, kbs, release_dates, orientation_verified),
            note=not_listed_note(kev.meta) if row.status == 'not-listed' else None,
            candidates=_in_engine_order(candidates.get(cve, ()), positions),
            abstentions=_abstentions(cwes.get(cve, ()), detector_cwes)))
    shown = order_indices([section.cell for section in sections], order)
    answered = next((section.lookup for section in sections if section.lookup.freshness != 'unknown'), None)
    return Worklist(order=order, order_label=dict(SORT_ITEMS)[order],
                    sections=tuple(sections[index] for index in shown), meta=kev.meta,
                    summary=kev.summary_line(kbs_of),
                    banner=None if answered is None else banner_text(answered.freshness, answered.age_days))
