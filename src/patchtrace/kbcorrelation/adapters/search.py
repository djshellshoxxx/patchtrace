"""WB1 search results as correlator corroboration (WB1-integration-plan 4; K8).

A hit is a lead, not a verdict: it never becomes a signal, a ``supports`` chip or a number. A search that did not run
to completion yields no leads and says why, so an empty list is not read as "nothing found".
"""
from __future__ import annotations

from dataclasses import dataclass

from ...search.contracts import SearchResult
from ..leads import plain_text

_COMPLETE = frozenset({'ok', 'no-results'})


@dataclass(frozen=True)
class SearchLead:
    kind: str
    side: str | None
    function_id: str | None
    title: str
    origins: tuple[str, ...]         # independent origins that carry the document (WB1 ``seen_by``)
    components: int                  # independent-origin count: shown as a count, never summed
    digest16: str
    source_ref: str | None           # provenance pointer from the locator


@dataclass(frozen=True)
class SearchLeads:
    leads: tuple[SearchLead, ...]
    complete: bool                   # False: the absence of a lead is unknown, not negative
    note: str
    index_key: str | None


def search_leads(result: SearchResult | None) -> SearchLeads:
    if result is None:
        return SearchLeads((), False, 'no search was run', None)
    if result.status not in _COMPLETE:
        return SearchLeads((), False, f'search incomplete ({result.status}); absence of a hit is unknown',
                           result.index_key)
    seen: dict[str, SearchLead] = {}
    for hit in result.hits:
        for ev in hit.evidence:
            if ev.digest16 not in seen:     # one document reached through several hits counts once
                seen[ev.digest16] = SearchLead(
                    ev.kind, ev.side, ev.locator.function_id, plain_text(ev.title, 200), tuple(sorted(ev.seen_by)),
                    min(hit.components, len(ev.seen_by)), ev.digest16, ev.locator.source_ref)
    leads = tuple(sorted(seen.values(), key=lambda s: (s.kind, s.side or '', s.title, s.digest16)))
    return SearchLeads(leads, True, '' if leads else 'no hits in the indexed scope', result.index_key)


def by_function(found: SearchLeads) -> dict[str, tuple[SearchLead, ...]]:
    grouped: dict[str, list[SearchLead]] = {}
    for lead in found.leads:
        if lead.function_id is not None:
            grouped.setdefault(lead.function_id, []).append(lead)
    return {key: tuple(value) for key, value in sorted(grouped.items())}
