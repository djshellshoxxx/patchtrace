"""Bridge from PIL advisory anchors to search (WB1 S10): `Anchor` -> `QueryPlan`, and per-anchor coverage.

An anchor is an untrusted, labelled search hint (`intelligence.anchors`); here it only becomes query INPUT. Each anchor
is run changed-code first, then over everything indexed. A miss is reported as `none` only when every group was
indexed; otherwise it is `unknown` (an unbuilt index is not a negative vote), and a hit says nothing about causation.
Nothing is scored or averaged across anchors.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.search.contracts import QueryPlan, SearchRequest, SearchResult
from patchtrace.search.errors import SearchError
from patchtrace.search.query import parse_query

AnchorStatus = Literal['changed', 'indexed-only', 'none', 'unknown', 'not-searchable']
# A PDB name is a build fact and a quoted string is a string; module, feature, component and API hints may live in
# names, code, imports or text, so they are not restricted.
KIND_FILTER: dict[str, str] = {'pdb': 'kind:build', 'string': 'kind:string'}
NO_PLAN = 'The anchor text cannot be turned into a search query.'
UNKNOWN_ABSENCE = 'Some search groups are not indexed, so the absence is unknown.'


@dataclass(frozen=True, slots=True)
class AnchorPlan:
    anchor_id: str
    kind: str
    label: str
    plan: QueryPlan | None  # None: `reason` says why (an anchor is never silently dropped)
    reason: str = ''


@dataclass(frozen=True, slots=True)
class AnchorCoverage:
    anchor_id: str
    kind: str
    label: str
    status: AnchorStatus
    hits: int = 0
    unindexed: tuple[str, ...] = ()  # groups that were not indexed when the answer was computed
    reason: str = ''


def _phrase(value: str) -> str:
    return '"' + ' '.join(value.replace('"', ' ').split()) + '"'


def query_text(anchor: Anchor, *, changed: bool) -> str:
    """Typed query text for one anchor; always a quoted phrase, so no anchor character acts as query syntax."""
    parts = [KIND_FILTER.get(anchor.kind, ''), 'scope:changed' if changed else '', _phrase(anchor.value)]
    return ' '.join(part for part in parts if part)


def plan_for(anchor: Anchor, *, changed: bool = True) -> AnchorPlan:
    try:
        plan = parse_query(query_text(anchor, changed=changed), mode='exact')
    except SearchError as error:
        return AnchorPlan(anchor.anchor_id, anchor.kind, anchor.label, None, error.message)
    return AnchorPlan(anchor.anchor_id, anchor.kind, anchor.label, plan)


def plans_for(anchors: AnchorSet | Iterable[Anchor]) -> tuple[AnchorPlan, ...]:
    """One plan per anchor, in the given order (an `AnchorSet` is already deterministic)."""
    return tuple(plan_for(a) for a in (anchors.anchors if isinstance(anchors, AnchorSet) else anchors))


def _hits(result: SearchResult) -> int:
    return result.total if result.total is not None else len(result.hits)


def _unindexed(result: SearchResult) -> tuple[str, ...]:
    return tuple(sorted(e.group for e in result.coverage if e.status not in ('indexed', 'not-applicable')))


def _run(search: Callable[[SearchRequest], SearchResult], plan: QueryPlan) -> SearchResult:
    return search(SearchRequest(plan=plan, limit=1, expand=False))


def anchor_coverage(item: AnchorPlan, search: Callable[[SearchRequest], SearchResult]) -> AnchorCoverage:
    def result(status: AnchorStatus, hits: int = 0, unindexed: tuple[str, ...] = (), reason: str = ''):
        return AnchorCoverage(item.anchor_id, item.kind, item.label, status, hits, unindexed, reason)

    if item.plan is None:
        return result('not-searchable', reason=item.reason or NO_PLAN)
    changed = _run(search, item.plan)
    if _hits(changed):
        return result('changed', _hits(changed), _unindexed(changed))
    everything = _run(search, item.plan.model_copy(update={'scope': 'indexed'}))
    missing = tuple(sorted({*_unindexed(changed), *_unindexed(everything)}))
    if _hits(everything):
        return result('indexed-only', _hits(everything), missing)
    if missing or everything.status not in ('ok', 'no-results'):
        return result('unknown', 0, missing, UNKNOWN_ABSENCE if missing else everything.status)
    return result('none')


def coverage_for(plans: Iterable[AnchorPlan], search: Callable[[SearchRequest], SearchResult]
                 ) -> tuple[AnchorCoverage, ...]:
    return tuple(anchor_coverage(item, search) for item in plans)
