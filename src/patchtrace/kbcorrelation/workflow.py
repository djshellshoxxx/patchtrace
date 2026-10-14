"""Investigation workflow reducer (KB-integration-plan 7.5; slice K2). Pure: no I/O, clock, Qt or sqlite3.

``reduce(snapshot, event)`` returns the next immutable :class:`InvestigationRevision` (revision + 1, parent = the
snapshot) or a :class:`KbcIssue`; it never mutates and never raises for a bad event. Side effects (search, fetch,
create a project, run an engine) run outside the reducer and report back as events. An event carries the
``generation`` of the revision it was launched from: if the investigation moved on (or its window closed and the
caller bumped the generation) the event is dropped with ``PT-KBC-STALE``.

Hard rules kept here, not in callers:

* ``BYTES_VERIFIED`` needs both final files hashed and parsed; ``PROJECT_CREATED`` needs both sides verified;
* a failure after ``PROJECT_CREATED`` is ``CONTEXT_PENDING`` (the project is kept);
* cancellation restores the previous committed snapshot (a new revision with the old content, so history is append
  only); a restart never fetches or runs an engine, so no event exists for that.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .contracts import InvestigationRevision
from .errors import KbcIssue

SEARCHED = ('METADATA_READY', 'METADATA_PARTIAL', 'NOT_OBSERVED', 'SCOPE_REQUIRED')
PAIR_STATES = ('PAIR_PROPOSED', 'NEEDS_OLDER', 'NEEDS_NEWER', 'LINEAGE_BLOCKED', 'NEEDS_PAIR_SELECTION')
PRODUCT_STATES = ('PRODUCT_SELECTED', 'NEEDS_PRODUCT')
COMPONENT_STATES = ('COMPONENTS_READY', 'NEEDS_FILENAME')


@dataclass(frozen=True)
class Event:
    """One reported fact. Unused fields stay at their defaults; ``outcome`` names a substate where the event has
    several. ``parsed`` is True only when the side effect hashed and parsed both final files."""
    kind: str
    generation: int
    outcome: str | None = None
    scope_ids: tuple[str, ...] = ()
    coverage_ids: tuple[str, ...] = ()
    scope_id: str | None = None
    pair_id: str | None = None
    plan_sha: str | None = None
    parsed: bool = False
    both_sides: bool = False
    warnings: tuple[str, ...] = ()
    restore: InvestigationRevision | None = field(default=None, compare=False)


def _issue(code: str, message: str) -> KbcIssue:
    return KbcIssue(code=code, message=message, recoverable=True)


def _next(snapshot: InvestigationRevision, **changes: Any) -> InvestigationRevision | KbcIssue:
    body = {**snapshot.model_dump(), 'revision': snapshot.revision + 1, 'parent': snapshot.revision, **changes}
    try:
        return InvestigationRevision.model_validate(body)
    except ValidationError:
        return _issue('PT-KBC-STATE', 'the event does not produce a valid investigation revision')


def _need(condition: bool, text: str) -> KbcIssue | None:
    return None if condition else _issue('PT-KBC-STATE', text)


# --- handlers: (snapshot, event) -> changes dict | KbcIssue --------------------------------------------------

def _lead_parsed(s, e):
    return {'state': 'LEAD_PARSED'}


def _search_done(s, e):
    if e.outcome not in SEARCHED:
        return _issue('PT-KBC-INPUT', 'search_done needs a searched outcome')
    return {'state': e.outcome, 'scope_ids': e.scope_ids, 'coverage_ids': e.coverage_ids,
            'selected_scope_id': None, 'selected_pair_id': None, 'plan_sha': None, 'warnings': e.warnings}


def _needs_product(s, e):
    return {'state': 'NEEDS_PRODUCT'}


def _product_selected(s, e):
    if e.scope_id is None or e.scope_id not in s.scope_ids:
        return _issue('PT-KBC-STATE', 'the selected product scope is not one of the investigation scopes')
    return {'state': 'PRODUCT_SELECTED', 'selected_scope_id': e.scope_id, 'selected_pair_id': None, 'plan_sha': None}


def _components(s, e):
    return {'state': 'COMPONENTS_READY', 'selected_pair_id': None}


def _needs_filename(s, e):
    return {'state': 'NEEDS_FILENAME', 'selected_pair_id': None}


def _pair_proposed(s, e):
    if e.outcome not in PAIR_STATES:
        return _issue('PT-KBC-INPUT', 'pair_proposed needs a pair outcome')
    if e.outcome == 'PAIR_PROPOSED':
        return {'state': 'PAIR_PROPOSED', 'selected_pair_id': e.pair_id} if e.pair_id else \
            _issue('PT-KBC-STATE', 'a proposed pair needs a pair id')
    return {'state': e.outcome, 'selected_pair_id': None}


def _pair_approved(s, e):
    return _need(s.selected_pair_id is not None and (e.pair_id in (None, s.selected_pair_id)),
                 'the approved pair is not the proposed pair') or {'state': 'PAIR_APPROVED'}


def _plan_ready(s, e):
    return {'state': 'PLAN_READY', 'plan_sha': e.plan_sha} if e.plan_sha else \
        _issue('PT-KBC-STATE', 'a plan needs its plan_sha')


def _acquire_started(s, e):
    return _need(e.plan_sha == s.plan_sha, 'the consented plan_sha differs from the plan') or {'state': 'ACQUIRING'}


def _bytes_verified(s, e):
    return _need(e.parsed and e.both_sides, 'both final files must be hashed and parsed before BYTES_VERIFIED') \
        or {'state': 'BYTES_VERIFIED'}


def _project_created(s, e):
    return _need(e.both_sides, 'a project is never created from one verified side') or {'state': 'PROJECT_CREATED'}


def _simple(state: str) -> Callable:
    return lambda s, e: {'state': state}


def _cancel(s, e):
    previous = e.restore
    if previous is None or previous.investigation_id != s.investigation_id or previous.revision >= s.revision:
        return _issue('PT-KBC-STATE', 'cancel needs an earlier committed revision of this investigation')
    body = previous.model_dump(include={'lead', 'state', 'scope_ids', 'coverage_ids', 'selected_scope_id',
                                        'selected_pair_id', 'plan_sha', 'warnings'})
    return {**body, 'warnings': (*previous.warnings, 'cancelled; the previous committed state was restored')}


Handler = Callable[[InvestigationRevision, Event], Any]
# event kind -> (allowed states, handler)
RULES: dict[str, tuple[tuple[str, ...], Handler]] = {
    'lead_parsed': (('NEW',), _lead_parsed),
    'search_done': (('LEAD_PARSED', *SEARCHED, *PRODUCT_STATES), _search_done),
    'needs_product': (('METADATA_READY', 'METADATA_PARTIAL'), _needs_product),
    'product_selected': (('METADATA_READY', 'METADATA_PARTIAL', *PRODUCT_STATES, *COMPONENT_STATES, *PAIR_STATES,
                          'PAIR_APPROVED'), _product_selected),
    'components_ready': (('PRODUCT_SELECTED', *COMPONENT_STATES), _components),
    'needs_filename': (('PRODUCT_SELECTED', *COMPONENT_STATES), _needs_filename),
    # a manual pair (E0) skips the product steps, with or without a KB search before it
    'pair_proposed': (('LEAD_PARSED', *SEARCHED, 'PRODUCT_SELECTED', *COMPONENT_STATES, *PAIR_STATES),
                      _pair_proposed),
    'pair_approved': (('PAIR_PROPOSED',), _pair_approved),
    'plan_ready': (('PAIR_APPROVED',), _plan_ready),
    'acquire_started': (('PLAN_READY',), _acquire_started),
    'bytes_verified': (('ACQUIRING', 'PAIR_APPROVED'), _bytes_verified),  # PAIR_APPROVED: local files, no plan
    'project_created': (('BYTES_VERIFIED',), _project_created),
    'context_pending': (('PROJECT_CREATED', 'CONTEXT_ATTACHED'), _simple('CONTEXT_PENDING')),
    'context_attached': (('PROJECT_CREATED', 'CONTEXT_PENDING'), _simple('CONTEXT_ATTACHED')),
    'comparison_pending': (('PROJECT_CREATED', 'CONTEXT_PENDING', 'CONTEXT_ATTACHED'), _simple('COMPARISON_PENDING')),
    'analyzed': (('COMPARISON_PENDING',), _simple('ANALYZED')),
    'leads_ready': (('ANALYZED',), _simple('LEADS_READY')),
    'cancel': (('PLAN_READY', 'ACQUIRING', 'BYTES_VERIFIED', 'COMPARISON_PENDING'), _cancel),
}


def reduce(snapshot: InvestigationRevision, event: Event) -> InvestigationRevision | KbcIssue:
    rule = RULES.get(event.kind)
    if rule is None:
        return _issue('PT-KBC-INPUT', 'unknown workflow event')
    if event.generation != snapshot.revision:
        return _issue('PT-KBC-STALE', 'the event belongs to an earlier revision and was dropped')
    allowed, handler = rule
    if snapshot.state not in allowed:
        return _issue('PT-KBC-STATE', f'event {event.kind} is not allowed in state {snapshot.state}')
    changes = handler(snapshot, event)
    if isinstance(changes, KbcIssue):
        return changes
    return _next(snapshot, **changes)
