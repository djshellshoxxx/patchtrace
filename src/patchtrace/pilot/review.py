"""Analyst review events of leads: pin, unpin, dismiss, restore and note (PIL-integration-plan.md s6, s7 `ReviewEvent`).

An event is a row of its own, `pilot-review:<uuid>` of kind `patch-intent`, so a result can be recomputed, replaced or
evicted without touching what the analyst said, and an older PatchTrace that reads no `pilot-review` row loses nothing.
Append-only by construction: this module has no function that changes or deletes an event, an id is never reused, and the
retention of `store.py` cannot reach these rows. A lead is addressed by its candidate key (stable across recomputation)
and its context (a CVE, or `None` for the code-only list). Events never change a lead's class; a note is the analyst's
statement and is shown as such, never as PatchTrace's finding.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Guard
from . import keys
from .contracts import Lead, ReviewEvent
from .limits import PilotError
from .store import require_project

KIND = keys.KIND
GUARD_RUN = 'pilot-review'
ReviewKey = tuple[str, str | None]  # (candidate key, CVE or None)


@dataclass(frozen=True, slots=True)
class LeadReview:
    """What the analyst did with one lead. `statements` are the events that carry text, oldest first."""
    pinned: bool = False
    dismissed: bool = False
    statements: tuple[ReviewEvent, ...] = ()


@dataclass(frozen=True, slots=True)
class Events:
    """Every readable event, oldest first, and the ids of `pilot-review` rows this version cannot read (a newer contract
    or damage): they are kept in the project and ignored here."""
    events: tuple[ReviewEvent, ...]
    skipped: tuple[str, ...]


def _new_id() -> str:
    return str(uuid.uuid4())


def _when(event: ReviewEvent) -> datetime:
    return datetime.fromisoformat(event.created_utc).astimezone(UTC)


def read(enrichment: EnrichmentStore) -> Events:
    skipped: list[str] = []
    found = []
    for entry in enrichment.entries(KIND, on_corrupt=skipped.append):
        if not entry.id.startswith(keys.REVIEW_PREFIX):
            continue
        try:
            keys.review_entry_id(entry.id.removeprefix(keys.REVIEW_PREFIX))  # a canonical id, or it is not ours
            found.append((ReviewEvent.model_validate_json(json.dumps(entry.body)), entry.id))
        except (ValidationError, ValueError):
            skipped.append(entry.id)
    found.sort(key=lambda item: (_when(item[0]), item[1]))
    return Events(tuple(event for event, _id in found),
                  tuple(sorted(i for i in set(skipped) if i.startswith(keys.REVIEW_PREFIX))))


def _stamp(previous: datetime | None, clock: Callable[[], datetime] | None) -> str:
    """The event time, later than every earlier event: clocks tie (Windows ticks 15.6 ms) and may run behind, and the
    order of a pin and an unpin must never depend on that."""
    now = (clock() if clock else datetime.now(UTC)).astimezone(UTC)
    if previous is not None and now <= previous:
        now = previous + timedelta(microseconds=1)
    return now.isoformat(timespec='microseconds')


def append(enrichment: EnrichmentStore, *, project_id: str, revision: int, candidate_key: str, cve: str | None,
           action: str, text: str = '', clock: Callable[[], datetime] | None = None) -> ReviewEvent:
    """Store one new event (owner thread) and return it. Raises `PT-PILOT-INPUT` for an event the contract refuses,
    `PT-PILOT-MISMATCH` for another project and `PT-PILOT-INTEGRITY` if the id exists (no row is ever rewritten)."""
    require_project(enrichment, project_id)
    earlier = read(enrichment).events
    try:
        event = ReviewEvent(candidate_key=candidate_key, cve=cve, action=action, text=text,
                            created_utc=_stamp(_when(earlier[-1]) if earlier else None, clock))
    except ValidationError:
        raise PilotError('PT-PILOT-INPUT', 'The review event is not valid', reason='review-invalid') from None
    row_id = keys.review_entry_id(_new_id())
    if any(entry.id == row_id for entry in enrichment.entries(KIND)):
        raise PilotError('PT-PILOT-INTEGRITY', 'A review event with this id exists already', reason='review-id-reused')
    guard = Guard(project_id, GUARD_RUN, candidate_key, keys.content_sha256(event))
    try:
        enrichment.publish(KIND, guard, guard, revision, 'complete', event.model_dump(mode='json'), row_id)
    except EnrichmentError:
        raise PilotError('PT-PILOT-STORAGE', 'The review event could not be stored', reason='review-publish') from None
    return event


def fold(events: Iterable[ReviewEvent]) -> dict[ReviewKey, LeadReview]:
    """The state per lead and context from events in the order `read` returns them (oldest first)."""
    state: dict[ReviewKey, LeadReview] = {}
    for event in events:
        key = (event.candidate_key, event.cve)
        now = state.get(key, LeadReview())
        state[key] = LeadReview(
            pinned={'pin': True, 'unpin': False}.get(event.action, now.pinned),
            dismissed={'dismiss': True, 'restore': False}.get(event.action, now.dismissed),
            statements=(*now.statements, event) if event.text.strip() else now.statements)
    return state


def pinned_first(leads: Sequence[Lead], reviews: Mapping[ReviewKey, LeadReview]) -> list[Lead]:
    """The Pinned band: pinned leads first, each group in its given order. Class and rank are not touched."""
    pinned = [reviews.get((lead.candidate_key, lead.cve), LeadReview()).pinned for lead in leads]
    return [lead for lead, flag in zip(leads, pinned, strict=True) if flag] + [
        lead for lead, flag in zip(leads, pinned, strict=True) if not flag]
