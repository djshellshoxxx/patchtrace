"""Saved searches and recent queries (WB1 section 7 'Saved searches', slice S7, pure part).

Both are untrusted text. A saved search keeps the analyst's query text and the plan it parsed to, but the plan is
only a record: running one re-parses `plan.text` with `query.parse_query`, so a hand-edited or newer row can never
smuggle a field the current grammar would refuse, and nothing stored is ever executed or sent to SQL. Results are
never stored.

`search-saved/1` rows are append-only events, `create` and `delete` (a tombstone naming the created row); nothing is
rewritten or deleted, retention never touches the kind, and unknown fields or contracts of a newer writer make a row
unreadable for this reader, which counts it in `SavedList.skipped` rather than hiding it. Recent queries are a small
per-user list (QSettings in the GUI) kept as JSON text: bounded, deduplicated, newest first, and read leniently
(garbage or a newer contract reads as empty and is never raised).

Thread ownership of `EnrichmentSavedStore` is that of the enrichment store: the thread that owns the project.
"""
from __future__ import annotations

import json
import re
import unicodedata
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.identity import domain_id
from patchtrace.enrichment.storage import EnrichmentStore, Entry, Guard
from patchtrace.search.contracts import QueryPlan
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import DEFAULT_LIMITS
from patchtrace.search.normalize import clean_query_text, fold
from patchtrace.search.query import parse_query

KIND = 'search-saved'
CONTRACT = 'search-saved/1'
RECENT_CONTRACT = 'search-recent/1'
GUARD_RUN = 'search'
SAVED_DOMAIN = 'search-saved'
NAME_MAX = 64
RECENT_MAX = 20
_ROW_ID = re.compile(r'search-saved:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_UTC = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$'


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


SavedId = Annotated[str, StringConstraints(pattern=_ROW_ID.pattern)]


class SavedSearch(_Strict):
    """Body of a `search-saved` row. `create` carries a name and a plan; `delete` carries only `of`, the row it ends."""
    contract: Literal['search-saved/1'] = CONTRACT
    saved_id: SavedId
    op: Literal['create', 'delete']
    name: str | None = Field(default=None, min_length=1, max_length=NAME_MAX)
    plan: QueryPlan | None = None
    of: SavedId | None = None
    created: str = Field(pattern=_UTC)

    @model_validator(mode='after')
    def _consistent(self):
        create = self.op == 'create'
        if create != (self.name is not None and self.plan is not None) or create == (self.of is not None):
            raise ValueError('a create has a name and a plan and no target; a delete has only a target')
        if self.of == self.saved_id:
            raise ValueError('a delete cannot end itself')
        return self


@dataclass(frozen=True, slots=True)
class SavedQuery:
    """A saved search that is set now. `text` is the stored query text, to be re-parsed, never trusted."""
    saved_id: str
    name: str
    text: str
    created: str


@dataclass(frozen=True, slots=True)
class SavedList:
    """The saved searches, ordered by name, and the number of stored rows this reader could not read."""
    items: tuple[SavedQuery, ...]
    skipped: int


@runtime_checkable
class SavedSearchStore(Protocol):
    def save(self, name: str, plan: QueryPlan) -> SavedQuery:
        """Keep a plan under a name. The same name and plan again returns the existing one; the same name with
        another plan, or more than `saved_searches` entries, is refused."""
        ...

    def delete(self, saved_id: str) -> bool:
        """End a saved search: True when it was set. Nothing is deleted from storage; the end is a row."""
        ...

    def list(self) -> SavedList:
        """The searches that are set, ordered by folded name."""
        ...


def clean_name(value: object) -> str:
    """A saved-search name: NFC text with whitespace collapsed, 1 to 64 characters, no control or format characters."""
    text = ' '.join(unicodedata.normalize('NFC', value).split()) if isinstance(value, str) else ''
    if not 1 <= len(text) <= NAME_MAX or any(unicodedata.category(c)[0] == 'C' for c in text):
        raise SearchError('PT-SEARCH-INPUT', f'a saved search needs a plain name of 1 to {NAME_MAX} characters',
                          recoverable=True)
    return text


def rerun_plan(item: SavedQuery) -> QueryPlan:
    """The plan to run for a saved search: its text parsed again by the current grammar (raises PT-SEARCH-QUERY)."""
    return parse_query(item.text)


def _ordered(items: list[SavedQuery]) -> tuple[SavedQuery, ...]:
    return tuple(sorted(items, key=lambda item: (fold(item.name), item.saved_id)))


def _fold_events(events: list[SavedSearch]) -> tuple[SavedQuery, ...]:
    """The creates that no delete names; a delete of an unknown row ends nothing."""
    ended = {event.of for event in events if event.op == 'delete'}
    return _ordered([SavedQuery(e.saved_id, e.name or '', e.plan.text if e.plan else '', e.created)
                     for e in events if e.op == 'create' and e.saved_id not in ended])


def _same_name(items: tuple[SavedQuery, ...] | list[SavedQuery], name: str) -> SavedQuery | None:
    return next((item for item in items if fold(item.name) == fold(name)), None)


def _text_gives(text: str, plan: QueryPlan) -> bool:
    """True when parsing `text` today gives `plan`: the only trust a stored or supplied plan gets."""
    try:
        return parse_query(text).digest() == plan.digest()
    except SearchError:
        return False


class MemorySavedStore:
    """`SavedSearchStore` kept in memory, for tests and for a project that cannot hold rows. It follows the same
    event rules as the enrichment-backed store."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None, new_id: Callable[[], str] | None = None):
        self._events: list[SavedSearch] = []
        self._clock = clock or (lambda: datetime.now(UTC))
        self._new_id = new_id or (lambda: str(uuid.uuid4()))

    def save(self, name: str, plan: QueryPlan) -> SavedQuery:
        return save_into(self, name, plan)

    def delete(self, saved_id: str) -> bool:
        return delete_from(self, saved_id)

    def list(self) -> SavedList:
        return SavedList(_fold_events(self._events), 0)

    def events(self) -> tuple[SavedSearch, ...]:
        return tuple(self._events)

    def append(self, event: SavedSearch) -> None:
        self._events.append(event)

    def make_event(self, **fields) -> SavedSearch:
        return new_event(self._clock, self._new_id, **fields)


def new_event(clock: Callable[[], datetime], new_id: Callable[[], str], **fields) -> SavedSearch:
    return SavedSearch(saved_id=f'search-saved:{new_id()}', created=clock().astimezone(UTC).isoformat(), **fields)


def save_into(target, name: str, plan: QueryPlan) -> SavedQuery:
    """Shared rule of both stores: validate, dedupe by folded name, bound the count, append one create row."""
    if not isinstance(plan, QueryPlan):
        raise SearchError('PT-SEARCH-INPUT', 'only a parsed query plan can be saved', recoverable=True)
    if not _text_gives(plan.text, plan):
        raise SearchError('PT-SEARCH-INPUT', 'the plan does not match its query text', recoverable=True)
    name = clean_name(name)
    current = target.list().items
    known = _same_name(current, name)
    if known is not None:
        if _text_gives(known.text, plan):
            return known
        raise SearchError('PT-SEARCH-INPUT', 'a saved search already has this name; delete it first or pick another',
                          recoverable=True)
    if len(current) >= DEFAULT_LIMITS.saved_searches:
        raise SearchError('PT-SEARCH-LIMIT', f'at most {DEFAULT_LIMITS.saved_searches} saved searches',
                          recoverable=True)
    event = target.make_event(op='create', name=name, plan=plan)
    target.append(event)
    return SavedQuery(event.saved_id, name, plan.text, event.created)


def delete_from(target, saved_id: str) -> bool:
    if not isinstance(saved_id, str) or not any(item.saved_id == saved_id for item in target.list().items):
        return False
    target.append(target.make_event(op='delete', of=saved_id))
    return True


class EnrichmentSavedStore:
    """`SavedSearchStore` over the project's `search-saved` rows. `project_id` names the project the rows belong to
    (rows of another project are skipped), `revision` gives the project revision to stamp on a row."""

    def __init__(self, enrichment: EnrichmentStore, project_id: str, *, revision: Callable[[], int] = lambda: 0,
                 clock: Callable[[], datetime] | None = None, new_id: Callable[[], str] | None = None):
        self._enrichment = enrichment
        self._project_id = project_id
        self._revision = revision
        self._clock = clock or (lambda: datetime.now(UTC))
        self._new_id = new_id or (lambda: str(uuid.uuid4()))

    def save(self, name: str, plan: QueryPlan) -> SavedQuery:
        return save_into(self, name, plan)

    def delete(self, saved_id: str) -> bool:
        return delete_from(self, saved_id)

    def list(self) -> SavedList:
        events, skipped = self._events()
        return SavedList(_fold_events(events), skipped)

    def make_event(self, **fields) -> SavedSearch:
        return new_event(self._clock, self._new_id, **fields)

    def append(self, event: SavedSearch) -> None:
        body = event.model_dump(mode='json')
        digest = event.plan.digest() if event.plan else domain_id(SAVED_DOMAIN, 1, body)
        guard = Guard(self._project_id, GUARD_RUN, digest, digest)
        try:
            self._enrichment.publish(KIND, guard, guard, self._revision(), 'complete', body, event.saved_id)
        except EnrichmentError as exc:
            raise SearchError('PT-SEARCH-STORE', 'the saved search could not be stored', recoverable=True) from exc

    def _events(self) -> tuple[list[SavedSearch], int]:
        corrupt: list[str] = []
        try:
            entries = self._enrichment.entries(KIND, on_corrupt=corrupt.append)
        except EnrichmentError as exc:
            raise SearchError('PT-SEARCH-STORE', 'the saved searches could not be read', recoverable=True) from exc
        events = [event for event in (self._event(entry) for entry in entries) if event is not None]
        return events, len(corrupt) + len(entries) - len(events)

    def _event(self, entry: Entry) -> SavedSearch | None:
        if entry.guard.project_id != self._project_id or not isinstance(entry.body, dict):
            return None
        try:
            event = SavedSearch.model_validate_json(json.dumps(entry.body))
        except ValidationError:
            return None
        return event if event.saved_id == entry.id else None


# --- recent queries ---------------------------------------------------------------------------------------------

class RecentState(_Strict):
    contract: Literal['search-recent/1'] = RECENT_CONTRACT
    queries: tuple[Annotated[str, Field(min_length=1, max_length=DEFAULT_LIMITS.query_chars)], ...] = Field(
        default=(), max_length=RECENT_MAX)


@runtime_checkable
class RecentStore(Protocol):
    """Where the recent list lives (QSettings in the GUI). Both methods never raise."""

    def load(self) -> str | None: ...

    def store(self, text: str) -> None: ...


class MemoryRecentStore:
    def __init__(self, text: str | None = None):
        self.text = text

    def load(self) -> str | None:
        return self.text

    def store(self, text: str) -> None:
        self.text = text


def remember(recent: tuple[str, ...], query: str) -> tuple[str, ...]:
    """The list with `query` first: whitespace collapsed, a repeat (by folded text) moved up and respelled, an empty,
    unprintable or too long query ignored, at most `RECENT_MAX` kept."""
    try:
        text = clean_query_text(query) if isinstance(query, str) else ''
    except SearchError:
        return recent
    if not text or len(text) > DEFAULT_LIMITS.query_chars:
        return recent
    rest = [item for item in recent if fold(item) != fold(text)]
    return (text, *rest)[:RECENT_MAX]


def dump_recent(recent: tuple[str, ...]) -> str:
    return RecentState(queries=recent[:RECENT_MAX]).model_dump_json()


def load_recent(text: str | None) -> tuple[str, ...]:
    """The stored list, read leniently: unknown fields are ignored, an entry that is not usable text is dropped, and a
    value that is not a `search-recent/1` document reads as empty."""
    try:
        doc = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return ()
    if not isinstance(doc, dict) or doc.get('contract') != RECENT_CONTRACT or not isinstance(doc.get('queries'), list):
        return ()
    out: tuple[str, ...] = ()
    for item in reversed(doc['queries'][:RECENT_MAX]):
        out = remember(out, item)
    return out


class RecentQueries:
    """The recent list over a `RecentStore`; each call reads and writes the whole bounded list."""

    def __init__(self, backing: RecentStore):
        self._backing = backing

    def items(self) -> tuple[str, ...]:
        return load_recent(self._backing.load())

    def add(self, query: str) -> tuple[str, ...]:
        updated = remember(self.items(), query)
        self._backing.store(dump_recent(updated))
        return updated

    def clear(self) -> None:
        self._backing.store(dump_recent(()))
