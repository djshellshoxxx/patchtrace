"""Analyst pins: `PinPort` and its enrichment-backed store over the rows of kind `anchor-pin`
(FAB-integration-plan.md s7 "Pins as built").

A pin keeps an anchor the analyst wants to come back to, with a note. It is its own port, so `AnchorSink` never changes,
and its own rows, so no producer can touch it: a pin names the anchor by identity (kind, key, side, role, subject), not
by the batch row that offered it, which means it outlives every replacement and retraction of that batch. The rows are
append-only events (`pin`, `unpin`); the state of an anchor is its event with the highest sequence number (a clock can
tie, as the Windows clock does within 15.6 ms, a sequence cannot), and nothing here deletes an event. Retention never
deletes the kind.

An event that cannot be read (a newer contract, a failed hash or identity check, another project) is counted in
`PinList.skipped`, never hidden. A pin made while the project compared the files the other way round is listed stale.
Notes are plain text, at most 2 KiB, and never cut: a longer note is refused.

Thread ownership as for the batch store: use it on the thread that owns the project.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated, Literal, Protocol, runtime_checkable

from pydantic import AfterValidator, Field, ValidationError, model_validator

from ..enrichment.identity import domain_id
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from .contracts import (
    ROLES_BY_KIND,
    Anchor,
    Key,
    Kind,
    Label,
    Role,
    Sha256,
    Side,
    Slug,
    clean_line,
    plain_line,
)
from .ids import anchor_id, check_orientation, verify_anchor
from .limits import FabricError
from .store import GUARD_RUN, ProjectAccess, ProjectFacts, StrictModel, as_fabric_errors, storage_error

KIND = 'anchor-pin'
CONTRACT = 'fabric-pin/1'
PIN_DOMAIN = 'fabric-pin'
MAX_NOTE_BYTES = 2 * 1024
_ROW_ID = re.compile(r'fabric-pin:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
_VIA = re.compile(r'[a-z0-9-]{1,48}')


# --- the persisted contract ---------------------------------------------------------------------------------------

def _plain_note(value: str) -> str:
    for line in value.split('\n'):
        plain_line(line)
    return value


Note = Annotated[str, AfterValidator(_plain_note), Field(max_length=MAX_NOTE_BYTES)]
_UTC = r'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(\+00:00|Z)$'
Utc = Annotated[str, Field(pattern=_UTC)]


class PinEvent(StrictModel):
    """Body of an `anchor-pin` row: one analyst action on one anchor. The anchor is named by its identity and label, so
    the event says what was pinned even after every batch that offered it is gone, and by the project's older and newer
    hashes, so it says which way round the files were compared."""
    contract: Literal['fabric-pin/1'] = CONTRACT
    seq: int = Field(ge=1)
    action: Literal['pin', 'unpin']
    anchor_id: Sha256
    kind: Kind
    key: Key
    side: Side
    role: Role
    subject: Key | None = None
    label: Label
    note: Note = ''
    via: Slug
    older_sha256: Sha256
    newer_sha256: Sha256
    created_utc: Utc

    @model_validator(mode='after')
    def _consistent(self):
        if len(self.note.encode('utf-8')) > MAX_NOTE_BYTES:
            raise ValueError(f'a note is at most {MAX_NOTE_BYTES} bytes')
        if self.action == 'unpin' and self.note:
            raise ValueError('an unpin carries no note')
        if self.role not in ROLES_BY_KIND[self.kind]:
            raise ValueError('the role is not allowed for this kind')
        if self.anchor_id != anchor_id(self.kind, self.key, self.side, self.role, self.subject):
            raise ValueError('anchor_id must be derived from the identity')
        return self


@dataclass(frozen=True, slots=True)
class Pin:
    """An anchor that is pinned now: its identity and label as pinned, the latest note, where the pin came from, when
    and in which event (`seq`), and whether it was made for the other orientation or stored stale."""
    anchor_id: str
    kind: str
    key: str
    side: str
    role: str
    subject: str | None
    label: str
    note: str
    via: str
    pinned_utc: str
    seq: int
    stale: bool


@dataclass(frozen=True, slots=True)
class PinList:
    """The pins of a project, newest first, and the number of stored events this reader could not read."""
    pins: tuple[Pin, ...]
    skipped: int


@runtime_checkable
class PinPort(Protocol):
    """An analyst's pins on anchors. A pin outlives the batches that offered its anchor; `unpin` keeps the history."""

    def pin(self, project_key: str, anchor: Anchor, note: str = '', via: str = 'analyst') -> Pin:
        """Pin an anchor with a note, or change the note of a pin that is set. Pinning again with the same note writes
        nothing. An anchor made for the other orientation of the project's pair is refused."""
        ...

    def unpin(self, project_key: str, anchor_id: str) -> bool:
        """Remove a pin: True when one was set. Nothing is deleted; the unpin is an event."""
        ...

    def pins(self, project_key: str) -> PinList:
        """The pins that are set, newest first, with the count of events that could not be read."""
        ...


def event_digest(event: PinEvent) -> str:
    """The `input_digest` of an event row's guard."""
    return domain_id(PIN_DOMAIN, 1, event.model_dump(mode='json'))


def event_row_id(uuid_text: str) -> str:
    return f'fabric-pin:{uuid_text}'


def clean_note(value: object) -> str:
    """Untrusted text -> a note `PinEvent` accepts: lines are kept, tabs and unsafe characters are dropped as
    `clean_line` does, and a note over 2 KiB is refused rather than cut (it is the analyst's own text)."""
    text = '' if value is None else str(value)
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    note = '\n'.join(clean_line(line, MAX_NOTE_BYTES + 1) for line in lines)
    if len(note.encode('utf-8')) > MAX_NOTE_BYTES:
        raise FabricError('PT-FAB-LIMIT', 'A note is longer than 2 KiB', reason='note-size')
    return note


# --- reading events -----------------------------------------------------------------------------------------------

def _event(entry: Entry, project_id: str) -> PinEvent | None:
    if entry.guard.project_id != project_id or not _ROW_ID.fullmatch(entry.id):
        return None
    try:
        return PinEvent.model_validate(entry.body)
    except ValidationError:
        return None


def _latest(events: list[tuple[Entry, PinEvent]]) -> dict[str, tuple[Entry, PinEvent]]:
    """The last event of each anchor; `events` is in sequence order."""
    return {event.anchor_id: (entry, event) for entry, event in events}


def _pin(entry: Entry, event: PinEvent, project: ProjectFacts) -> Pin:
    stale = entry.stale or (event.older_sha256, event.newer_sha256) != project.pair
    return Pin(event.anchor_id, event.kind, event.key, event.side, event.role, event.subject, event.label, event.note,
               event.via, event.created_utc, event.seq, stale)


class EnrichmentPinStore:
    """`PinPort` over the project's `anchor-pin` rows. `clock` (a timezone-aware time) and `new_id` (a canonical
    lower-case UUID) may be given for tests; the defaults are the system clock and `uuid4`."""

    def __init__(self, enrichment: EnrichmentStore, *, clock: Callable[[], datetime] | None = None,
                 new_id: Callable[[], str] | None = None):
        self._enrichment = enrichment
        self._access = ProjectAccess(enrichment)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._new_id = new_id or (lambda: str(uuid.uuid4()))

    def pin(self, project_key: str, anchor: Anchor, note: str = '', via: str = 'analyst') -> Pin:
        _, project = self._access.open(project_key)
        if project is None:
            raise storage_error('project-unsaved', 'The project has no saved snapshot to hold pins')
        if not isinstance(anchor, Anchor):
            raise FabricError('PT-FAB-INPUT', 'Only an anchor record can be pinned', reason='not-an-anchor')
        if not isinstance(via, str) or not _VIA.fullmatch(via):
            raise FabricError('PT-FAB-INPUT', 'Where a pin came from is a slug', reason='via')
        verify_anchor(anchor)
        check_orientation(anchor, *project.pair)
        text = clean_note(note)
        events, _ = self._events(project)
        known = _latest(events).get(anchor.anchor_id)
        if known is not None and known[1].action == 'pin' and known[1].note == text:
            current = _pin(*known, project)
            if not current.stale:  # a stale pin is pinned again, so that it says which way round the files are now
                return current
        return _pin(*self._append(project, events, 'pin', anchor, text, via), project)

    def unpin(self, project_key: str, anchor_id: str) -> bool:
        _, project = self._access.open(project_key)
        if project is None:
            return False
        events, _ = self._events(project)
        known = _latest(events).get(anchor_id) if isinstance(anchor_id, str) else None
        if known is None or known[1].action != 'pin':
            return False
        self._append(project, events, 'unpin', known[1], '', 'analyst')
        return True

    def pins(self, project_key: str) -> PinList:
        _, project = self._access.open(project_key)
        if project is None:
            return PinList((), 0)
        events, skipped = self._events(project)
        set_now = [(entry, event) for entry, event in _latest(events).values() if event.action == 'pin']
        newest_first = sorted(set_now, key=lambda pair: (pair[1].seq, pair[0].id), reverse=True)
        return PinList(tuple(_pin(entry, event, project) for entry, event in newest_first), skipped)

    def _events(self, project: ProjectFacts) -> tuple[list[tuple[Entry, PinEvent]], int]:
        """The readable events in sequence order and the number of stored rows that were not."""
        corrupt: list[str] = []
        with as_fabric_errors():
            entries = self._enrichment.entries(KIND, on_corrupt=corrupt.append)
        read = [(entry, _event(entry, project.id)) for entry in entries]
        events = sorted(((entry, event) for entry, event in read if event is not None),
                        key=lambda pair: (pair[1].seq, pair[0].id))
        return events, len(corrupt) + len(read) - len(events)

    def _append(self, project: ProjectFacts, events: list[tuple[Entry, PinEvent]], action: str,
                source: Anchor | PinEvent, note: str, via: str) -> tuple[Entry, PinEvent]:
        """Write one event about the anchor `source` names, numbered after every readable event."""
        event = PinEvent(
            seq=max((event.seq for _, event in events), default=0) + 1, action=action, anchor_id=source.anchor_id,
            kind=source.kind, key=source.key, side=source.side, role=source.role, subject=source.subject,
            label=source.label, note=note, via=via, older_sha256=project.pair[0], newer_sha256=project.pair[1],
            created_utc=self._clock().astimezone(UTC).isoformat())
        guard = Guard(project.id, GUARD_RUN, '', event_digest(event))
        with as_fabric_errors():
            entry = self._enrichment.publish(KIND, guard, guard, project.revision, 'complete',
                                             event.model_dump(mode='json'), event_row_id(self._new_id()))
        return entry, event
