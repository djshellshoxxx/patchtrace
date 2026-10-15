"""Ports of the anchor fabric: Protocols only, no behaviour, no I/O (FAB-integration-plan.md s7).

Every feature track talks to the fabric through these seams and never imports another feature's internals. The write
side is `AnchorSink` (PIL and KB assume `publish(project_key, anchors)`), the read side is `AnchorReader` (GDE assumes
`resolve(kind, value, side)`); a pin for the analyst is a separate port added in FAB-4, so neither Protocol changes.
`OriginRegistry` and `AnchorSink` are the seams PIL uses: `pilot/ports.py` re-exports them (FAB-3), so PIL has no copy.

Rules every implementation follows: a source that is missing, not run or failed yields fewer anchors (unknown, never a
negative vote); free text in an anchor is already plain text (`contracts.clean_line`); nothing here executes a target
binary, opens a socket or transmits data; a no-op sink is valid, so no track waits for another.
"""
from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, runtime_checkable

from .contracts import Anchor, AnchorPage, AnchorQuery, PublishReport, Resolution


@runtime_checkable
class OriginRegistry(Protocol):
    """Origin tags per evidence source and the shared-origin component calculus (`origins.DefaultOriginRegistry`)."""

    @property
    def version(self) -> int:
        """Version of the tag table; part of `digest()`."""
        ...

    def tags_for(self, source: str) -> tuple[str, ...]:
        """Sorted origin tags of an evidence source; an unknown source fails closed (`PT-FAB-ORIGIN`)."""
        ...

    def components(self, origin_sets: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
        """Connected components of origin tags: witnesses sharing a tag count once."""
        ...

    def digest(self) -> str:
        """Digest of the table; part of every stored batch identity."""
        ...


@runtime_checkable
class AnchorSink(Protocol):
    """Receives the anchors a producer offers for one project; the fabric owns storage."""

    def publish(self, project_key: str, anchors: Sequence[Anchor]) -> PublishReport:
        """Atomic. First removes every witness of each (producer, batch) present in the call, then adds the new ones
        (equal anchors merge into one with several witnesses). A no-op sink is valid."""
        ...

    def retract(self, project_key: str, producer: str, batch: str) -> PublishReport:
        """Remove every witness of one (producer, batch); anchors left without a witness disappear."""
        ...


@runtime_checkable
class AnchorReader(Protocol):
    """Reads what the producers published. Missing is unknown: there is no way to ask for absence."""

    def get(self, project_key: str, anchor_id: str) -> Anchor | None:
        """One anchor by id, or None."""
        ...

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        """Anchors matching every filter, in canonical order, one page at a time."""
        ...

    def resolve(self, project_key: str, kind: str, value: str | None, side: str | None) -> Resolution:
        """Is there something to look at: found (one anchor), ambiguous (candidates, never the first), unknown or
        unsupported. `side` older or newer also matches an anchor present on both; None is any side."""
        ...
