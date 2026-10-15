"""The one door other features use to read KEV answers (KEV-integration-plan sections 4 and 6). Stdlib only.

KB, patch-intelligence, report and fabric code receive a ``KevLookupPort`` and never import ``kev`` internals. It
exposes facts about a CVE, and the opt-in reading-order helpers of ``view_model`` work on its cells; no method takes
or returns a score, a rank or a function, so KEV cannot reach a ranking through it.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .contracts import KevCatalogMeta, KevLookup
    from .view_model import KevCell


@runtime_checkable
class KevLookupPort(Protocol):
    """Answers for CVE IDs against one catalog snapshot at one injected moment."""

    @property
    def meta(self) -> KevCatalogMeta | None:
        """Provenance of the snapshot behind every answer, or None when no catalog is loaded."""

    def cell(self, cve: str) -> KevCell:
        """The KEV column cell for one ID (O(1) after the first call): text, sentence, reading-order key."""

    def lookup(self, cve: str) -> KevLookup:
        """The full answer for one ID: status, CISA's entry and the snapshot's age."""

    def summary_line(self, cves: Iterable[str]) -> str | None:
        """One sentence counting the listed CVEs among ``cves``; None when there is no catalog or no valid ID."""
