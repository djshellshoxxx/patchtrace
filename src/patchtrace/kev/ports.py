"""Protocol ports other packages call instead of importing KEV behaviour (KEV-integration-plan sections 7 and 8)."""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .view_model import KevCell


@runtime_checkable
class KevLookupPort(Protocol):
    """KB and CVE tables ask for one cell per visible CVE; the answer is an O(1) lookup, never a score."""

    def cell(self, cve: str) -> KevCell: ...
