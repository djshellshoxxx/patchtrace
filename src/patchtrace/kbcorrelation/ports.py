"""Protocol ports for sibling-package calls (KB-integration-plan section 9).

``kbcorrelation`` domain modules never import ``intelligence``, ``acquisition``, ``enrichment``, ``unified`` or
``secondary`` behaviour; they call these ports. Only ``wiring.py`` (slice K3) imports siblings and binds
implementations. Ports use plain data (bytes, str, dict, tuple) so no sibling type leaks into the domain.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class AdvisoryPort(Protocol):
    """CSAF facts (``intelligence``): validate and normalise exact bytes, return JSON-compatible dicts."""

    def parse_csaf(self, raw: bytes, *, source_sha256: str) -> Mapping[str, Any]: ...

    def report_for(self, cve: str, facts: Sequence[Mapping[str, Any]], older_sha256: str | None,
                   newer_sha256: str | None) -> Mapping[str, Any]: ...


@runtime_checkable
class IndexPort(Protocol):
    """Winbindex rows (``acquisition``): rows for a file name, keyed by SHA-256, in index order."""

    def rows_for(self, file_name: str, winbindex_key: str) -> Sequence[Mapping[str, Any]]: ...


@runtime_checkable
class TransportPort(Protocol):
    """Consented HTTPS fetch. Only K6/K7 bind it; the domain never opens a socket."""

    def fetch(self, url: str, *, max_bytes: int, timeout_s: int) -> bytes: ...


@runtime_checkable
class ProjectPort(Protocol):
    """Project creation and enrichment rows (``ProjectService`` and ``enrichment.storage``)."""

    def create_project(self, older_path: str, newer_path: str, *, directory: str) -> Mapping[str, Any]: ...

    def put_row(self, project_id: str, kind: str, key: str, body: bytes) -> None: ...

    def get_row(self, project_id: str, kind: str, key: str) -> bytes | None: ...


@runtime_checkable
class EvidencePort(Protocol):
    """Comparison evidence for lead rows (``unified`` and ``secondary``); read-only."""

    def evidence_for(self, project_id: str, run_id: str | None) -> Sequence[Mapping[str, Any]]: ...


@runtime_checkable
class ClockPort(Protocol):
    def now_utc(self) -> str: ...


@runtime_checkable
class CancelPort(Protocol):
    def is_cancelled(self) -> bool: ...
