"""Ports of the patch-intent localization core: Protocols only, no behaviour, no I/O (PIL-integration-plan.md s4).

The core (`localize`, PIL-B2) depends on these seams and on `contracts`, never on another feature's internals. Concrete
implementations are adapters in `pilot/sources/*` (PIL-A2/A3) over stored K, B1, SPEC-31, T, PE and KEV data, or fakes in
tests. The signatures are provisional until A2/A3/B2 land (they are not persisted contracts) and may be amended by
their owners; the persisted records they exchange are frozen in `contracts`.

Rules every implementation follows: a source that is missing, not run, unsupported, failed or stale reports it through
a `ChannelStatus` and yields fewer observations (unknown, never a negative vote); free text in a returned observation is
already plain text (`contracts.clean_line`); nothing here executes a target binary, opens a socket or transmits data.
When the insight fabric (FAB) lands it adopts or replaces `origins.py` and rebinds `OriginRegistry`, `AnchorSink` and
`Navigator` here, and nothing else changes.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from .contracts import Candidate, ChannelStatus, Kev, Nav, Observation, PilotAnchor, ToolKey

if TYPE_CHECKING:  # annotation only: the K contract is the canonical advisory model (intelligence/1)
    from ..intelligence.contracts import IntelligenceReport


@runtime_checkable
class OriginRegistry(Protocol):
    """Origin tags per evidence source and the shared-origin component calculus (`origins.DefaultOriginRegistry`)."""

    @property
    def version(self) -> int:
        """Version of the tag table; part of `digest()`."""
        ...

    def tags_for(self, source: str) -> tuple[str, ...]:
        """Sorted origin tags of an evidence source; an unknown source fails closed (`PT-PILOT-INPUT`)."""
        ...

    def components(self, origin_sets: Iterable[Iterable[str]]) -> tuple[tuple[str, ...], ...]:
        """Connected components of origin tags: observations sharing a tag count once."""
        ...

    def digest(self) -> str:
        """Digest of the table; `PilotInputs.origins_digest`."""
        ...


@runtime_checkable
class AnchorSink(Protocol):
    """Receives the anchors PIL offers (function, wanted string and API, rule, CVE, CWE); the fabric owns storage."""

    def publish(self, project_key: str, anchors: Sequence[PilotAnchor]) -> None:
        """Hand over anchors for one project; an implementation may ignore them (a no-op sink is valid)."""
        ...


@runtime_checkable
class Navigator(Protocol):
    """One click to the code, inside the single main window; nothing is fabricated."""

    def unavailable_reason(self, candidate_key: str, nav: Nav | None) -> str | None:
        """None when the location can be revealed; else a short reason slug for the disabled button's tooltip."""
        ...

    def go(self, candidate_key: str, nav: Nav | None) -> bool:
        """Reveal the location (older or newer side); False when it could not be revealed."""
        ...


@runtime_checkable
class AdvisorySource(Protocol):
    """Advisory facts per CVE as the K contract states them (intelligence/1); other sources adapt into it."""

    def cves(self) -> Sequence[str]:
        """CVE ids with stored advisory facts, sorted."""
        ...

    def report(self, cve: str) -> IntelligenceReport | None:
        """Facts, applicability, CWE profile, hypotheses and anchors for one CVE; None when nothing is stored."""
        ...

    def facts_ids(self) -> Sequence[str]:
        """Sorted `facts_id` of every advisory document used (a `PilotInputs.advisory_facts_ids` input)."""
        ...


@runtime_checkable
class ChangeEvidenceSource(Protocol):
    """Code-channel observations per candidate: B1 signals (`b1:*`) and SPEC-31 ChangeFacts (`cf:*`)."""

    def status(self) -> ChannelStatus:
        """State of the code channel (a project without a typed result is `partial`: lexical evidence only)."""
        ...

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        """(candidate_key, observation) pairs for the given candidates, in a deterministic order."""
        ...


@runtime_checkable
class ToolEvidenceSource(Protocol):
    """capa, FLOSS and DiE deltas as observations (`capa:*`, `str:*`, `die:*`); T owns running the tools."""

    def statuses(self) -> Sequence[ChannelStatus]:
        """States of the capa, strings and build channels (not-run until the tool results exist)."""
        ...

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        """Function-attributed observations only: an unlocalized capability or a static string never attaches."""
        ...

    def pair_observations(self) -> Sequence[Observation]:
        """Binary-level observations (toolchain changed, packed, unlocalized capability) that apply to every lead."""
        ...

    def cache_keys(self) -> Sequence[ToolKey]:
        """Cache keys of the tool results used, sorted by engine and side (a `PilotInputs.tool_keys` input)."""
        ...


@runtime_checkable
class KevSource(Protocol):
    """CISA KEV status per CVE: context for ordering CVEs, never evidence about a function."""

    def lookup(self, cve: str) -> Kev:
        """`listed`, `not-in-snapshot` or `unknown`; absence from a snapshot says nothing about exploitation."""
        ...

    def snapshot_id(self) -> str | None:
        """Id of the snapshot consulted (a `PilotInputs.kev_snapshot_id` input), or None when none is loaded."""
        ...


@runtime_checkable
class CallDeltaSource(Protocol):
    """Call observations per candidate (`call:added`, `call:removed`) from imports, IR call keys and Ghidriff labels."""

    def status(self) -> ChannelStatus:
        """State of the calls channel."""
        ...

    def observations(self, candidate_keys: Iterable[str]) -> Iterator[tuple[str, Observation]]:
        """Label-only calls carry verification `label-only` and support at most a tentative lead."""
        ...


@runtime_checkable
class PairingSource(Protocol):
    """The candidate universe and its pairing verdicts (unified result when current, else secondary or Ghidriff)."""

    def status(self) -> ChannelStatus:
        """State of the pairing channel."""
        ...

    def candidates(self) -> Iterator[Candidate]:
        """Every candidate once, in a deterministic order; the verdict follows the identity map of s7."""
        ...

    def unified_result_id(self) -> str | None:
        """Id of the unified result used (a `PilotInputs.unified_result_id` input), or None."""
        ...

    def secondary_set_ids(self) -> Sequence[str]:
        """Sorted ids of the secondary match sets used (a `PilotInputs.secondary_set_ids` input)."""
        ...
