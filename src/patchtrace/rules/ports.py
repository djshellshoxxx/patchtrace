"""Ports of the rule workflow: Protocols and the plain data that crosses them (YRX-integration-plan s7, "Ports").

The rule modules depend on these seams and on `contracts`, never on another feature's internals. Concrete
implementations are adapters (`rules/adapters/*`: tools_delta and pe_imports in R3, mask_iced in R4) or fakes in tests.
The signatures are provisional until R3, R4, R5 and R6a land (they are not persisted contracts); the slice that needs a
different shape proposes it to the integrator.

Naming: the card lists `PairSource` as both the persisted record (`contracts.PairSource`, embedded in candidates and
versions) and a port. The record keeps the name; the port that returns it is `PairLookup`.

Rules every implementation follows: a tool that is missing, failed or not run is reported through `Coverage` as
`unavailable` and yields fewer items (unknown is never a negative vote, and "no items" from a `complete` channel is the
only way to say "none found"); free text is returned as-is and is untrusted (the pure modules bound and escape it);
nothing here executes a target binary, opens a socket or transmits data.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from .contracts import (
    ApiRef,
    Classification,
    Encoding,
    LinkedBy,
    MaskKind,
    MaskSourceName,
    PairSource,
    Resolution,
    Separation,
    Side,
    TargetRef,
)

ChannelState = Literal['complete', 'unavailable']
Flow = Literal['next', 'call', 'indirect-call', 'branch', 'indirect-branch', 'conditional', 'return', 'other']


@dataclass(frozen=True)
class Coverage:
    """Whether the producing tool finished for each build of the pair. An item missing from an `unavailable` build is
    `unknown`; only a `complete` build may say `absent`."""
    older: ChannelState
    newer: ChannelState


# --- strings (WB3 / FLOSS via the SPEC-29 delta) ------------------------------------------------------------------------

@dataclass(frozen=True)
class StringObservation:
    side: Side                    # the build the bytes were read from
    value_sha256: str
    data: bytes                   # the exact bytes at `offset`, re-read from the verified artifact (never a display form)
    encoding: Encoding
    offset: int                   # file offset of the string in that build
    evidence_run_id: str
    linked_by: LinkedBy           # `xref` only when a decoded RIP-relative target equals the string's RVA
    separation: Separation
    secret_kind: str | None = None  # set: the string looks like a secret and is never used in a rule


@dataclass(frozen=True)
class StringChannel:
    coverage: Coverage
    items: tuple[StringObservation, ...] = ()


@runtime_checkable
class StringSource(Protocol):
    def strings(self, pair: PairSource) -> StringChannel:
        """Static strings added, removed or shared by the pair's code (decoded and stack strings are never offered)."""
        ...


# --- capabilities (CAP / capa via the SPEC-29 delta) -----------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityObservation:
    rule_id: str
    namespace: str | None
    attack: tuple[str, ...]
    classification: Classification  # only `newly-introduced` and `removed-with-code`; the rest is never offered
    api_gates: tuple[ApiRef, ...] = ()


@dataclass(frozen=True)
class CapabilityChannel:
    coverage: Coverage
    items: tuple[CapabilityObservation, ...] = ()


@runtime_checkable
class CapabilitySource(Protocol):
    def capabilities(self, pair: PairSource) -> CapabilityChannel:
        """Capabilities that appeared or disappeared together with the changed function."""
        ...


# --- imports (pe_overview) -----------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ImportEntry:
    dll: str
    name: str | None              # exactly one of name and ordinal
    ordinal: int | None
    delay: bool
    slot_rva: int | None          # RVA of the import address table slot, when the table gives it


@dataclass(frozen=True)
class ImportTable:
    entries: tuple[ImportEntry, ...]


@runtime_checkable
class ImportSource(Protocol):
    def imports(self, pair: PairSource, side: Side) -> ImportTable | None:
        """The build's import table; None when it is unavailable (unreadable, packed, not parsed)."""
        ...


# --- bytes (decoder) -------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class MaskSpan:
    start: int                    # byte offset inside the instruction
    length: int
    kind: MaskKind


@dataclass(frozen=True)
class DecodedInstruction:
    offset: int                   # byte offset inside the function body
    size: int
    flow: Flow
    spans: tuple[MaskSpan, ...] = ()  # address-dependent fields, positive evidence only; immediates are kept
    target_rva: int | None = None  # what a RIP-relative operand or a near branch resolves to (an import slot for a call pin)


@runtime_checkable
class MaskSource(Protocol):
    """Decodes one function body and marks the bytes that depend on the image layout. Default adapter: iced-x86; the
    unified-engine IR replaces it once it lands (a parity test then compares the two)."""

    @property
    def name(self) -> MaskSourceName: ...

    @property
    def version(self) -> str: ...

    def decode(self, code: bytes, rva: int) -> tuple[DecodedInstruction, ...]:
        """`code` is the whole verified function body mapped at `rva`. RIP-relative displacements are `rip-disp`; a branch
        whose target lies outside the body is `branch-ext`. Raises `RuleError('PT-RULE-DECODE')` on an invalid instruction."""
        ...


# --- project facts ---------------------------------------------------------------------------------------------------

@runtime_checkable
class PairLookup(Protocol):
    def pair(self, project_id: str, match_id: str) -> PairSource:
        """The accepted pair for a match. Raises `RuleError`: `PT-RULE-INPUT` (reasons `no-such-match`, `not-accepted`) or
        `PT-RULE-STALE` when the project or its artifacts moved."""
        ...


@dataclass(frozen=True)
class BuildEntry:
    target: TargetRef
    path: str                     # the local file the worker reads; never stored and never exported


@runtime_checkable
class BuildSource(Protocol):
    def builds(self, pair: PairSource) -> tuple[BuildEntry, ...]:
        """The series (anchors included), extra builds and the project's clean files, in display order."""
        ...


@runtime_checkable
class AdvisorySource(Protocol):
    def advisory_says(self, cves: Sequence[str], sha256s: Sequence[str]) -> Mapping[str, Resolution]:
        """What the advisories say about each build, by SHA-256; builds the advisories do not cover read `unknown`."""
        ...
