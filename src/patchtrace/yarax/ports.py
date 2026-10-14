"""Seams of the rule-authoring core: Protocols only, no behaviour, no I/O (plan s7).

Adapters over stored data or fakes in tests implement them; a source that is missing, failed or stale returns fewer
items (unknown, never a negative vote). Signatures are provisional until R3/R4/R5 land. The plan's `PairSource` port
is `PairSourcePort` here because `contracts.PairSource` is the persisted record of the same name.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .contracts import (
    CallPin,
    CapabilityFeature,
    Cve,
    Cwe,
    FunctionRef,
    ImportFeature,
    Kb,
    MaskKind,
    PairSource,
    Side,
    StringFeature,
    TargetRef,
)


@dataclass(frozen=True)
class MaskedInstruction:
    rva: int
    length: int
    token: str  # hex tokens with `??` for masked bytes
    masks: tuple[MaskKind, ...] = ()
    pin: CallPin | None = None


@dataclass(frozen=True)
class MaskedFunction:
    function: FunctionRef
    mask_source: str
    instructions: tuple[MaskedInstruction, ...]


@dataclass(frozen=True)
class AdvisoryAnchors:
    cve: tuple[Cve, ...] = ()
    kb: tuple[Kb, ...] = ()
    cwe: tuple[Cwe, ...] = ()


@runtime_checkable
class PairSourcePort(Protocol):
    def accepted_pairs(self, project_id: str) -> Sequence[PairSource]:
        """Reviewed pairs only; unreviewed pairs are never offered."""
        ...


@runtime_checkable
class MaskSource(Protocol):
    def masked_function(self, sha256: str, side: Side, function: FunctionRef) -> MaskedFunction:
        """Raises `RulesError` PT-RULE-MASK without a verified extent and PT-RULE-DECODE on an invalid instruction."""
        ...


@runtime_checkable
class StringSource(Protocol):
    def string_features(self, pair: PairSource) -> Sequence[StringFeature]: ...


@runtime_checkable
class CapabilitySource(Protocol):
    def capability_features(self, pair: PairSource) -> Sequence[CapabilityFeature]: ...


@runtime_checkable
class ImportSource(Protocol):
    def import_features(self, pair: PairSource) -> Sequence[ImportFeature]: ...


@runtime_checkable
class BuildSource(Protocol):
    def targets(self, pair: PairSource) -> Sequence[TargetRef]:
        """Anchors, series, extra and clean files, referenced by hash (paths stay in the adapter)."""
        ...


@runtime_checkable
class AdvisorySource(Protocol):
    def anchors(self, project_id: str) -> AdvisoryAnchors: ...
