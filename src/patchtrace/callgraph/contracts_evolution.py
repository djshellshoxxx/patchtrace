"""Persisted-shape models of the N-way callee evolution (workbench-graph-evolution/1). Additive changes only."""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from .contracts import Model

Cell = Literal['present', 'absent', 'unknown']
EventKind = Literal['appeared', 'dropped', 'reverted']
InconsistencyKind = Literal['same-build-callees-differ']


class LineageEvent(Model):
    kind: EventKind
    ordinal: int = Field(ge=0)  # the build where the change is first seen


class CalleeLineage(Model):
    id: str
    labels_by_ordinal: tuple[str | None, ...]  # sanitized; None where the callee has no label in that build
    cells: tuple[Cell, ...]
    events: tuple[LineageEvent, ...] = ()


class OrdinalDigest(Model):
    ordinal: int = Field(ge=0)
    digest: str


class Inconsistency(Model):
    kind: InconsistencyKind
    ordinal: int = Field(ge=0)
    detail: str = Field(max_length=512)


class NeighbourhoodEvolution(Model):
    contract: Literal['workbench-graph-evolution/1'] = 'workbench-graph-evolution/1'
    series_id: str
    chain_id: str
    builds: tuple[str, ...]  # build labels in ordinal order
    focus_labels: tuple[str | None, ...]  # the chain's function label per build (sanitized)
    lineages: tuple[CalleeLineage, ...]
    digest_by_ordinal: tuple[OrdinalDigest, ...] = ()
    inconsistencies: tuple[Inconsistency, ...] = ()
    truncated: bool = False
    limitations: tuple[str, ...] = ()
