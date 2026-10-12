"""Strict, frozen nway/1 records (SPEC-09 §2). Pure: no Qt, Ghidra, network or I/O.

A chain is a labelled hypothesis assembled from independent pairwise results; nothing
here is a similarity score. Ratios stay upstream text so no new number is implied.
"""
from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT = 'nway/1'
MIN_BUILDS, MAX_BUILDS = 3, 8
MAX_NODES = 100_000
Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Ordinal = Annotated[int, Field(ge=0, le=MAX_BUILDS - 1)]
EventKind = Literal['added', 'removed', 'split', 'merged', 'ambiguous', 'unmatched', 'reverted']
ChainStatus = Literal['inferred', 'confirmed', 'contradicted']


class NwayError(Exception):
    """Typed, user-safe failure; `code` is PT-NWAY-INPUT, -LIMIT, -PAIR or -STORAGE."""

    def __init__(self, code: str, message: str):
        super().__init__(f'{code}: {message}')
        self.code = code


class Record(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class BuildRef(Record):
    ordinal: Ordinal
    label: str = Field(min_length=1, max_length=64)
    artifact_sha256: Sha256


class PairRef(Record):
    """A pair project as observed when the series was computed; any drift marks it stale."""
    from_ordinal: Ordinal
    to_ordinal: Ordinal
    path: str = Field(min_length=1, max_length=1024)
    project_id: str = Field(min_length=1, max_length=128)
    revision: int = Field(ge=0)
    run_id: str | None = Field(default=None, max_length=128)

    @model_validator(mode='after')
    def _relative(self):
        posix = PurePosixPath(self.path)
        if (self.path != posix.as_posix() or posix.is_absolute() or PureWindowsPath(self.path).drive
                or '..' in posix.parts or '\\' in self.path or self.path == '.'):
            raise ValueError('pair project path must be a relative POSIX path below the series root')
        if self.to_ordinal <= self.from_ordinal:
            raise ValueError('pair must run from an older to a newer ordinal')
        return self


class FunctionNode(Record):
    ordinal: Ordinal
    address: int | None = Field(default=None, ge=0, le=2**64 - 1)
    name: str = Field(min_length=1, max_length=4096)


class PairEdge(Record):
    from_node: FunctionNode
    to_node: FunctionNode
    category: str = Field(min_length=1, max_length=32)
    match_types: tuple[str, ...] = ()
    ratio_text: str | None = None
    manual: bool = False
    # Lets a viewer open the pair project at this exact relation.
    match_id: str = Field(min_length=1, max_length=128)

    @model_validator(mode='after')
    def _adjacent(self):
        if self.to_node.ordinal != self.from_node.ordinal + 1:
            raise ValueError('chain edges join adjacent builds only')
        return self


class ChainEvent(Record):
    kind: EventKind
    ordinal: Ordinal
    detail: str = Field(default='', max_length=512)


class Chain(Record):
    chain_id: Sha256
    nodes: tuple[FunctionNode, ...] = Field(min_length=MIN_BUILDS)
    edges: tuple[PairEdge, ...]
    hops: int = Field(ge=MIN_BUILDS - 1)
    weakest_match_type: str
    status: ChainStatus = 'inferred'
    gaps: tuple[Ordinal, ...] = ()
    events: tuple[ChainEvent, ...] = ()

    @model_validator(mode='after')
    def _consistent(self):
        if self.hops != len(self.edges) or len(self.nodes) != self.hops + 1:
            raise ValueError('chain hop count does not match its nodes and edges')
        for i, edge in enumerate(self.edges):
            if edge.from_node != self.nodes[i] or edge.to_node != self.nodes[i + 1]:
                raise ValueError('chain edges do not connect its nodes in order')
        return self


class Series(Record):
    schema_: Literal['nway/1'] = Field(default=CONTRACT, alias='schema')
    series_id: Sha256
    builds: tuple[BuildRef, ...] = Field(min_length=MIN_BUILDS, max_length=MAX_BUILDS)
    pair_projects: tuple[PairRef, ...]
    direct_project: PairRef | None = None
    node_count: int = Field(ge=0, le=MAX_NODES)
    chains: tuple[Chain, ...] = ()

    model_config = ConfigDict(extra='forbid', strict=True, frozen=True, populate_by_name=True)

    @model_validator(mode='after')
    def _shape(self):
        from .graph import series_id
        n = len(self.builds)
        if [b.ordinal for b in self.builds] != list(range(n)):
            raise ValueError('build ordinals must be 0..n-1 in analyst order')
        hashes = [b.artifact_sha256 for b in self.builds]
        if len(set(hashes)) != n:
            raise ValueError('build hashes must be unique')
        if self.series_id != series_id(hashes):
            raise ValueError('series_id does not match the ordered build hashes')
        if [(p.from_ordinal, p.to_ordinal) for p in self.pair_projects] != [(i, i + 1) for i in range(n - 1)]:
            raise ValueError('series needs exactly one pair project per adjacent build pair')
        if self.direct_project is not None and (self.direct_project.from_ordinal,
                                                self.direct_project.to_ordinal) != (0, n - 1):
            raise ValueError('direct pair must run from the first to the last build')
        if any(node.ordinal >= n for chain in self.chains for node in chain.nodes):
            raise ValueError('chain refers to a build outside the series')
        return self
