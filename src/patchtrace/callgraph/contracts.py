"""Persisted-shape models of the call-graph explorer (workbench-graph/1). Additive changes only."""
from __future__ import annotations

from collections.abc import Iterable
from typing import Literal, NamedTuple, Protocol

from pydantic import BaseModel, ConfigDict, Field

from .limits import CancelCheck

Side = Literal['older', 'newer']
NodeKind = Literal['function', 'paired-unchanged', 'external', 'label-only', 'ambiguous']
NodeTier = Literal['record', 'pairing', 'label']
# How the A1 resolution ladder decided; `unresolved` is the label-only fallback.
NodeVia = Literal['emitted-record', 'name-match', 'address-match', 'external', 'thunk', 'count-suffix',
                  'unresolved']
NodeFlag = Literal['import', 'hub', 'thunk-suspect', 'api-hint', 'newly-imported', 'trace-helper',
                   'inferred-count-suffix']
Support = Literal['called', 'calling']
Completeness = Literal['changed-set-lists', 'whole-program', 'unknown']
PairKind = Literal['one', 'many', 'removed', 'added', 'unknown', 'contested']


class Model(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True, extra='forbid')


class GraphNode(Model):
    contract: Literal['workbench-graph-node/1'] = 'workbench-graph-node/1'
    id: str
    side: Side
    kind: NodeKind
    label: str = Field(max_length=512)
    via: NodeVia
    tier: NodeTier
    function_id: str | None = None
    match_id: str | None = None
    # Address as Ghidriff lists it (virtual); comparable within one side only, never across builds.
    address: int | None = None
    flags: tuple[NodeFlag, ...] = ()
    candidates: tuple[str, ...] = ()
    reason: str = ''


class GraphEdge(Model):
    contract: Literal['workbench-graph-edge/1'] = 'workbench-graph-edge/1'
    id: str
    src: str  # caller node id
    dst: str  # callee node id
    side: Side
    support: tuple[Support, ...]  # both = listed by both ends
    flags: tuple[str, ...] = ()


class SourceInfo(Model):
    source_id: str
    version: str
    tier: Literal['labels', 'addresses']


class MoreMarker(Model):
    node: str
    count: int = Field(ge=1)


class Opinion(Model):
    """One engine's statement about a function's partners."""
    via: str
    partners: tuple[str, ...]


class Pairing(Model):
    contract: Literal['workbench-graph-pairing/1'] = 'workbench-graph-pairing/1'
    kind: PairKind
    partners: tuple[str, ...] = ()  # raw labels on the other side (sanitize before display)
    via: str = ''  # manual | ghidriff:<first match type> | unified:<tier> | secondary:<engine> | inferred
    engines: tuple[Opinion, ...] = ()  # every opinion kept
    inferred: bool = False


class GraphView(Model):
    contract: Literal['workbench-graph/1'] = 'workbench-graph/1'
    project_id: str
    run_id: str
    older_sha256: str
    newer_sha256: str
    orientation: Literal['older->newer'] = 'older->newer'
    side: Side
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    correspondence: tuple[tuple[str, str], ...] = ()  # (older node id, newer node id); never a call
    more: tuple[MoreMarker, ...] = ()
    truncated: bool = False
    completeness: Completeness
    limitations: tuple[str, ...] = ()
    source: SourceInfo


class Claim(NamedTuple):
    """One directed call statement: `caller` calls `callee`, said by `support` (a calls or a callers list).
    A tuple, not a model: up to 250,000 of these flow through one snapshot."""
    caller: str
    callee: str
    support: Support


class CallSource(Protocol):
    source_id: str
    tier: Literal['labels', 'addresses']
    completeness: Completeness

    def claims(self, side: Side, cancel: CancelCheck) -> Iterable[Claim]: ...

    def listed(self, side: Side) -> Iterable[str]:
        """Labels whose own call lists are stored (an absent list is unknown, not empty)."""
        ...


class PairMapPort(Protocol):
    def partner(self, side: Side, label: str) -> Pairing: ...


class RawMatchesReader(Protocol):
    def __call__(self, root: object, project: object) -> tuple[dict | None, tuple[str, ...]]: ...
