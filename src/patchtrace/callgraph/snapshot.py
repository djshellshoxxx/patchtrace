"""Immutable per-pair call snapshot: resolved nodes and one CSR graph per side, built from a `CallSource`."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from ..enrichment.identity import domain_id
from .contracts import CallSource, Claim, Completeness, GraphNode, Side, SourceInfo, Support
from .csr import CSRGraph, build_csr
from .limits import CANCEL_CLAIM_INTERVAL, CancelCheck, GraphError
from .pairing import ExtraOpinion, PairMap
from .project_input import ProjectInput
from .resolver import Resolver
from .text import sanitize

MAX_CLAIMS = 250_000  # GL-01
ALGO = 'callgraph/1'
SIDES: tuple[Side, ...] = ('older', 'newer')


class GhidriffListSource:
    """Claims from the stored `called`/`calling` lists of Ghidriff's emitted records (changed set only)."""
    source_id = 'ghidriff-lists'
    tier: Literal['labels', 'addresses'] = 'labels'
    completeness: Completeness = 'changed-set-lists'

    def __init__(self, data: ProjectInput) -> None:
        self._data = data

    def claims(self, side: Side, cancel: CancelCheck) -> Iterable[Claim]:
        for entry in self._data.side_entries(side):
            for callee in entry.callees:
                yield Claim(entry.label, callee, 'called')
            for caller in entry.callers:
                yield Claim(caller, entry.label, 'calling')

    def listed(self, side: Side) -> Iterable[str]:
        """Labels whose own call lists are stored (imports carry only a callers list)."""
        return (e.label for e in self._data.side_entries(side) if not e.external)


@dataclass(frozen=True)
class SnapshotOptions:
    resolve_thunks: bool = False
    hub_registry_version: str | None = None
    patch_rules: tuple[str, str] | None = None  # (version, digest)
    secondary_set_digest: str | None = None
    unified_result_id: str | None = None


@dataclass(frozen=True)
class SideGraph:
    nodes: tuple[GraphNode, ...]
    raw_labels: tuple[str, ...]  # first label text that produced each node
    graph: CSRGraph
    support: dict[tuple[int, int], frozenset[Support]]
    listed: frozenset[int]  # nodes whose own call lists are stored
    index: dict[str, int]  # node id -> position
    by_label: dict[str, tuple[int, ...]]  # sanitized label -> positions


@dataclass(frozen=True)
class CallSnapshot:
    key: str
    data: ProjectInput
    source: SourceInfo
    completeness: Completeness
    older: SideGraph
    newer: SideGraph
    pairs: PairMap
    claims: int
    truncated: bool
    limitations: tuple[str, ...] = field(default=())

    def side(self, side: Side) -> SideGraph:
        return self.older if side == 'older' else self.newer


def snapshot_key(data: ProjectInput, options: SnapshotOptions | None = None) -> str:
    options = options or SnapshotOptions()
    return domain_id('callgraph-cache', 1, {
        'project_id': data.project_id, 'revision': data.revision, 'run_id': data.run_id,
        'raw_sha256': data.raw_sha256, 'raw_status': data.raw.status,
        'older_sha': data.older_sha256, 'newer_sha': data.newer_sha256, 'manual_digest': data.manual_digest,
        'secondary_set_digest': options.secondary_set_digest, 'unified_result_id': options.unified_result_id,
        'patch_rules': options.patch_rules, 'hub_registry_version': options.hub_registry_version,
        'resolve_thunks': options.resolve_thunks, 'algo': ALGO})


class _Builder:
    def __init__(self, resolver: Resolver) -> None:
        self.resolver = resolver
        self.nodes: list[GraphNode] = []
        self.raw: list[str] = []
        self.index: dict[str, int] = {}
        self.edges: dict[tuple[int, int], set[Support]] = {}
        self.dropped = 0

    def node(self, label: str) -> int:
        node = self.resolver.resolve(label)
        position = self.index.get(node.id)
        if position is None:
            position = self.index[node.id] = len(self.nodes)
            self.nodes.append(node)
            self.raw.append(label)
        return position

    def add(self, claim: Claim) -> None:
        caller, callee = self.node(claim.caller), self.node(claim.callee)
        if self.nodes[caller].kind == 'ambiguous':  # which of the same-named functions called it is unknowable
            self.dropped += 1
            return
        self.edges.setdefault((caller, callee), set()).add(claim.support)

    def finish(self, listed_labels: Iterable[str]) -> SideGraph:
        listed = {self.node(label) for label in listed_labels}
        listed = {p for p in listed if self.nodes[p].kind != 'ambiguous'}
        by_label: dict[str, list[int]] = {}
        for position, node in enumerate(self.nodes):
            by_label.setdefault(node.label, []).append(position)
        return SideGraph(
            tuple(self.nodes), tuple(self.raw), build_csr(len(self.nodes), self.edges),
            {edge: frozenset(support) for edge, support in self.edges.items()}, frozenset(listed),
            dict(self.index), {label: tuple(positions) for label, positions in by_label.items()})


def build_snapshot(data: ProjectInput, source: CallSource | None = None,
                   options: SnapshotOptions | None = None, cancel: CancelCheck = None,
                   extra_pairings: Iterable[ExtraOpinion] = ()) -> CallSnapshot:
    source = source or GhidriffListSource(data)
    options = options or SnapshotOptions()
    builders = {side: _Builder(Resolver(data, side, options.resolve_thunks)) for side in SIDES}
    claims, truncated = 0, False
    for side in SIDES:
        for claim in source.claims(side, cancel):
            if claims >= MAX_CLAIMS:
                truncated = True
                break
            claims += 1
            if cancel is not None and claims % CANCEL_CLAIM_INTERVAL == 0 and cancel():
                raise GraphError('PT-GRAPH-CANCEL', 'cancelled')
            builders[side].add(claim)
    graphs = {side: builders[side].finish(source.listed(side)) for side in SIDES}
    labels = {side: set(graphs[side].raw_labels) for side in SIDES}
    dropped = sum(b.dropped for b in builders.values())
    return CallSnapshot(
        snapshot_key(data, options), data, SourceInfo(source_id=source.source_id, version=data.backend_version,
                                                       tier=source.tier),
        source.completeness, graphs['older'], graphs['newer'], PairMap(data, labels, extra_pairings), claims,
        truncated, _limitations(data, source, graphs, truncated, dropped))


def _limitations(data: ProjectInput, source: CallSource, graphs: dict[Side, SideGraph], truncated: bool,
                 dropped: int) -> tuple[str, ...]:
    notes = ['Direct calls only: tail-call jumps and unresolved indirect calls are not listed.']
    if source.completeness == 'changed-set-lists':
        counts = ' and '.join(f'{len(graphs[s].listed)} {s}' for s in SIDES)
        notes.append(f'Not found among the functions with stored call lists ({counts}); '
                     'a missing edge is unknown, not removed.')
    if data.raw.status != 'ok':
        notes.append('Raw Ghidriff matches are not available: unchanged functions are not paired and '
                     'equal non-default labels are inferred.')
    notes.extend(data.raw.notes)
    if truncated:
        notes.append(f'Call claims were capped at {MAX_CLAIMS:,}; the graph is incomplete.')
    if dropped:
        notes.append(f'{dropped} call claims from same-named functions were not attributed to either one.')
    return tuple(sanitize(n, 300) for n in notes)
