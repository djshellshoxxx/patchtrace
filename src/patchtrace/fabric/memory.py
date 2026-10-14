"""In-memory sink and reader, and the null implementations (FAB-integration-plan.md s7).

`MemoryAnchorStore` is the reference behaviour of both ports for tests and until the enrichment-backed store lands
(FAB-1): the same publish, replace, merge, find and resolve semantics, held in plain dicts. Every state is replaced
whole, never edited in place, so a reader that holds a snapshot never sees a half-applied publish; writers take a lock.
`NullAnchorSink` and `NullAnchorReader` answer "nothing here", so a track that publishes or reads anchors never waits
for another one.
"""
from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping, Sequence

from .contracts import (
    CODE_EVIDENCE_KINDS,
    KINDS,
    PRODUCERS,
    PROJECT_ID,
    ROLES,
    SHA256_RE,
    SIDES,
    Anchor,
    AnchorPage,
    AnchorQuery,
    PublishReport,
    Resolution,
)
from .ids import (
    anchor_id,
    anchors_digest,
    check_orientation,
    key_for_value,
    pair_members,
    verify_anchor,
)
from .limits import DEFAULT_LIMITS, FabricError, FabricLimits
from .origins import DefaultOriginRegistry, check_origins
from .ports import OriginRegistry

_KIND_ORDER = {name: index for index, name in enumerate(KINDS)}
_SIDE_ORDER = {name: index for index, name in enumerate(SIDES)}
_ROLE_ORDER = {name: index for index, name in enumerate(ROLES)}
_EMPTY: Mapping[str, Anchor] = {}


def _input(message: str, reason: str) -> FabricError:
    return FabricError('PT-FAB-INPUT', message, reason=reason)


def _project(project_key: object) -> str:
    if not isinstance(project_key, str) or not PROJECT_ID.fullmatch(project_key):
        raise _input('The project key is not a project id', 'project-key')
    return project_key


def _order(anchor: Anchor) -> tuple:
    """Canonical order: kind, key, side, role, subject (none first), id."""
    return (_KIND_ORDER[anchor.kind], anchor.key, _SIDE_ORDER[anchor.side], _ROLE_ORDER[anchor.role],
            anchor.subject or '', anchor.anchor_id)


def _without(before: Mapping[str, Anchor], touched: set[tuple[str, str]]) -> tuple[dict[str, Anchor], set[str]]:
    """The state minus every witness of the touched (producer, batch) pairs, and the ids of anchors that changed."""
    state: dict[str, Anchor] = {}
    changed: set[str] = set()
    for key, anchor in before.items():
        kept = tuple(w for w in anchor.witnesses if (w.producer, w.batch) not in touched)
        if len(kept) == len(anchor.witnesses):
            state[key] = anchor
            continue
        changed.add(key)
        if kept:
            state[key] = anchor.model_copy(update={'witnesses': kept})
    return state, changed


def _union(current: Anchor, new: Anchor) -> Anchor:
    by_id = {w.witness_id: w for w in current.witnesses}
    by_id.update((w.witness_id, w) for w in new.witnesses)
    if len(by_id) == len(current.witnesses):
        return current
    return current.model_copy(update={'witnesses': tuple(by_id[key] for key in sorted(by_id))})


def _merge(state: dict[str, Anchor], batch: Iterable[Anchor], max_witnesses: int) -> None:
    for anchor in batch:
        current = state.get(anchor.anchor_id)
        merged = anchor if current is None else _union(current, anchor)
        if len(merged.witnesses) > max_witnesses:
            raise FabricError('PT-FAB-LIMIT', 'An anchor would hold more witnesses than allowed', reason='witnesses')
        state[anchor.anchor_id] = merged


def _report(before: Mapping[str, Anchor], after: Mapping[str, Anchor], affected: Iterable[str]) -> PublishReport:
    counts = {'added': 0, 'merged': 0, 'unchanged': 0, 'removed': 0}
    for key in set(affected):
        old, new = before.get(key), after.get(key)
        if old is None and new is not None:
            counts['added'] += 1
        elif old is not None and new is None:
            counts['removed'] += 1
        elif old is not None and new is not None:
            counts['unchanged' if old.witnesses == new.witnesses else 'merged'] += 1
    return PublishReport(**counts)


def _on_side(anchor: Anchor, side: str | None) -> bool:
    """Present on a side: older or newer also matches an anchor seen on both; both and none match exactly."""
    if side is None:
        return True
    return anchor.side in (side, 'both') if side in ('older', 'newer') else anchor.side == side


def _named(anchor: Anchor, name: str) -> bool:
    return any(facet == ('name', name) for witness in anchor.witnesses for facet in witness.facets)


class MemoryAnchorStore:
    """`AnchorSink` and `AnchorReader` in memory. `limits` may tighten the counts (F-01, F-02, F-03, F-09, F-12); the
    shape caps are fixed by the contract models. `bind_pair` tells the store which images a project compares, which
    switches on the orientation check (without it a store cannot tell a swapped pair from a right one)."""

    def __init__(self, registry: OriginRegistry | None = None, limits: FabricLimits = DEFAULT_LIMITS):
        self._registry = DefaultOriginRegistry() if registry is None else registry
        self._limits = limits
        self._projects: dict[str, Mapping[str, Anchor]] = {}
        self._pairs: dict[str, tuple[str, str]] = {}
        self._lock = threading.Lock()

    def bind_pair(self, project_key: str, older_sha256: str, newer_sha256: str) -> None:
        key = _project(project_key)
        if not all(isinstance(sha, str) and SHA256_RE.fullmatch(sha) for sha in (older_sha256, newer_sha256)):
            raise _input('A project pair is two SHA-256 digests, older first', 'pair-sha256')
        self._pairs[key] = (older_sha256, newer_sha256)

    # --- AnchorSink -------------------------------------------------------------------------------------------------

    def publish(self, project_key: str, anchors: Sequence[Anchor]) -> PublishReport:
        key = _project(project_key)
        batch = self._accept(key, anchors)
        touched = {(w.producer, w.batch) for anchor in batch for w in anchor.witnesses}
        return self._replace(key, touched, batch)

    def retract(self, project_key: str, producer: str, batch: str) -> PublishReport:
        key = _project(project_key)
        if producer not in PRODUCERS or not isinstance(batch, str):
            raise _input('A batch is named by a known producer and a batch name', 'batch')
        return self._replace(key, {(producer, batch)}, ())

    def _accept(self, key: str, anchors: Sequence[Anchor]) -> tuple[Anchor, ...]:
        try:
            batch = tuple(anchors)
        except TypeError:
            raise _input('Anchors must be a sequence of anchor records', 'anchors-not-iterable') from None
        if len(batch) > self._limits.f01_anchors_per_publish:
            raise FabricError('PT-FAB-LIMIT', 'A publish call carries more anchors than allowed', reason='publish-size')
        pair = self._pairs.get(key)
        for anchor in batch:
            if not isinstance(anchor, Anchor):
                raise _input('Only anchor records can be published', 'not-an-anchor')
            verify_anchor(anchor)
            check_origins(anchor, self._registry)
            if pair is not None:
                check_orientation(anchor, *pair)
        return batch

    def _replace(self, key: str, touched: set[tuple[str, str]], batch: Iterable[Anchor]) -> PublishReport:
        batch = tuple(batch)
        with self._lock:
            before = self._projects.get(key, _EMPTY)
            after, purged = _without(before, touched)
            _merge(after, batch, self._limits.f03_witnesses_per_anchor)
            if len(after) > self._limits.f02_anchors_per_project:
                raise FabricError('PT-FAB-LIMIT', 'The project would hold more anchors than allowed',
                                  reason='project-size')
            if after:
                self._projects[key] = after
            else:
                self._projects.pop(key, None)
        return _report(before, after, {*purged, *(anchor.anchor_id for anchor in batch)})

    # --- AnchorReader -----------------------------------------------------------------------------------------------

    def get(self, project_key: str, anchor_id: str) -> Anchor | None:
        anchors = self._projects.get(_project(project_key), _EMPTY)
        return anchors.get(anchor_id) if isinstance(anchor_id, str) else None

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        anchors = self._projects.get(_project(project_key), _EMPTY)
        if not isinstance(query, AnchorQuery):
            raise _input('A query is an AnchorQuery', 'query')
        subjects = self._subjects(anchors, query.subject)
        rows = sorted((a for a in anchors.values() if self._matches(a, query, subjects)), key=_order)
        limit = min(query.limit, self._limits.f09_page_rows)
        return AnchorPage(tuple(rows[query.offset:query.offset + limit]), len(rows))

    def resolve(self, project_key: str, kind: str, value: str | None, side: str | None) -> Resolution:
        anchors = self._projects.get(_project(project_key), _EMPTY)
        if kind not in KINDS:
            raise FabricError('PT-FAB-KIND', 'Unknown anchor kind', reason='kind')
        if side is not None and side not in SIDES:
            raise _input('Unknown side', 'side')
        key = None if value is None else key_for_value(kind, value)
        by_name = value is not None and key is None  # a function name, matched against the facet `name`

        def wanted(anchor: Anchor) -> bool:
            if anchor.kind != kind or not _on_side(anchor, side):
                return False
            if kind in CODE_EVIDENCE_KINDS and anchor.role != 'observed':
                return False  # a hint or a statement is not something found in the code
            return _named(anchor, value) if by_name else key is None or anchor.key == key

        rows = sorted((a for a in anchors.values() if wanted(a)), key=_order)
        if not rows:
            return Resolution('unknown')
        if len(rows) == 1:
            return Resolution('found', rows[0].anchor_id, rows[0].label, (), 1)
        candidates = tuple(a.anchor_id for a in rows[:self._limits.f12_resolve_candidates])
        return Resolution('ambiguous', None, None, candidates, len(rows))

    def digest(self, project_key: str) -> str:
        """Order-independent digest of everything stored for a project (for tests and cache keys)."""
        return anchors_digest(self._projects.get(_project(project_key), _EMPTY).values())

    @staticmethod
    def _subjects(anchors: Mapping[str, Anchor], subject: str | None) -> frozenset[str] | None:
        """The subjects a query matches: the one asked for and, for a pair that is stored, its member image functions."""
        if subject is None:
            return None
        pair = anchors.get(anchor_id('function', subject, 'both', 'observed', None))
        members = pair_members(pair.pair) if pair is not None and pair.pair is not None else ()
        return frozenset((subject, *members))

    @staticmethod
    def _matches(anchor: Anchor, query: AnchorQuery, subjects: frozenset[str] | None) -> bool:
        return ((query.kind is None or anchor.kind == query.kind)
                and (query.key is None or anchor.key == query.key)
                and (query.side is None or anchor.side == query.side)
                and (query.role is None or anchor.role == query.role)
                and (subjects is None or anchor.subject in subjects)
                and (query.producer is None or any(w.producer == query.producer for w in anchor.witnesses)))


class NullAnchorSink:
    """Accepts every call and stores nothing."""

    def publish(self, project_key: str, anchors: Sequence[Anchor]) -> PublishReport:
        return PublishReport()

    def retract(self, project_key: str, producer: str, batch: str) -> PublishReport:
        return PublishReport()


class NullAnchorReader:
    """Knows nothing: there is no fabric behind it, so `resolve` says `unsupported`."""

    def get(self, project_key: str, anchor_id: str) -> Anchor | None:
        return None

    def find(self, project_key: str, query: AnchorQuery) -> AnchorPage:
        return AnchorPage((), 0)

    def resolve(self, project_key: str, kind: str, value: str | None, side: str | None) -> Resolution:
        return Resolution('unsupported')
