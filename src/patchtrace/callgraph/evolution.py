"""A7 N-way evolution: how one function's callee neighbourhood changes across a series of builds."""
from __future__ import annotations

from collections.abc import Sequence
from typing import NamedTuple

from ..enrichment.identity import domain_id
from .contracts_evolution import (
    CalleeLineage,
    Cell,
    Inconsistency,
    LineageEvent,
    NeighbourhoodEvolution,
    OrdinalDigest,
)
from .limits import CancelCheck, GraphError
from .pair_calls import Direction, PairCalls
from .text import sanitize

MAX_BUILDS = 8  # GL-09
MIN_BUILDS = 3
MAX_LINEAGES = 2_000


class BuildCallees(NamedTuple):
    """What the stored records say about one build's callee set for the focus function."""
    labels: frozenset[str] | None  # None = no record anywhere: unknown, never empty
    conflict: frozenset[str]  # labels the two records of this build disagree on
    digest: str | None


class Hop(NamedTuple):
    label: str | None
    state: str  # ok | gone | unknown


def _digest(labels: frozenset[str]) -> str:
    return domain_id('callgraph-callee-set', 1, sorted(labels))


def _build_callees(ordinal: int, focus: Sequence[str | None], pairs: Sequence[PairCalls | None],
                   inconsistencies: list[Inconsistency]) -> BuildCallees:
    label = focus[ordinal]
    as_newer = pairs[ordinal - 1].callees('newer', label) if label and ordinal > 0 and pairs[ordinal - 1] else None
    as_older = (pairs[ordinal].callees('older', label)
                if label and ordinal < len(pairs) and pairs[ordinal] else None)
    if as_newer is not None and as_older is not None and as_newer != as_older:
        differ = as_newer ^ as_older
        inconsistencies.append(Inconsistency(
            kind='same-build-callees-differ', ordinal=ordinal,
            detail=sanitize(f'the two pair records of this build list different callees: {len(differ)} differ '
                            f'(digests {_digest(as_newer)[:12]} and {_digest(as_older)[:12]})', 512)))
        return BuildCallees(as_newer & as_older, differ, _digest(as_newer))
    found = as_newer if as_newer is not None else as_older
    return BuildCallees(found, frozenset(), None if found is None else _digest(found))


def _walk(pairs: Sequence[PairCalls | None], start: int, label: str, count: int) -> list[Hop | None]:
    """The callee's label in every build, following 1:1 pairs both ways from its anchor build."""
    hops: list[Hop | None] = [None] * count
    hops[start] = Hop(label, 'ok')
    walks: tuple[tuple[Direction, range], ...] = (('forward', range(start, count - 1)),
                                                  ('backward', range(start - 1, -1, -1)))
    for direction, indices in walks:
        current: str | None = label
        state = 'ok'
        for i in indices:
            pair = pairs[i]
            if state == 'ok':
                if pair is None:
                    state = 'unknown'
                else:
                    step = pair.step(direction, current)
                    current, state = step.label, {'mapped': 'ok'}.get(step.status, step.status)
            hops[i + 1 if direction == 'forward' else i] = Hop(current, state)
    return hops


def _cell(hop: Hop, known: BuildCallees) -> Cell:
    if hop.state == 'gone':
        return 'absent'
    if hop.state == 'unknown' or known.labels is None or hop.label in known.conflict:
        return 'unknown'
    return 'present' if hop.label in known.labels else 'absent'


def _events(cells: Sequence[Cell]) -> tuple[LineageEvent, ...]:
    events = []
    seen_present = cells[0] == 'present'
    for i in range(1, len(cells)):
        before, now = cells[i - 1], cells[i]  # only two adjacent known cells make a statement
        if before == 'present' and now == 'absent':
            events.append(LineageEvent(kind='dropped', ordinal=i))
        elif before == 'absent' and now == 'present':
            events.append(LineageEvent(kind='reverted' if seen_present else 'appeared', ordinal=i))
        seen_present = seen_present or now == 'present'
    return tuple(events)


def _lineage(series_id: str, chain_id: str, anchor: tuple[int, str], hops: list[Hop | None],
             known: Sequence[BuildCallees]) -> CalleeLineage:
    cells = tuple(_cell(hop, known[i]) for i, hop in enumerate(hops) if hop is not None)
    labels = tuple(None if hop.state != 'ok' else sanitize(hop.label) for hop in hops if hop is not None)
    lineage_id = domain_id('callgraph-lineage', 1, {'series': series_id, 'chain': chain_id,
                                                    'anchor': [anchor[0], anchor[1]]})
    return CalleeLineage(id=lineage_id, labels_by_ordinal=labels, cells=cells, events=_events(cells))


def _limitations(pairs: Sequence[PairCalls | None], known: Sequence[BuildCallees]) -> tuple[str, ...]:
    notes = []
    missing = [str(i) for i, pair in enumerate(pairs) if pair is None]
    if missing:
        notes.append(f'pair project(s) {", ".join(missing)} unavailable: their builds and callees are unknown')
    bare = [str(i) for i, pair in enumerate(pairs) if pair is not None and not pair.has_raw_matches]
    if bare:
        notes.append(f'pair(s) {", ".join(bare)} have no raw matches: only emitted pairs map callees across builds')
    blind = [str(i) for i, item in enumerate(known) if item.labels is None]
    if blind:
        notes.append(f'build(s) {", ".join(blind)} have no stored record of the function: callee cells are unknown')
    return tuple(notes)


def build_evolution(series_id: str, chain_id: str, build_labels: Sequence[str], focus: Sequence[str | None],
                    pairs: Sequence[PairCalls | None], cancel: CancelCheck = None) -> NeighbourhoodEvolution:
    """`focus[k]` is the function's label in build k (None = no name there); `pairs[k]` is pair (k, k+1)
    or None when that pair project is unavailable. Pure: reads nothing, opens nothing."""
    count = len(build_labels)
    if not MIN_BUILDS <= count <= MAX_BUILDS:
        raise GraphError('PT-GRAPH-LIMIT', f'evolution needs {MIN_BUILDS} to {MAX_BUILDS} builds, got {count}')
    if len(focus) != count or len(pairs) != count - 1:
        raise GraphError('PT-GRAPH-INPUT', 'evolution needs one focus label per build and one pair per adjacent builds')
    inconsistencies: list[Inconsistency] = []
    known = [_build_callees(i, focus, pairs, inconsistencies) for i in range(count)]
    anchored: set[tuple[int, str]] = set()
    lineages: list[CalleeLineage] = []
    truncated = False
    for ordinal, item in enumerate(known):
        for label in sorted((item.labels or frozenset()) | item.conflict):
            if (ordinal, label) in anchored:
                continue
            if cancel is not None and cancel():
                raise GraphError('PT-GRAPH-CANCEL', 'evolution cancelled')
            if len(lineages) >= MAX_LINEAGES:
                truncated = True
                break
            hops = _walk(pairs, ordinal, label, count)
            for i, hop in enumerate(hops):
                if hop is not None and hop.state == 'ok' and hop.label is not None:
                    anchored.add((i, hop.label))
            lineages.append(_lineage(series_id, chain_id, (ordinal, label), hops, known))
    notes = _limitations(pairs, known)
    if truncated:
        notes += (f'more than {MAX_LINEAGES} callee lineages: the list is cut',)
    return NeighbourhoodEvolution(
        series_id=series_id, chain_id=chain_id, builds=tuple(sanitize(b, 64) for b in build_labels),
        focus_labels=tuple(None if name is None else sanitize(name) for name in focus),
        lineages=tuple(lineages),
        digest_by_ordinal=tuple(OrdinalDigest(ordinal=i, digest=k.digest) for i, k in enumerate(known)
                                if k.digest is not None),
        inconsistencies=tuple(inconsistencies), truncated=truncated, limitations=notes)
