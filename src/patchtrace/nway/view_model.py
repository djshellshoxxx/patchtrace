"""Pure view-model for the Series window (SPEC-09b section 5). No Qt.

`load_view` reads a series.json plus one snapshot per pair (through an injected reader) and
builds immutable rows once; `apply_query` filters and sorts them without touching disk.
Per-hop scores are the pair project's stored attention/1 entries, never combined into a
chain-level probability: `max_score` / `sum_score` are display aids only.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from . import series as series_store
from .contracts import BuildRef, ChainEvent, FunctionNode, NwayError, Series
from .pair_access import PairReader, PairSnapshot, PairState

ViewState = Literal['empty', 'loading', 'ready', 'partial', 'stale', 'failed']
ScoreState = Literal['scored', 'unchanged', 'no-ranking', 'pair-unavailable', 'stale-ranking', 'not-ranked']
SortKey = Literal['max-score', 'sum-score', 'hops', 'name', 'chain-id']
MAX_ROWS = 5000
MAX_QUERY_TEXT = 200
EMPTY_MESSAGE = 'No 1:1 chain across 3 or more builds was found in the stored pair results'
_UNAVAILABLE: frozenset[str] = frozenset({'missing', 'unreadable', 'locked', 'mismatch'})
_DEGRADED_SCORES: frozenset[str] = frozenset({'no-ranking', 'stale-ranking', 'pair-unavailable'})


@dataclass(frozen=True)
class HopView:
    from_ordinal: int
    to_ordinal: int
    label: str
    category: str
    match_types: tuple[str, ...]
    ratio_text: str | None
    manual: bool
    from_name: str
    to_name: str
    score: int | None
    rank: int | None
    of: int | None
    score_state: ScoreState
    match_id: str
    pair_state: PairState
    reason: str = ''


@dataclass(frozen=True)
class ChainRow:
    chain_id: str
    title: str
    hops: tuple[HopView, ...]
    status: str
    stale: bool
    weakest_match_type: str
    gaps: tuple[int, ...]
    events: tuple[ChainEvent, ...]
    max_score: int | None
    sum_score: int | None
    scored_hops: int
    total_hops: int
    degraded: bool
    search: str = field(default='', repr=False, compare=False)


@dataclass(frozen=True)
class PairHealth:
    from_ordinal: int
    to_ordinal: int
    state: PairState
    reason: str
    path: str = ''  # relative POSIX path below the series root, from series.json


@dataclass(frozen=True)
class SeriesView:
    state: ViewState
    message: str
    builds: tuple[BuildRef, ...]
    pairs: tuple[PairHealth, ...]
    rows: tuple[ChainRow, ...]
    total_chains: int
    hidden_by_filter: int
    truncated: bool
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class ViewQuery:
    text: str = ''
    status: frozenset[str] = frozenset()
    event: frozenset[str] = frozenset()
    only_stale: bool = False
    only_scored: bool = False
    min_score: int = 0
    sort: SortKey = 'max-score'
    descending: bool = True


@dataclass(frozen=True)
class LoadedSeries:
    """Everything read from disk, already reduced to immutable rows (no rankings are kept)."""
    state: ViewState
    message: str
    builds: tuple[BuildRef, ...] = ()
    pairs: tuple[PairHealth, ...] = ()
    rows: tuple[ChainRow, ...] = ()
    warnings: tuple[str, ...] = ()

    @classmethod
    def failed(cls, message: str) -> LoadedSeries:
        return cls('failed', message)


def _node_name(node: FunctionNode) -> str:
    if node.name is not None:
        return node.name
    return f'0x{node.address:x}' if node.address is not None else ''


def _score(edge, snapshot: PairSnapshot, entries: dict) -> tuple[ScoreState, int | None, int | None]:
    if edge.match_id.startswith('raw:'):
        return 'unchanged', None, None
    if snapshot.state in _UNAVAILABLE:
        return 'pair-unavailable', None, None
    if snapshot.ranking is None:
        return ('stale-ranking' if 'stale' in snapshot.ranking_note else 'no-ranking'), None, None
    entry = entries.get(edge.match_id)
    if entry is None:
        return 'not-ranked', None, None
    return 'scored', entry.score, entry.rank


def _hop(edge, labels: dict[int, str], snapshot: PairSnapshot, entries: dict, total: int) -> HopView:
    state, score, rank = _score(edge, snapshot, entries)
    return HopView(
        from_ordinal=edge.from_node.ordinal, to_ordinal=edge.to_node.ordinal,
        label=f'{labels[edge.from_node.ordinal]} -> {labels[edge.to_node.ordinal]}',
        category=edge.category, match_types=tuple(edge.match_types), ratio_text=edge.ratio_text, manual=edge.manual,
        from_name=_node_name(edge.from_node), to_name=_node_name(edge.to_node),
        score=score, rank=rank, of=total if score is not None else None, score_state=state,
        match_id=edge.match_id, pair_state=snapshot.state, reason=snapshot.reason or snapshot.ranking_note)


def _row(chain, hops: tuple[HopView, ...], stale: bool) -> ChainRow:
    scores = [h.score for h in hops if h.score is not None]
    title = next((_node_name(n) for n in chain.nodes if _node_name(n)), chain.chain_id[:12])
    haystack = ' '.join([chain.chain_id, *(h.label for h in hops), *(h.from_name for h in hops),
                         *(h.to_name for h in hops), *(f'{n.address:x}' for n in chain.nodes if n.address is not None)])
    return ChainRow(
        chain_id=chain.chain_id, title=title, hops=hops, status=chain.status, stale=stale,
        weakest_match_type=chain.weakest_match_type, gaps=tuple(chain.gaps), events=tuple(chain.events),
        max_score=max(scores) if scores else None, sum_score=sum(scores) if scores else None,
        scored_hops=len(scores), total_hops=len(hops),
        degraded=any(h.pair_state != 'ok' or h.score_state in _DEGRADED_SCORES for h in hops),
        search=haystack.casefold())


def _derive_state(series: Series, pairs: tuple[PairHealth, ...], reasons: tuple[str, ...],
                  rows: tuple[ChainRow, ...]) -> tuple[ViewState, str]:
    if not series.chains:
        return 'empty', EMPTY_MESSAGE
    problems = [f'pair {p.from_ordinal}->{p.to_ordinal}: {p.reason or p.state}' for p in pairs if p.state != 'ok']
    if reasons and pairs and not any(p.state == 'ok' for p in pairs):
        return 'stale', 'Stored chains are out of date for: ' + '; '.join(problems or reasons)
    if problems or any(r.degraded for r in rows):
        return 'partial', '; '.join(problems) or 'some hops have no usable ranking'
    return 'ready', ''


def load_view(series_path: Path, reader: PairReader, cancel: threading.Event) -> LoadedSeries:
    """Read series.json and one snapshot per pair. Per-pair problems never raise."""
    try:
        series = series_store.load(series_path)
    except NwayError as exc:
        return LoadedSeries.failed(str(exc))
    root = Path(series_path).resolve().parent
    hashes = [b.artifact_sha256 for b in series.builds]
    labels = {b.ordinal: b.label for b in series.builds}
    staleness = series_store.staleness(series, series_path)
    wanted: dict[int, set[str]] = {}
    for chain in series.chains:
        for edge in chain.edges:
            if not edge.match_id.startswith('raw:'):
                wanted.setdefault(edge.from_node.ordinal, set()).add(edge.match_id)
    snapshots: dict[int, PairSnapshot] = {}
    for ref in series.pair_projects:
        if cancel.is_set():
            raise NwayError('PT-NWAY-CANCEL', 'loading the series was cancelled')
        i = ref.from_ordinal
        snapshots[i] = reader.read(root, ref, hashes[i], hashes[i + 1], frozenset(wanted.get(i, ())))
    if cancel.is_set():
        raise NwayError('PT-NWAY-CANCEL', 'loading the series was cancelled')
    # A locked pair cannot be compared with its recorded revision: unknown, so degraded, not stale.
    locked = {i for i, s in snapshots.items() if s.state == 'locked'}
    last = len(series.builds) - 1
    # The direct pair has no snapshot; its lock shows only in the staleness reason.
    direct_prefix = f'pair 0→{last}: cannot open'
    direct_locked = staleness.direct and any(
        r.startswith(direct_prefix) and 'locked' in r.lower() for r in staleness.reasons)
    effective = series_store.Staleness(staleness.pairs - locked, staleness.direct and not direct_locked, tuple(
        r for r in staleness.reasons
        if not any(r.startswith(f'pair {i}→{i + 1}:') for i in locked)
        and not (direct_locked and r.startswith(direct_prefix))))
    entries = {i: ({e.match_id: e for e in s.ranking.entries} if s.ranking is not None else {})
               for i, s in snapshots.items()}
    totals = {i: (len(s.ranking.entries) if s.ranking is not None else 0) for i, s in snapshots.items()}
    rows = tuple(_row(chain, tuple(_hop(edge, labels, snapshots[edge.from_node.ordinal],
                                        entries[edge.from_node.ordinal], totals[edge.from_node.ordinal])
                                   for edge in chain.edges), effective.chain_stale(chain, last))
                 for chain in series.chains)
    pairs = tuple(PairHealth(r.from_ordinal, r.to_ordinal, snapshots[r.from_ordinal].state,
                             snapshots[r.from_ordinal].reason, r.path) for r in series.pair_projects)
    state, message = _derive_state(series, pairs, effective.reasons, rows)
    return LoadedSeries(state, message, series.builds, pairs, rows, effective.reasons)


def _matches(row: ChainRow, query: ViewQuery, needle: str) -> bool:
    if needle and needle not in row.search:
        return False
    if query.status and row.status not in query.status:
        return False
    if query.event and not any(e.kind in query.event for e in row.events):
        return False
    if query.only_stale and not row.stale:
        return False
    if (query.only_scored or query.min_score > 0) and row.max_score is None:
        return False
    return not (query.min_score > 0 and (row.max_score or 0) < query.min_score)


def _sorted(rows: list[ChainRow], query: ViewQuery) -> list[ChainRow]:
    rows.sort(key=lambda r: r.chain_id)  # stable base order: ties always resolve by chain id ascending
    key = query.sort
    if key == 'chain-id':
        rows.sort(key=lambda r: r.chain_id, reverse=query.descending)
        return rows
    if key in {'max-score', 'sum-score'}:
        scored = [r for r in rows if r.max_score is not None]
        unscored = [r for r in rows if r.max_score is None]
        scored.sort(key=(lambda r: (r.max_score, r.sum_score)) if key == 'max-score'
                    else (lambda r: (r.sum_score, r.max_score)), reverse=query.descending)
        return scored + unscored
    rows.sort(key=(lambda r: r.total_hops) if key == 'hops' else (lambda r: r.title.casefold()),
              reverse=query.descending)
    return rows


def apply_query(loaded: LoadedSeries, query: ViewQuery) -> SeriesView:
    """Filter and sort the loaded rows; pure and deterministic for identical inputs."""
    needle = query.text[:MAX_QUERY_TEXT].strip().casefold()
    matched = [r for r in loaded.rows if _matches(r, query, needle)]
    ordered = _sorted(matched, query)
    return SeriesView(
        state=loaded.state, message=loaded.message, builds=loaded.builds, pairs=loaded.pairs,
        rows=tuple(ordered[:MAX_ROWS]), total_chains=len(loaded.rows),
        hidden_by_filter=len(loaded.rows) - len(matched), truncated=len(ordered) > MAX_ROWS,
        warnings=loaded.warnings)


def chain_text(row: ChainRow, builds: tuple[BuildRef, ...]) -> str:
    """Plain-text copy of one chain: labels, ordinals and the first 12 hex of each build hash."""
    lines = [f'Chain {row.chain_id[:12]} ({row.status}{", stale" if row.stale else ""}); '
             'inferred hypothesis across independent pairwise results']
    lines += [f'  build {b.ordinal}: {b.label} sha256:{b.artifact_sha256[:12]}' for b in builds]
    for hop in row.hops:
        score = f'attention {hop.score}' if hop.score is not None else hop.score_state
        lines.append(f'  {hop.from_ordinal}->{hop.to_ordinal} {hop.label}: {hop.from_name} -> {hop.to_name} '
                     f'[{hop.category}; {score}]')
    return '\n'.join(lines)
