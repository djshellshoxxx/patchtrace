"""One current secondary match set per engine (SPEC-28 §6.1). Over EnrichmentStore; no Qt.

`secondary/2` ids omit the output hash, so re-running an engine upserts the same row. Legacy
`secondary/1` rows are never deleted or rewritten; they are simply ignored on read when a newer
row for the same engine exists.
"""
from __future__ import annotations

import json

from ..enrichment.contracts import EnrichmentError
from ..enrichment.storage import EnrichmentStore, Entry, Guard
from . import load_secondary
from .contracts import KIND, SecondaryMatchSet
from .runs import RUN_KIND, EngineRun, as_v2

ENGINE_ORDER = {'rz-diff': 0, 'bindiff': 1}
Row = tuple[Entry, SecondaryMatchSet]


def publish_engine_set(store: EnrichmentStore, guard: Guard, current: Guard, revision: int,
                       match_set: SecondaryMatchSet) -> Entry:
    """Upsert the engine's current set; earlier history stays in EngineRun rows."""
    if match_set.contract != 'secondary/2':
        match_set = as_v2(match_set)
    return store.publish(KIND, guard, current, revision, 'complete', match_set.model_dump(mode='json'),
                         match_set.entry_id)


def select_current(rows: list[Row], pair: tuple[str, str] | None = None) -> tuple[list[Row], list[str]]:
    """Newest non-stale row per engine (ties: higher entry id) plus notes naming superseded rows.

    With `pair` (older, newer SHA-256) a row for that pair beats a newer row for another pair; an engine with no
    row for the pair still yields its newest row so the caller can show it as stale."""
    live = sorted(((e, m) for e, m in rows if not e.stale),
                  key=lambda v: ((v[1].older_sha256, v[1].newer_sha256) == pair, v[0].created, v[0].id), reverse=True)
    chosen: dict[str, Row] = {}
    notes: list[str] = []
    for entry, match_set in live:
        winner = chosen.get(match_set.engine)
        if winner is None:
            chosen[match_set.engine] = (entry, match_set)
        elif (winner[1].older_sha256, winner[1].newer_sha256) == (match_set.older_sha256, match_set.newer_sha256):
            notes.append(f'{match_set.engine}: entry {winner[0].id} supersedes {entry.id}')
        else:
            notes.append(f'{match_set.engine}: ignored entry {entry.id} for a different artifact pair')
    ordered = sorted(chosen.values(), key=lambda v: ENGINE_ORDER.get(v[1].engine, len(ENGINE_ORDER)))
    return ordered, notes


def current_sets(store: EnrichmentStore, current: Guard | None = None,
                 pair: tuple[str, str] | None = None) -> list[Row]:
    return select_current(load_secondary(store, current), pair)[0]


def publish_run(store: EnrichmentStore, guard: Guard, current: Guard, revision: int, run: EngineRun) -> Entry:
    """Append one EngineRun row (ids are unique per attempt, so rows are never overwritten)."""
    entry = store.publish(RUN_KIND, guard, current, revision, 'complete', run.model_dump(mode='json'), run.run_id)
    store.prune_runs()  # best-effort retention: newest RUN_KEEP per engine/pair, sets never touched
    return entry


def cache_snapshot(store: EnrichmentStore, older_sha256: str, newer_sha256: str,
                   current: Guard | None = None) -> dict[str, SecondaryMatchSet]:
    """In-memory cache_key -> re-validated stored set. Built on the caller's thread because the
    project database connection must not be shared with scheduler workers; any bad row is skipped."""
    found: dict[str, SecondaryMatchSet] = {}
    try:
        sets = {e.id: m for e, m in load_secondary(store, current) if not e.stale}
        entries = store.entries(RUN_KIND, current, on_corrupt=lambda _id: None)
    except (ValueError, EnrichmentError):
        return found  # PT-SECONDARY-CACHE: unreadable rows are a miss, never fatal
    for entry in reversed(entries):  # oldest first so the newest valid row wins
        try:
            run = EngineRun.model_validate_json(json.dumps(entry.body))
        except ValueError:
            continue
        match_set = sets.get(run.match_set_id or '')
        if (not entry.stale and run.status in ('ok', 'cached') and match_set is not None
                and (match_set.older_sha256, match_set.newer_sha256) == (older_sha256, newer_sha256)
                and match_set.file_sha256 == run.output_sha256):
            found[run.cache_key] = match_set
    return found


def find_cached(store: EnrichmentStore, key: str, older_sha256: str, newer_sha256: str,
                current: Guard | None = None) -> SecondaryMatchSet | None:
    return cache_snapshot(store, older_sha256, newer_sha256, current).get(key)
