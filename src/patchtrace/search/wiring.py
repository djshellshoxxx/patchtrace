"""Production ports of the S8 search groups (WB1 sections 4 and 7): stored tool evidence, advisories, CVE records.

`snapshot_sources(service)` runs on the thread that owns the project store (the CLI thread, or the GUI thread before
each submit) and copies what the `tool:<engine>:<side>`, `adv` and `cve` groups need into a frozen `SourceSnapshot`
of validated values. A search worker receives only a `BoundService` (project, root, snapshot), never a store or a
SQLite connection. A row that cannot be read makes its group `unavailable` with a reason and nothing here raises on
stored data, so an unreadable run is never an empty (and therefore "absent") group. `cve-snapshot` rows are read as
`CveSnapshot` bodies; no production code writes them yet, so that group is usually empty. Qt-free.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from patchtrace.enrichment.contracts import CveSnapshot
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.storage import FACTS_KIND, SOURCE_KIND, AdvisoryStore
from patchtrace.intelligence.tools.common import EVIDENCE_KIND, RUN_KIND
from patchtrace.intelligence.tools.normalize import comparability
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.search.sources.advisory import advisory_specs
from patchtrace.search.sources.base import SourceSpec, skipped
from patchtrace.search.sources.tools import ENGINES, SIDES, tool_specs

CVE_KIND = 'cve-snapshot'
KEY_KINDS = (RUN_KIND, EVIDENCE_KIND, SOURCE_KIND, FACTS_KIND, CVE_KIND)
TOOL_UNREADABLE = 'The stored {title} results for the {side} build could not be read ({error}). Run {title} again.'
ADV_UNREADABLE = 'The stored advisories could not be read ({error}).'
CVE_UNREADABLE = '{count} stored CVE record(s) could not be read, so CVE text is not searchable.'
CVE_FAILED = 'The stored CVE records could not be read ({error}).'


@dataclass(frozen=True, slots=True)
class _ToolRows:
    """`ToolEvidencePort` over copied rows: ((engine, side), (run, evidence)) per produced run."""
    found: tuple[tuple[tuple[str, str], tuple[Any, Any]], ...] = ()

    def latest(self, engine: str, side: str) -> tuple[Any, Any] | None:
        return next((pair for where, pair in self.found if where == (engine, side)), None)


@dataclass(frozen=True, slots=True)
class _Advisories:
    """`AdvisoryPort` over copied `StoredAdvisory` values."""
    items: tuple[Any, ...]
    warnings: tuple[str, ...]

    def advisories(self) -> tuple[tuple[Any, ...], tuple[str, ...]]:
        return self.items, self.warnings


@dataclass(frozen=True, slots=True)
class _Snapshots:
    """`CveSnapshotPort` over copied `CveSnapshot` values."""
    items: tuple[CveSnapshot, ...]

    def snapshots(self) -> tuple[CveSnapshot, ...]:
        return self.items


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    key: tuple | None  # what it was read from (`_key`); None: unknown, so it is never reused
    tools: _ToolRows | None = None
    advisories: _Advisories | None = None
    snapshots: _Snapshots | None = None
    unavailable: tuple[tuple[str, str], ...] = ()  # (group, reason) of groups whose rows could not be read
    comparable_engines: frozenset[str] = frozenset()

    def extra_specs(self, _request=None) -> tuple[SourceSpec, ...]:
        """The six tool groups plus `adv` and `cve` (`SearchService(extra_specs=...)`); in memory, any thread."""
        reasons = dict(self.unavailable)
        specs = tool_specs(self.tools) + advisory_specs(self.advisories, self.snapshots)
        return tuple(skipped(s.group, s.kinds, s.side, 'unavailable', reasons[s.group]) if s.group in reasons else s
                     for s in specs)

    def comparable(self, engine: str) -> bool:
        """Both runs of `engine` are stored and `comparability(older, newer)` finds nothing."""
        return engine in self.comparable_engines


@dataclass(frozen=True, slots=True)
class BoundService:
    """What a search worker gets instead of the `ProjectService`: the `.project` and `.root` `SearchService` reads."""
    project: Any
    root: Path | str
    sources: SourceSnapshot | None = None


def _error(exc: Exception) -> str:
    return str(getattr(exc, 'code', '') or type(exc).__name__)[:40]


def _key(service) -> tuple | None:
    """The project and every row the snapshot reads, as (kind, id, status, created): no body is decoded. The columns
    precede `body`, so SQLite never walks a large body's overflow pages; `entries()` would parse every body."""
    try:
        project, db = service.project, service.store.connection
        marks = ','.join('?' * len(KEY_KINDS))
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='enrichment_entries'").fetchone()
        rows = db.execute(f'SELECT kind, id, status, created FROM enrichment_entries WHERE kind IN ({marks}) '
                          'ORDER BY kind, id', KEY_KINDS).fetchall() if exists else []
        return str(service.root), project.id, project.revision, tuple(rows)
    except (AttributeError, sqlite3.Error):
        return None


def _tools(store: ToolStore, unavailable: list) -> tuple[_ToolRows, frozenset[str]]:
    found = []
    for engine, (title, *_rest) in ENGINES.items():
        for side in SIDES:
            try:
                latest = store.latest(engine, side)
            except Exception as exc:  # fault boundary: one unreadable row must not hide the other groups
                unavailable.append((f'tool:{engine}:{side}',
                                    TOOL_UNREADABLE.format(title=title, side=side, error=_error(exc))))
                continue
            if latest is not None:
                found.append(((engine, side), latest))
    rows = _ToolRows(tuple(found))
    return rows, frozenset(engine for engine in ENGINES if _comparable(rows, engine))


def _comparable(rows: _ToolRows, engine: str) -> bool:
    older, newer = rows.latest(engine, 'older'), rows.latest(engine, 'newer')
    try:
        return older is not None and newer is not None and not comparability(older[0], newer[0])
    except Exception:  # a pair that cannot be compared is not comparable, never a guess
        return False


def _advisories(store: AdvisoryStore, unavailable: list) -> _Advisories | None:
    try:
        items, warnings = store.advisories()
    except Exception as exc:  # fault boundary, as in `_tools`
        unavailable.append(('adv', ADV_UNREADABLE.format(error=_error(exc))))
        return None
    return _Advisories(tuple(items), tuple(warnings))


def _snapshots(enrichment: EnrichmentStore, unavailable: list) -> _Snapshots | None:
    bad: list[str] = []
    try:
        entries = enrichment.entries(CVE_KIND, on_corrupt=bad.append)
    except Exception as exc:  # fault boundary, as in `_tools`
        unavailable.append(('cve', CVE_FAILED.format(error=_error(exc))))
        return None
    found = []
    for entry in entries:
        try:
            found.append(CveSnapshot.model_validate_json(entry.body_json or json.dumps(entry.body)))
        except ValidationError:
            bad.append(entry.id)
    if bad:  # a partial set would let a missing record read as "not mentioned"
        unavailable.append(('cve', CVE_UNREADABLE.format(count=len(bad))))
        return None
    return _Snapshots(tuple(found))


def snapshot_sources(service, reuse: SourceSnapshot | None = None) -> SourceSnapshot:
    """Read the latest run and evidence of every engine and side, the stored advisories with their warnings and the
    `cve-snapshot` rows, on the store's own thread. `reuse` comes back unchanged while none of those rows changed,
    so a keystroke never re-reads evidence bodies. Never raises on stored data."""
    key = _key(service)
    if reuse is not None and key is not None and reuse.key == key:
        return reuse
    store = getattr(service, 'store', None)
    if store is None:  # nothing to read: every group reports its "not available" reason
        return SourceSnapshot(None)
    project, root, enrichment = service.project, Path(service.root), EnrichmentStore(store)
    unavailable: list[tuple[str, str]] = []
    tools, comparable = _tools(ToolStore(enrichment, root, project.id, project.revision), unavailable)
    advisories = _advisories(AdvisoryStore(root, enrichment, project.id, project.revision), unavailable)
    return SourceSnapshot(key, tools, advisories, _snapshots(enrichment, unavailable), tuple(unavailable), comparable)
