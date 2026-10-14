"""Orchestration of the KEV catalog lifecycle (KEV-integration-plan sections 7 and 8). No Qt, no sqlite.

The network step is an injected ``fetch(plan) -> Fetched`` so this module never opens a socket itself: ``plan`` does no
network and no DNS, ``fetch_catalog`` runs one consented download then parses, checks for shrinkage and installs, and
``import_file`` reads a file the analyst saved. Parsing happens only after a download completed, never during it.
"""
from __future__ import annotations

import datetime
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from . import limits
from .contracts import ConsentRecord, KevCatalog, KevDelta, KevError, KevPlan
from .join import diff, freshness
from .parse import parse_catalog
from .store import Installed, KevStore, Loaded
from .transport import Fetched, KevConsent

MAX_SNAPSHOT_FILE_BYTES = 8 * 1024 * 1024
Clock = Callable[[], datetime.datetime]


def utc_stamp(now: datetime.datetime) -> str:
    return now.astimezone(datetime.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')


def plan(source: str) -> KevPlan:
    """The exact request that would be sent. Pure: no network and no DNS."""
    return KevPlan.for_source(source)


def consent_for(kev_plan: KevPlan, hosts: Iterable[str]) -> KevConsent:
    """Operation-specific consent: the named hosts must be exactly the plan's host."""
    named = {host.strip().lower() for host in hosts if host.strip()}
    if named != {kev_plan.host}:
        raise KevError('PT-KEV-CONSENT', f'consent must name exactly {kev_plan.host}')
    return KevConsent.from_plan(kev_plan)


@dataclass(frozen=True)
class Outcome:
    catalog: KevCatalog
    installed: Installed


def _check_shrink(store: KevStore, new: KevCatalog, accept_shrink: bool) -> None:
    current = store.load_current()
    if current is None or accept_shrink or new.meta.date_released < current.catalog.meta.date_released:
        return
    before, after = current.catalog.meta.entry_count, new.meta.entry_count
    if after * 100 < before * limits.SHRINK_FLOOR_PERCENT:
        raise KevError('PT-KEV-SHRINK', f'the new catalog has {before - after} fewer entries than the one in use')


def fetch_catalog(store: KevStore, kev_plan: KevPlan, fetch: Callable[[KevPlan], Fetched], now: Clock, *,
                  accept_shrink: bool = False, surface: str = 'cli') -> Outcome:
    fetched = fetch(kev_plan)
    stamp = utc_stamp(now())
    consent = ConsentRecord(operation='fetch-kev-catalog', source=kev_plan.source, url=kev_plan.url,
                            plan_sha=kev_plan.plan_sha, granted_at=stamp, surface=surface)
    catalog = parse_catalog(fetched.body, source=kev_plan.source, retrieved_at=fetched.retrieved_at,
                            source_url=fetched.url, final_url=fetched.final_url, consent=consent)
    _check_shrink(store, catalog, accept_shrink)
    return Outcome(catalog, store.install(catalog, fetched.body, stamp))


def read_file(path: Path, cap: int = limits.MAX_BYTES) -> bytes:
    try:
        if path.stat().st_size > cap:
            raise KevError('PT-KEV-LIMIT', 'the file is larger than its size limit')
        with path.open('rb') as stream:
            data = stream.read(cap + 1)
    except OSError:
        raise KevError('PT-KEV-INPUT', 'the file cannot be read') from None
    if len(data) > cap:
        raise KevError('PT-KEV-LIMIT', 'the file is larger than its size limit')
    return data


def import_file(store: KevStore, path: Path, now: Clock) -> Outcome:
    raw = read_file(path)
    stamp = utc_stamp(now())
    catalog = parse_catalog(raw, source='local-import', retrieved_at=stamp, file_name=path.name)
    return Outcome(catalog, store.install(catalog, raw, stamp))


def open_catalog_file(path: Path, now: Clock) -> KevCatalog:
    """Parse a catalog file for one lookup without storing it."""
    return parse_catalog(read_file(path), source='local-import', retrieved_at=utc_stamp(now()), file_name=path.name)


@dataclass(frozen=True)
class Status:
    loaded: Loaded | None
    freshness: str
    age_days: int | None
    older_than_limit: bool


def status(store: KevStore, now: Clock, max_age_days: int | None = None) -> Status:
    loaded = store.load_current()
    state, days = freshness(loaded.catalog.meta if loaded else None, now())
    over = bool(max_age_days is not None and days is not None and days > max_age_days)
    return Status(loaded, state, days, over)


def cve_ids_from_snapshot_file(path: Path) -> list[str]:
    """CVE IDs of a saved ``cve-snapshot`` JSON file (one object or a list of objects with a ``cve_id``)."""
    try:
        data = json.loads(read_file(path, MAX_SNAPSHOT_FILE_BYTES).decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise KevError('PT-KEV-FORMAT', 'the CVE snapshot file is not JSON') from None
    items = data if isinstance(data, list) else [data]
    ids = [item.get('cve_id') for item in items if isinstance(item, dict)]
    found = [cve for cve in ids if isinstance(cve, str)]
    if not found:
        raise KevError('PT-KEV-FORMAT', 'the CVE snapshot file holds no cve_id')
    return found


def gather_cves(cves: Iterable[str], snapshot_files: Iterable[Path]) -> list[str]:
    """Typed IDs first, then snapshot IDs, each distinct raw spelling once; at most 5,000."""
    out = list(dict.fromkeys([*cves, *(cve for path in snapshot_files for cve in cve_ids_from_snapshot_file(path))]))
    if len(out) > limits.MAX_LOOKUP_CVES:
        raise KevError('PT-KEV-LIMIT', 'too many CVE IDs in one lookup')
    return out


def diff_snapshots(store: KevStore, from_id: str | None, to_id: str | None) -> tuple[KevDelta, KevCatalog]:
    """Default: previous versus current. Returns the delta and the newer catalog (the delta lines read its entries)."""
    new = store.load(to_id) if to_id else None
    if new is None:
        current = store.load_current()
        if current is None:
            raise KevError('PT-KEV-NOTFOUND', 'no KEV catalog is loaded')
        new = current.catalog
    if from_id:
        old = store.load(from_id)
    else:
        older = [meta for meta in store.list_snapshots() if meta.snapshot_id != new.meta.snapshot_id
                 and (meta.date_released, meta.retrieved_at) <= (new.meta.date_released, new.meta.retrieved_at)]
        if not older:
            raise KevError('PT-KEV-NOTFOUND', 'only one stored catalog; there is nothing to compare')
        old = store.load(older[0].snapshot_id)
    return diff(old, new), new

