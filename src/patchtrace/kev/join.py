"""Exact-wording CVE join, freshness, snapshot delta and project-row builder for ``kev/1``. Pure.

The CVE ID is the only join key (no Microsoft entry names a KB). IDs are ASCII only: a fullwidth or Arabic-Indic
spelling is ``invalid-id``, never "not listed". Freshness counts whole UTC calendar days and takes ``now`` as an
argument, so wall-clock time is never hidden input.
"""
from __future__ import annotations

import datetime
import re
from collections.abc import Iterable

from ..search.normalize import sanitize_text
from . import limits
from .contracts import (
    Freshness,
    KevCatalog,
    KevCatalogMeta,
    KevChange,
    KevContext,
    KevContextLookup,
    KevDelta,
    KevEntry,
    KevError,
    KevFacts,
    KevLookup,
    context_id,
)

CVE_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}', re.ASCII)


def normalize_cve_id(text: str) -> str | None:
    """The canonical upper-case ID for ``text`` (edges trimmed, ASCII only), or None when it is not a CVE ID."""
    candidate = text.strip()
    if candidate.isascii():
        candidate = candidate.upper()
    return candidate if len(candidate) <= 24 and CVE_ID.fullmatch(candidate) else None


def _released(meta: KevCatalogMeta) -> datetime.datetime:
    return datetime.datetime.strptime(meta.date_released, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.UTC)


def freshness(meta: KevCatalogMeta | None, now: datetime.datetime) -> tuple[Freshness, int | None]:
    """(state, whole UTC days old). A release time after ``now`` is ``future`` with no age."""
    if meta is None:
        return 'unknown', None
    released = _released(meta)
    now = now.astimezone(datetime.UTC)
    if released > now:
        return 'future', None
    days = (now.date() - released.date()).days
    if days <= limits.FRESH_MAX_DAYS:
        return 'fresh', days
    return ('aging' if days <= limits.AGING_MAX_DAYS else 'stale'), days


class KevIndex:
    """O(1) CVE lookup over one snapshot."""

    def __init__(self, catalog: KevCatalog | None) -> None:
        self.catalog = catalog
        self._by_id = {entry.cve_id: entry for entry in catalog.entries} if catalog else {}

    def get(self, cve_id: str) -> KevEntry | None:
        return self._by_id.get(cve_id)


def lookup_one(index: KevIndex, raw: str, now: datetime.datetime) -> KevLookup:
    meta = index.catalog.meta if index.catalog else None
    state, age = freshness(meta, now)
    notes = ('The catalog release time is in the future.',) if state == 'future' else ()
    cve = normalize_cve_id(raw)
    if cve is None:
        return KevLookup(cve_id=sanitize_text(raw.strip(), 64) or '(empty)', status='invalid-id', freshness=state,
                         age_days=age, snapshot_id=meta.snapshot_id if meta else None, notes=notes)
    if meta is None:
        return KevLookup(cve_id=cve, status='unavailable', freshness='unknown')
    entry = index.get(cve)
    return KevLookup(cve_id=cve, status='listed' if entry else 'not-listed', entry=entry, snapshot_id=meta.snapshot_id,
                     freshness=state, age_days=age, notes=notes)


def lookup(catalog: KevCatalog | None, cves: Iterable[str], now: datetime.datetime) -> tuple[KevLookup, ...]:
    """One result per distinct input, in first-seen order. More than 5,000 inputs is a PT-KEV-LIMIT error."""
    raws = list(cves)
    if len(raws) > limits.MAX_LOOKUP_CVES:
        raise KevError('PT-KEV-LIMIT', 'too many CVE IDs in one lookup')
    index, out, seen = KevIndex(catalog), [], set()
    for raw in raws:
        result = lookup_one(index, raw, now)
        if (result.status, result.cve_id) not in seen:
            seen.add((result.status, result.cve_id))
            out.append(result)
    return tuple(out)


def _facts(entry: KevEntry) -> KevFacts:
    return KevFacts(ransomware_use=entry.ransomware_use, due_date=entry.due_date,
                    forensic_triage=entry.forensic_triage, cwes=entry.cwes)


def diff(old: KevCatalog, new: KevCatalog) -> KevDelta:
    """What changed from ``old`` to ``new``: ids are sorted, lists are capped at 500, counts are exact."""
    before = {entry.cve_id: entry for entry in old.entries}
    after = {entry.cve_id: entry for entry in new.entries}
    added = sorted(after.keys() - before.keys())
    removed = sorted(before.keys() - after.keys())
    changed = [KevChange(cve_id=cve, before=_facts(before[cve]), after=_facts(after[cve]))
               for cve in sorted(before.keys() & after.keys()) if _facts(before[cve]) != _facts(after[cve])]
    cap = limits.MAX_DELTA_IDS
    return KevDelta(from_snapshot_id=old.meta.snapshot_id, to_snapshot_id=new.meta.snapshot_id,
                    from_catalog_version=old.meta.catalog_version, to_catalog_version=new.meta.catalog_version,
                    added=tuple(added[:cap]), removed=tuple(removed[:cap]), changed=tuple(changed[:cap]),
                    added_count=len(added), removed_count=len(removed), changed_count=len(changed))


def make_context(catalog: KevCatalog, cves: Iterable[str], now: datetime.datetime, *, kb: str | None = None,
                 release_date: str | None = None, orientation_verified: bool = False) -> KevContext:
    """The ``kev-context`` project row for the valid, distinct CVEs among ``cves`` (at most 256)."""
    ids = sorted({cve for cve in map(normalize_cve_id, cves) if cve})
    if len(ids) > limits.MAX_PROJECT_CVES:
        raise KevError('PT-KEV-LIMIT', 'too many CVE IDs for one project row')
    rows = tuple(KevContextLookup(**{**result.model_dump(exclude={'entry'}),
                                     'entry': result.entry.slim() if result.entry else None})
                 for result in lookup(catalog, ids, now))
    meta = catalog.meta
    return KevContext(context_id=context_id(meta.snapshot_id, ids), created_at=now.astimezone(datetime.UTC)
                      .strftime('%Y-%m-%dT%H:%M:%SZ'), snapshot_id=meta.snapshot_id,
                      catalog_version=meta.catalog_version, date_released=meta.date_released,
                      content_digest=meta.content_digest, source=meta.source, lookups=rows, kb=kb,
                      release_date=release_date, orientation_verified=orientation_verified)
