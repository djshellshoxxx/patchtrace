"""Exact CVE join, freshness and snapshot delta (KEV-integration-plan sections 4 to 7). Pure; the clock is a parameter.

KEV is context at the level of a CVE and it NEVER alters a ranking: nothing in this package imports the ranking
code, no function here takes or returns a score, and the only ordering offered is the opt-in "listed first" reading
order in ``view_model``. A CVE ID is joined by exact ASCII text: an ID that is not one is ``invalid-id`` (never "not
listed"), and with no catalog loaded a valid ID is ``unavailable`` (never "not listed"), because neither says
anything about the CVE.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC, datetime

from . import limits
from .contracts import (
    Freshness,
    KevCatalog,
    KevChange,
    KevDelta,
    KevEntry,
    KevError,
    KevLookup,
    KevTracked,
    LookupStatus,
    clean_text,
    is_cve_id,
    utc,
)

NOTE_INVALID = 'expected CVE-YYYY-NNNN with ASCII digits'
NOTE_NO_CATALOG = 'no catalog is loaded'
NOTE_FUTURE = "the catalog's release time is in the future; treat results as unverified"
_SPLIT = re.compile(r'[\s,;]+')                                 # Unicode white space too, as pasted text carries it


def _limit_error() -> KevError:
    return KevError('PT-KEV-LIMIT', f'more than {limits.MAX_LOOKUP_CVES} CVE IDs at once')


def split_cve_ids(text: str) -> tuple[str, ...]:
    """The distinct tokens of typed or pasted text in first-seen order; ASCII tokens are upper-cased. Whether a token is
    a CVE ID is decided later by ``lookup`` (a fullwidth token stays as typed and is reported invalid)."""
    found: dict[str, None] = {}
    for token in _SPLIT.split(text):
        if token:
            found[token.upper() if token.isascii() else token] = None
            if len(found) > limits.MAX_LOOKUP_CVES:
                raise _limit_error()
    return tuple(found)


def freshness_of(date_released: str, now: datetime) -> tuple[Freshness, int]:
    """How old a catalog is at ``now``: whole UTC calendar days since its release day (fresh up to 3, aging up to 14,
    stale from 15), or ``future`` when the release instant is after ``now`` (a wrong clock or a wrong file)."""
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('now must be timezone-aware')
    released, moment = utc(date_released), now.astimezone(UTC)
    age = (moment.date() - released.date()).days
    if released > moment:
        return 'future', age
    if age <= limits.FRESH_MAX_DAYS:
        return 'fresh', age
    return ('aging' if age <= limits.AGING_MAX_DAYS else 'stale'), age


def classify(catalog: KevCatalog | None, cve: str) -> tuple[LookupStatus, KevEntry | None]:
    """The status of one ID and its entry; the cheap core of ``lookup`` that the column provider shares."""
    if not is_cve_id(cve):
        return 'invalid-id', None
    if catalog is None:
        return 'unavailable', None
    entry = catalog.by_cve.get(cve)
    return ('not-listed', None) if entry is None else ('listed', entry)


def lookup(catalog: KevCatalog | None, cve_ids: Iterable[str], now: datetime) -> tuple[KevLookup, ...]:
    """One ``KevLookup`` per distinct ID, in first-seen order. Total over any strings; at most 5,000 distinct IDs."""
    ids = list(dict.fromkeys(cve_ids))
    if len(ids) > limits.MAX_LOOKUP_CVES:
        raise _limit_error()
    freshness, age = freshness_of(catalog.meta.date_released, now) if catalog is not None else ('unknown', None)
    rows = []
    for cve in ids:
        status, entry = classify(catalog, cve)
        if status == 'invalid-id':
            rows.append(KevLookup(cve_id=clean_text(cve, limits.MAX_ECHO_CHARS), status=status, notes=(NOTE_INVALID,)))
        elif status == 'unavailable':
            rows.append(KevLookup(cve_id=cve, status=status, notes=(NOTE_NO_CATALOG,)))
        else:
            rows.append(KevLookup(cve_id=cve, status=status, entry=entry, snapshot_id=catalog.meta.snapshot_id,
                                  freshness=freshness, age_days=age,
                                  notes=(NOTE_FUTURE,) if freshness == 'future' else ()))
    return tuple(rows)


def _tracked(entry: KevEntry) -> KevTracked:
    return KevTracked(ransomware_use=entry.ransomware_use, due_date=entry.due_date,
                      forensic_triage=entry.forensic_triage, cwes=entry.cwes)


def diff(old: KevCatalog, new: KevCatalog) -> KevDelta:
    """What changed between two catalogs: CVEs added (newest first), removed, and CVEs whose tracked fields differ
    (ransomware use, CISA due date, forensic triage, weakness list). A reworded description is not a change."""
    added = sorted(sorted((item for cve, item in new.by_cve.items() if cve not in old.by_cve),
                          key=lambda item: item.cve_id), key=lambda item: item.date_added, reverse=True)
    removed = sorted(cve for cve in old.by_cve if cve not in new.by_cve)
    changed = []
    for cve in sorted(new.by_cve.keys() & old.by_cve.keys()):
        before, after = _tracked(old.by_cve[cve]), _tracked(new.by_cve[cve])
        if before != after:
            changed.append(KevChange(cve_id=cve, before=before, after=after))
    cap = limits.MAX_DELTA_IDS
    return KevDelta(from_snapshot_id=old.meta.snapshot_id, to_snapshot_id=new.meta.snapshot_id,
                    added=tuple(item.cve_id for item in added[:cap]), removed=tuple(removed[:cap]),
                    changed=tuple(changed[:cap]), added_count=len(added), removed_count=len(removed),
                    changed_count=len(changed))
