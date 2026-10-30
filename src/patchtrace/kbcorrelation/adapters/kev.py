"""KEV for ``kb leads``: the local catalog in use as an ``ExploitationLookup`` (KB-integration-plan 9, slice K8 KEV
part; KEV-integration-plan sections 4 and 6). Offline and read-only: it never fetches, writes or creates a folder.

The catalog is read through ``kev.store.KevStore.load_current`` and answered through ``kev.view_model.KevColumnProvider``
(the ``KevLookupPort``), so this module adds no catalog, parser or join of its own. Every outcome is total: a missing
folder, an empty folder and a damaged store all become a ``KevSource`` state, never an exception, so KEV can only add
CVE-level context to a report and can never stop one. Nothing here sees a function, a score or a rank.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path

from ...fabric.contracts import Anchor
from ...kev import store as kev_store
from ...kev.contracts import KevError, KevLookup, utc
from ...kev.ports import KevLookupPort
from ...kev.view_model import NOT_LISTED_NEGATION, KevColumnProvider, age_phrase, banner_text
from ..leads import ExploitationLookup, KevFact, KevSource, plain_text

TEXT_NOT_LOADED = ('KEV: not loaded (no local catalog). Import one with "patchtrace kev import FILE"; the leads do not '
                   'depend on it.')
TEXT_UNREADABLE = ('KEV: stored catalogs exist, but none of them could be read, so no CVE is shown as listed or not '
                   'listed. Run "patchtrace kev status".')


def default_kev_dir() -> Path:
    """The folder ``patchtrace kev`` uses (a seam so the test suite never reads a developer's real catalog)."""
    return kev_store.default_kev_dir()


def clock_moment(clock) -> Callable[[], datetime]:
    """The moment of a KB ``Clock`` (``now_utc() -> 'YYYY-MM-DDTHH:MM:SSZ'``), so KEV ages use the same injected time."""
    return lambda: utc(clock.now_utc())


def _stored(directory: Path) -> bool:
    """Whether the store's own files exist, leftover temporaries aside (what tells "unreadable" from "not loaded").
    Only the pointer and the two store folders are looked at, never the rest of a folder passed as ``--kev-dir``."""
    try:
        if (directory / kev_store.CURRENT_FILE).is_file():
            return True
        return any(path.is_file() and not path.name.endswith(kev_store.TMP_SUFFIX)
                   for name in (kev_store.META_DIR, kev_store.SNAPSHOT_DIR) if (directory / name).is_dir()
                   for path in (directory / name).iterdir())
    except OSError:
        return True


class KevExploitation:
    """``ExploitationLookup`` over one loaded snapshot at one injected moment. ``source`` describes the snapshot for the
    whole report; ``status`` answers one CVE with the snapshot's identity and age attached."""

    def __init__(self, provider: KevLookupPort | None, source: KevSource | None = None):
        self._provider, self.source = provider, source or KevSource()

    def status(self, cve: str) -> KevFact:
        if self._provider is None:
            return KevFact('no-snapshot')
        row: KevLookup = self._provider.lookup(cve)
        if row.status not in ('listed', 'not-listed') or (row.status == 'listed' and row.entry is None):
            return KevFact('no-snapshot')
        meta = getattr(self._provider, 'meta', None)
        if meta is None:  # existing generic KevLookupPort callers need no catalog metadata
            return KevFact(row.status, row.entry.date_added if row.entry else None, row.snapshot_id)
        return KevFact(row.status, row.entry.date_added if row.entry else None, row.snapshot_id,
                       catalog_version=meta.catalog_version, freshness=row.freshness, age_days=row.age_days)


def _loaded_source(provider: KevColumnProvider, notes: tuple[str, ...]) -> KevSource:
    meta = provider.meta
    age = age_phrase(provider.freshness, provider.age_days)
    origin = 'a local file, unverified' if meta.source == 'local-import' else f'{meta.source} over TLS'
    text = f'KEV: catalog {meta.catalog_version} ({age}; from {origin}). {NOT_LISTED_NEGATION}'
    return KevSource(state='loaded', text=plain_text(text, 1000), snapshot_id=meta.snapshot_id,
                     catalog_version=plain_text(meta.catalog_version, 200), date_released=meta.date_released,
                     retrieved_at=meta.retrieved_at, source=meta.source, authenticity=meta.authenticity,
                     freshness=provider.freshness, age_days=provider.age_days,
                     banner=banner_text(provider.freshness, provider.age_days),
                     notes=tuple(plain_text(note, 500) for note in notes))


def load_exploitation(directory: Path | str, now: datetime | Callable[[], datetime]) -> KevExploitation:
    """The catalog in use under ``directory`` (``patchtrace kev``'s store), answered at ``now``. Never raises."""
    folder = Path(directory)
    if not folder.is_dir():
        return KevExploitation(None, KevSource(state='not-loaded', text=TEXT_NOT_LOADED))
    try:
        loaded = kev_store.KevStore(folder).load_current()
        moment = now() if callable(now) else now
        provider = None if loaded is None else KevColumnProvider(loaded.catalog, moment)
    except (KevError, OSError, ValueError):
        loaded, provider = None, None
    if provider is None:
        unreadable = _stored(folder)
        return KevExploitation(None, KevSource(state='unreadable' if unreadable else 'not-loaded',
                                               text=TEXT_UNREADABLE if unreadable else TEXT_NOT_LOADED))
    return KevExploitation(provider, _loaded_source(provider, loaded.notes))


_DAY = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}')
_SHA = re.compile(r'[0-9a-f]{64}')
UNKNOWN = KevFact('no-snapshot')


class AnchorExploitation:
    """KEV listings carried as FAB witness facets ``kev=listed``, ``date_added``, ``snapshot`` on a ``cve`` anchor.

    Only a positive witness answers. The absence of an anchor says nothing, so it is never ``not-listed``."""

    def __init__(self, anchors: Iterable[Anchor]) -> None:
        self._listed: dict[str, KevFact] = {}
        for anchor in anchors:
            if anchor.kind != 'cve':
                continue
            for witness in anchor.witnesses:
                facets = dict(witness.facets)
                if facets.get('kev') != 'listed':
                    continue
                day, snap = facets.get('date_added', ''), facets.get('snapshot', '')
                fact = KevFact('listed', day if _DAY.fullmatch(day) else None, snap if _SHA.fullmatch(snap) else None)
                old = self._listed.get(anchor.key)
                if old is None or (fact.date_added or '') < (old.date_added or ''):
                    self._listed[anchor.key] = fact

    def status(self, cve: str) -> KevFact:
        return self._listed.get(cve, UNKNOWN)


class FirstAnswer:
    """The first lookup that answers; a catalog's ``not-listed`` outranks silence from a later one."""

    def __init__(self, lookups: Sequence[ExploitationLookup]) -> None:
        self._lookups = tuple(lookups)

    def status(self, cve: str) -> KevFact:
        for lookup in self._lookups:
            fact = lookup.status(cve)
            if fact.state != 'no-snapshot':
                return fact
        return UNKNOWN
