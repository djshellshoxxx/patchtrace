"""KEV for ``kb leads``: the local catalog in use as an ``ExploitationLookup`` (KB-integration-plan 9, slice K8 KEV
part; KEV-integration-plan sections 4 and 6). Offline and read-only: it never fetches, writes or creates a folder.

The catalog is read through ``kev.store.KevStore.load_current`` and answered through ``kev.view_model.KevColumnProvider``
(the ``KevLookupPort``), so this module adds no catalog, parser or join of its own. Every outcome is total: a missing
folder, an empty folder and a damaged store all become a ``KevSource`` state, never an exception, so KEV can only add
CVE-level context to a report and can never stop one. Nothing here sees a function, a score or a rank.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from ...kev import store as kev_store
from ...kev.contracts import KevError, KevLookup, utc
from ...kev.view_model import NOT_LISTED_NEGATION, KevColumnProvider, age_phrase, banner_text
from ..leads import KevFact, KevSource, plain_text

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
    """Whether the folder holds anything but leftover temporaries (what tells "unreadable" from "not loaded")."""
    try:
        return any(path.is_file() and not path.name.endswith(kev_store.TMP_SUFFIX) for path in directory.rglob('*'))
    except OSError:
        return True


class KevExploitation:
    """``ExploitationLookup`` over one loaded snapshot at one injected moment. ``source`` describes the snapshot for the
    whole report; ``status`` answers one CVE with the snapshot's identity and age attached."""

    def __init__(self, provider: KevColumnProvider | None, source: KevSource):
        self._provider, self.source = provider, source

    def status(self, cve: str) -> KevFact:
        if self._provider is None:
            return KevFact('no-snapshot')
        row: KevLookup = self._provider.lookup(cve)
        if row.status not in ('listed', 'not-listed'):          # invalid-id or unavailable: nothing is known
            return KevFact('no-snapshot')
        meta = self._provider.meta
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
