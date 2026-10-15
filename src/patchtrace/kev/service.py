"""What the CLI and the dock do with a KEV catalog folder, without printing and without Qt (KEV-integration-plan
sections 7 and 8).

``fetch`` downloads through the consented transport, checks the bytes with the parser and installs them through the
store; ``import_file`` and ``read_catalog`` take a file the person saved; ``diff`` loads two stored catalogs. The clock,
the opener and the retry sleep are parameters (a module default is looked up when the service is built, so a test or a
host can replace it). The store has no lock: install from one process at a time.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import limits, transport
from .contracts import (
    FETCH_OPERATION,
    ConsentRecord,
    KevCatalog,
    KevCatalogMeta,
    KevDelta,
    KevError,
    KevPlan,
    clean_text,
    plan_for,
)
from .join import diff
from .parse import parse_catalog
from .store import InstallResult, KevStore
from .transport import KevConsent, KevTransport, stamp

SURFACES = ('cli', 'gui')
__all__ = ['Comparison', 'Installed', 'KevService', 'consent_for', 'file_label', 'stamp', 'utc_now']


def utc_now() -> datetime:
    return datetime.now(UTC)


def consent_for(plan: KevPlan, hosts: str) -> KevConsent:
    """The consent a person gave by naming hosts (``--consent-hosts``): exactly the host of ``plan``, in any case."""
    named = {part.strip().lower() for part in hosts.split(',') if part.strip()}
    if named != {plan.host}:
        raise KevError('PT-KEV-CONSENT', f'consent must name exactly {plan.host} for the source {plan.source}')
    return KevConsent.for_plan(plan)


def file_label(name: str) -> str | None:
    """The file name as shown in the catalog description: one plain line, or ``None`` when it cannot be a base name."""
    label = clean_text(name, 255)
    return None if not label or label in ('.', '..') or '/' in label or '\\' in label else label


@dataclass(frozen=True, slots=True)
class Installed:
    """A catalog taken from the network or a file: its description, what the store did, and the catalog in use now
    (another one when a newer release was kept)."""
    meta: KevCatalogMeta
    result: InstallResult
    in_use: KevCatalogMeta


@dataclass(frozen=True, slots=True)
class Comparison:
    delta: KevDelta
    old: KevCatalog
    new: KevCatalog


def _read_file(path: Path | str) -> bytes:
    try:
        with open(path, 'rb') as handle:
            return handle.read(limits.MAX_CATALOG_BYTES + 1)       # the parser refuses the byte beyond the limit
    except OSError:
        raise KevError('PT-KEV-INPUT', 'the file cannot be read') from None


class KevService:
    def __init__(self, directory: Path | str, *, now: Callable[[], datetime] | None = None,
                 opener: Callable | None = None, sleep: Callable[[float, threading.Event | None], None] | None = None):
        self.store = KevStore(directory)
        self._now = now or utc_now
        self._opener = opener or transport.urllib_open
        self._sleep = sleep or transport.default_sleep

    def now(self) -> datetime:
        return self._now()

    def _install(self, raw: bytes, catalog: KevCatalog, accept_shrink: bool) -> Installed:
        result = self.store.install(raw, catalog, now=stamp(self._now()), accept_shrink=accept_shrink)
        meta = catalog.meta
        in_use = meta if result.current_id == meta.snapshot_id else self.store.read_meta(result.current_id)
        return Installed(meta, result, in_use)

    def fetch(self, source: str, hosts: str, *, surface: str = 'cli', accept_shrink: bool = False,
              cancel: threading.Event | None = None, announce: Callable[[str], None] | None = None) -> Installed:
        """Download the catalog of ``source`` after the consent named by ``hosts`` has been checked, check it and make it
        the catalog in use (unless it is an older release). Raises only ``KevError``; nothing is stored on failure."""
        if surface not in SURFACES:
            raise KevError('PT-KEV-INPUT', 'the surface must be cli or gui')
        plan = plan_for(source)
        consent = consent_for(plan, hosts)
        granted = stamp(self._now())
        client = KevTransport(consent, opener=self._opener, cancel=cancel, sleep=self._sleep, now=self._now,
                              announce=announce)
        fetched = client.fetch(plan)
        record = ConsentRecord(operation=FETCH_OPERATION, source=plan.source, url=plan.url, plan_sha=plan.plan_sha,
                               granted_at=granted, surface=surface)
        catalog = parse_catalog(fetched.body, source=plan.source, retrieved_at=fetched.retrieved_at,
                                source_url=plan.url, final_url=fetched.final_url, consent=record)
        return self._install(fetched.body, catalog, accept_shrink)

    def _parse_file(self, path: Path | str) -> tuple[bytes, KevCatalog]:
        raw = _read_file(path)
        return raw, parse_catalog(raw, source='local-import', retrieved_at=stamp(self._now()),
                                  file_name=file_label(Path(path).name))

    def import_file(self, path: Path | str, *, accept_shrink: bool = False) -> Installed:
        raw, catalog = self._parse_file(path)
        return self._install(raw, catalog, accept_shrink)

    def read_catalog(self, path: Path | str) -> KevCatalog:
        """A catalog file parsed and checked but not installed (what ``lookup --catalog`` reads)."""
        return self._parse_file(path)[1]

    def _previous(self, meta: KevCatalogMeta) -> str:
        key = (meta.date_released, meta.retrieved_at, meta.snapshot_id)
        for other in self.store.list_snapshots():                    # newest release first
            if (other.date_released, other.retrieved_at, other.snapshot_id) < key:
                return other.snapshot_id
        raise KevError('PT-KEV-NOTFOUND', 'a comparison needs two stored catalogs')

    def diff(self, from_id: str | None = None, to_id: str | None = None) -> Comparison:
        """The change from ``from_id`` to ``to_id``; by default the catalog in use against the release before it."""
        if to_id is None:
            loaded = self.store.load_current()
            if loaded is None:
                raise KevError('PT-KEV-NOTFOUND', 'no catalog is loaded')
            new = loaded.catalog
        else:
            new = self.store.load(to_id)
        old = self.store.load(self._previous(new.meta) if from_id is None else from_id)
        return Comparison(diff(old, new), old, new)
