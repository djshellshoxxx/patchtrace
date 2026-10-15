"""Qt-free acquisition workflow shared by the KB correlator (KB-integration-plan 9, slice K7).

The same steps as ``AcquisitionDialog`` (plan the requests, resolve candidate URLs, download and verify two files into
a private staging directory, promote them into a normal project), but as plain functions over an injected
``Transport``. Nothing here asks for consent: the caller shows ``plan_requests`` to the analyst and builds the consent
from what was shown. Nothing is executed. A cancel or any failure leaves no staging directory and no project.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from . import quarantine, winbindex
from .contracts import AcquiredArtifact, AcquisitionError, BuildCandidate, DownloadPlan, KbRef
from .transport import SYMBOL_HOST, AcquisitionConsent, Transport

Emit = Callable[[tuple[str | None, float | None]], None]
REQUIRED_FIELDS = ('file_name', 'sha256', 'size', 'machine_type', 'timestamp', 'record_sha256', 'source')
PROBED = 'the one probed URL that answers 302'


@dataclass(frozen=True)
class RequestPlan:
    """Every request a run may make, in order, for the consent text. ``urls`` maps a SHA-256 to its candidate URLs."""
    urls: Mapping[str, tuple[str, ...]]
    requests: tuple[tuple[str, str], ...]

    @property
    def hosts(self) -> tuple[str, ...]:
        return (SYMBOL_HOST,)


@dataclass(frozen=True)
class Staged:
    """Two verified files in a private staging directory. Call ``discard`` exactly when done with the paths."""
    older: AcquiredArtifact
    newer: AcquiredArtifact
    staging: Path

    @property
    def older_path(self) -> str:
        return self.older.path

    @property
    def newer_path(self) -> str:
        return self.newer.path

    def discard(self) -> None:
        quarantine.remove_staging(self.staging)


def candidate_from_row(row: Mapping[str, Any]) -> BuildCandidate:
    """A downloadable build from one ``WinbindexRow.as_mapping()``. A row that lacks a field is not downloadable."""
    if any(row.get(name) is None for name in REQUIRED_FIELDS):
        raise AcquisitionError('PT-ACQ-NOTFOUND', f'{str(row.get("sha256"))[:12]} has no file facts to download from')
    try:
        return BuildCandidate(
            file_name=row['file_name'], sha256=row['sha256'], size=row['size'], machine_type=row['machine_type'],
            timestamp=row['timestamp'], virtual_size=row.get('virtual_size'),
            last_section_va=row.get('last_section_va'), last_section_raw=row.get('last_section_raw'),
            version=row.get('file_version'), kbs=(KbRef(kb=row['kb']),) if row.get('kb') else (),
            download=row['download'], source=row['source'], record_sha256=row['record_sha256'])
    except (ValidationError, KeyError) as exc:
        raise AcquisitionError('PT-ACQ-INPUT', f'index row is not a usable build: {type(exc).__name__}') from None


def plan_requests(older: BuildCandidate, newer: BuildCandidate) -> RequestPlan:
    """Pure: the URLs and the request list shown for consent (one GET if direct; HEADs then one GET otherwise)."""
    urls: dict[str, tuple[str, ...]] = {}
    requests: list[tuple[str, str]] = []
    for candidate in (older, newer):
        if candidate.download == 'direct':
            urls[candidate.sha256] = (winbindex.direct_url(candidate),)
            requests.append(('GET', urls[candidate.sha256][0]))
        elif candidate.download == 'candidates':
            urls[candidate.sha256] = winbindex.candidate_urls(candidate)
            requests += [('HEAD', u) for u in urls[candidate.sha256]]
            requests.append(('GET', PROBED))
        else:
            raise AcquisitionError('PT-ACQ-NOTFOUND', f'{candidate.sha256[:12]} is update-package only')
    return RequestPlan(urls, tuple(requests))


def check_project_root(root: Path) -> None:
    root = Path(root)
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise AcquisitionError('PT-ACQ-INPUT', 'the project directory must be absent or empty')


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise AcquisitionError('PT-ACQ-CANCEL', 'acquisition cancelled', recoverable=True)


def _resolve(older: BuildCandidate, newer: BuildCandidate, plan: RequestPlan, transport: Transport,
             emit: Emit) -> DownloadPlan:
    chosen = []
    for candidate in (older, newer):
        probes = plan.urls[candidate.sha256]
        if candidate.download == 'direct':
            chosen.append(probes[0])
        else:
            emit((f'Probing {len(probes)} candidate URLs for {candidate.sha256[:12]}', None))
            chosen.append(transport.resolve(probes, AcquisitionConsent.for_urls(probes)))
    return quarantine.make_plan(older, newer, chosen[0], chosen[1])


def stage(older: BuildCandidate, newer: BuildCandidate, transport: Transport, *, emit: Emit | None = None,
          parent: Path | None = None) -> Staged:
    """Resolve, download and verify both files. On cancel or any failure the staging directory is removed."""
    emit = emit or (lambda _event: None)
    plan = plan_requests(older, newer)
    staging = None
    try:
        download_plan = _resolve(older, newer, plan, transport, emit)
        consent = AcquisitionConsent.for_urls(d.url for d in download_plan.downloads)
        staging = quarantine.create_staging(parent)
        acquired = []
        for index, planned in enumerate(download_plan.downloads):
            emit((f'GET {planned.url}', index / 2))
            acquired.append(quarantine.acquire(
                planned, consent, staging, transport,
                lambda done, total, i=index: emit((None, (i + done / max(total, 1)) / 2))))
            emit((f'{planned.side}: {planned.sha256} verified ({acquired[-1].format})', (index + 1) / 2))
        _cancelled(transport.cancel)
        return Staged(acquired[0], acquired[1], staging)
    except BaseException:
        if staging is not None:
            quarantine.remove_staging(staging)
        raise


def create_project(staged: Staged, name: str, root: Path, *, cancel: threading.Event | None = None):
    """Promote a staged pair into a new project at ``root`` and always remove the staging directory.

    A cancel before the promote creates nothing. ``quarantine.promote`` removes its own partial project on failure.
    """
    try:
        check_project_root(root)
        _cancelled(cancel)
        return quarantine.promote(staged.older, staged.newer, name, Path(root))
    finally:
        staged.discard()


def acquire_project(older: BuildCandidate, newer: BuildCandidate, name: str, root: Path, transport: Transport, *,
                    emit: Emit | None = None):
    """The dialog's whole download flow: stage, then promote. Returns the open ``ProjectService``."""
    check_project_root(root)
    return create_project(stage(older, newer, transport, emit=emit), name, root, cancel=transport.cancel)


@dataclass(frozen=True)
class Acquirer:
    """Mapping-level facade used through the KB ``AcquirePort``; ``transport_factory(cancel=...)`` builds a Transport."""
    transport_factory: Callable[..., Transport] = Transport

    def plan(self, older: Mapping[str, Any], newer: Mapping[str, Any]) -> RequestPlan:
        return plan_requests(candidate_from_row(older), candidate_from_row(newer))

    def stage(self, older: Mapping[str, Any], newer: Mapping[str, Any], *, cancel: threading.Event | None = None,
              emit: Emit | None = None) -> Staged:
        return stage(candidate_from_row(older), candidate_from_row(newer), self.transport_factory(cancel=cancel),
                     emit=emit)
