"""Consented download and import of a file-index pair (KB-integration-plan 8.1 ``kb acquire``; slice K7). Qt-free.

Flow: plan the exact requests (pure), check the analyst's consent against the planned hosts and ``plan_sha``, stage and
verify both files through ``AcquirePort`` (SHA-256 against the index row; nothing is executed), import them as a
normal KB pair, then remove the staging directory. Nothing is requested without consent for exactly the plan, and the
symbol server is only reached from here, never by default. A cancel or any failure creates no project.

The acquisition package is bound by ``wiring`` (``acquisition.workflow.Acquirer``); this module sees only the port.
Provenance of the download (URL, retrieval time, verified SHA-256) is returned in the result; it is not written into
the project, because that would advance the project revision the attach link records.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .contracts import PairProposal, domain_id
from .pairs import blocking_text
from .store import KbcStoreError

CODE_MAP = {'PT-ACQ-CANCEL': 'PT-KBC-CANCEL', 'PT-ACQ-VERIFY': 'PT-KBC-VERIFY', 'PT-ACQ-INPUT': 'PT-KBC-INPUT',
            'PT-ACQ-LIMIT': 'PT-KBC-LIMIT', 'PT-ACQ-UNSUPPORTED': 'PT-KBC-UNSUPPORTED'}
IMPORT_OK = (0, 3)  # 3: project created, advisory context pending ("kb attach --repair")
MAX_MESSAGE = 400


class RequestPlanLike(Protocol):
    @property
    def requests(self) -> Sequence[tuple[str, str]]: ...

    @property
    def hosts(self) -> Sequence[str]: ...


class StagedLike(Protocol):
    older_path: str
    newer_path: str
    older: Any
    newer: Any

    def discard(self) -> None: ...


class AcquirePort(Protocol):
    def plan(self, older: Mapping[str, Any], newer: Mapping[str, Any]) -> RequestPlanLike: ...

    def stage(self, older: Mapping[str, Any], newer: Mapping[str, Any], *, cancel: threading.Event | None,
              emit: Callable | None) -> StagedLike: ...


@dataclass(frozen=True)
class AcquirePlan:
    """What a consented acquisition would request. ``plan_sha`` covers the pair, the shas and every request."""
    plan_sha: str
    pair_id: str
    older_sha: str
    newer_sha: str
    hosts: tuple[str, ...]
    requests: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict:
        return {'plan_sha': self.plan_sha, 'pair_id': self.pair_id, 'older_sha256': self.older_sha,
                'newer_sha256': self.newer_sha, 'hosts': list(self.hosts),
                'requests': [{'method': m, 'target': t} for m, t in self.requests],
                'network_requests': len(self.requests), 'consent_required': True}

    @property
    def text(self) -> str:
        lines = [f'Acquisition plan {self.plan_sha}: up to {len(self.requests)} request(s) to {", ".join(self.hosts)}.',
                 'Only public file names, timestamps and sizes are sent; nothing from your projects.']
        lines += [f'  {method} {target}' for method, target in self.requests]
        lines.append('Each file is checked against its expected SHA-256 and never run. '
                     f'To fetch exactly this plan pass --consent-hosts {",".join(self.hosts)} '
                     f'--consent-plan {self.plan_sha}')
        return '\n'.join(lines)


@dataclass(frozen=True)
class AcquireResult:
    plan_sha: str
    outcome: Any  # the import's service Outcome; its result names the project
    downloads: tuple[dict, ...]  # per side: sha256, size, format, source_url, redirect_host, retrieved_at


def row_for(rows: Sequence[Mapping[str, Any]], sha256: str, file_name: str) -> Mapping[str, Any]:
    """The first index row of this build; rows of one SHA share the file facts."""
    found = next((r for r in rows if r.get('sha256') == sha256 and r.get('file_name') == file_name), None)
    if found is None:
        raise KbcStoreError('PT-KBC-INPUT', 'the file index has no row for one of the pair builds')
    return found


def _acquisition_error(exc: Exception) -> KbcStoreError | None:
    code = getattr(exc, 'code', None)
    if not isinstance(code, str) or not code.startswith('PT-ACQ-'):
        return None
    return KbcStoreError(CODE_MAP.get(code, 'PT-KBC-ACQUIRE'),
                         f'Acquisition stopped: {str(getattr(exc, "message", ""))[:MAX_MESSAGE]}',
                         recoverable=bool(getattr(exc, 'recoverable', True)), details={'acquisition_code': code})


def build_plan(pair: PairProposal, older_row: Mapping[str, Any], newer_row: Mapping[str, Any],
               port: AcquirePort) -> AcquirePlan:
    """Pure. A blocked pair, or a row that is not the pair's build, is refused before anything is planned."""
    if pair.grade == 'X':
        raise KbcStoreError('PT-KBC-UNSUPPORTED', blocking_text(pair) or 'This pair is blocked.')
    for ref, row in ((pair.older, older_row), (pair.newer, newer_row)):
        if row.get('sha256') != ref.sha256:
            raise KbcStoreError('PT-KBC-INPUT', 'an index row is not the pair build it was given for')
    try:
        planned = port.plan(older_row, newer_row)
    except Exception as exc:
        raise _acquisition_error(exc) or exc from None
    hosts, requests = tuple(sorted(planned.hosts)), tuple(planned.requests)
    sha = domain_id('kbc.acquireplan', 1, {'pair_id': pair.pair_id, 'older': pair.older.sha256,
                                           'newer': pair.newer.sha256, 'hosts': list(hosts),
                                           'requests': [list(r) for r in requests]})
    return AcquirePlan(sha, pair.pair_id, pair.older.sha256, pair.newer.sha256, hosts, requests)


def verify_consent(plan: AcquirePlan, *, consent_hosts: Sequence[str], consent_plan: str, offline: bool) -> None:
    if offline:
        raise KbcStoreError('PT-KBC-CONSENT', 'offline mode never fetches')
    if sorted(h.strip() for h in consent_hosts if h.strip()) != list(plan.hosts):
        raise KbcStoreError('PT-KBC-CONSENT', 'consent must name exactly the planned hosts')
    if consent_plan != plan.plan_sha:
        raise KbcStoreError('PT-KBC-CONSENT', 'consent was given for a different plan; review the new plan_sha')


def _check_directory(directory: str) -> None:
    root = Path(directory)
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise KbcStoreError('PT-KBC-INPUT', 'the project directory must be absent or empty')


def _provenance(staged: StagedLike) -> tuple[dict, ...]:
    return tuple({'side': a.side, 'sha256': a.sha256, 'size': a.size, 'format': a.format,
                  'source_url': a.provenance.source_url, 'redirect_host': a.provenance.redirect_host,
                  'retrieved_at': a.provenance.retrieved_at} for a in (staged.older, staged.newer))


def acquire_pair(plan: AcquirePlan, older_row: Mapping[str, Any], newer_row: Mapping[str, Any], *, port: AcquirePort,
                 import_pair: Callable[[str, str, str], Any], directory: str, consent_hosts: Sequence[str],
                 consent_plan: str, offline: bool = False, cancel: threading.Event | None = None,
                 emit: Callable | None = None) -> AcquireResult:
    """Download, verify and import one planned pair. Raises ``KbcStoreError``; on any raise there is no project.

    ``import_pair(older_path, newer_path, directory)`` is ``KbService.import_pair`` bound to its investigation.
    """
    verify_consent(plan, consent_hosts=consent_hosts, consent_plan=consent_plan, offline=offline)
    _check_directory(directory)
    try:
        staged = port.stage(older_row, newer_row, cancel=cancel, emit=emit)
    except Exception as exc:
        raise _acquisition_error(exc) or exc from None
    try:
        if cancel is not None and cancel.is_set():
            raise KbcStoreError('PT-KBC-CANCEL', 'Acquisition cancelled; nothing was imported.')
        if (staged.older.sha256, staged.newer.sha256) != (plan.older_sha, plan.newer_sha):
            raise KbcStoreError('PT-KBC-VERIFY', 'a downloaded file is not the build the plan named', recoverable=False)
        outcome = import_pair(staged.older_path, staged.newer_path, directory)
        if outcome.exit not in IMPORT_OK:
            raise KbcStoreError('PT-KBC-ACQUIRE', 'The files were verified but the comparison project was not created.',
                                details={'import_exit': outcome.exit})
        return AcquireResult(plan.plan_sha, outcome, _provenance(staged))
    finally:
        staged.discard()
