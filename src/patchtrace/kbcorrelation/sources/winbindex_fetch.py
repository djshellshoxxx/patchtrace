"""Explicit metadata-only Winbindex refresh over existing transport, parser and publisher."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from ...acquisition import transport as tr
from ...acquisition import winbindex as wb
from ...acquisition.contracts import AcquisitionError
from ..contracts import domain_id
from .cvrf import SourceError, load_json

MAX_PLAN_BYTES = 65536
_ERROR_CODES = {'PT-ACQ-CANCEL': 'PT-KBC-CANCEL', 'PT-ACQ-LIMIT': 'PT-KBC-LIMIT',
                'PT-ACQ-INPUT': 'PT-KBC-INPUT', 'PT-ACQ-NOTFOUND': 'PT-KBC-SOURCE'}


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


@dataclass(frozen=True, slots=True)
class MetadataPlan:
    file_name: str
    method: str
    url: str
    hosts: tuple[str, ...]
    headers: tuple[tuple[str, str], ...]
    max_response_bytes: int
    max_decompressed_bytes: int
    request_timeout_s: float
    total_timeout_s: float
    attempts: int
    retry_after_max_s: int
    redirect_policy: str
    plan_sha: str

    def as_dict(self) -> dict:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return _canonical(dataclasses.asdict(self))


@dataclass(frozen=True, slots=True)
class RefreshRequest:
    workspace: Path
    file_name: str
    plan_json: str
    consent_hosts: tuple[str, ...]
    consent_plan: str
    offline: bool = False


@dataclass(frozen=True, slots=True)
class RefreshResult:
    file_name: str
    source_url: str
    retrieved_at: str
    last_modified: str | None
    date_basis: Literal['http-last-modified', 'retrieved-at']
    data_date: str
    raw_sha256: str
    raw_bytes: int
    stored_as: str
    rows: int
    skipped: int
    skipped_bodies: int
    warnings: tuple[str, ...]
    source_kind: str = 'third-party-index'
    authenticity: str = 'tls-allowlisted-host'


def build_plan(file_name: str) -> MetadataPlan:
    """Pure preview; the existing URL validator accepts normalized public PE basenames only."""
    try:
        url = wb.metadata_url(file_name)
    except AcquisitionError as exc:
        raise SourceError('PT-KBC-INPUT', exc.message) from None
    body = dict(file_name=file_name, method='GET', url=url, hosts=(tr.METADATA_HOST,), headers=tr.HEADERS,
                max_response_bytes=wb.MAX_COMPRESSED, max_decompressed_bytes=wb.MAX_DECOMPRESSED,
                request_timeout_s=tr.TIMEOUT, total_timeout_s=tr.METADATA_DEADLINE,
                attempts=tr.MAX_ATTEMPTS, retry_after_max_s=tr.MAX_RETRY_AFTER,
                redirect_policy='refuse every redirect')
    # The identity helper rejects numeric floats; hash their exact canonical JSON representation as text.
    return MetadataPlan(**body, plan_sha=domain_id('kbc.winbindex-metadata-plan', 1, {'plan_json': _canonical(body)}))


def render_plan(plan: MetadataPlan) -> str:
    """Exact application requests and limits; no I/O and no project values are included."""
    return ('Third-party Winbindex metadata only. No request has been made.\n'
            'TLS origin and the raw SHA-256 do not establish Microsoft authorship or vulnerability attribution.\n'
            f'{plan.method} {plan.url}\nHosts: {", ".join(plan.hosts)}\n'
            + '\n'.join(f'Header: {name}: {value}' for name, value in plan.headers)
            + '\nExact plan JSON (application headers, caps and digest):\n'
            + json.dumps(plan.as_dict(), indent=2, ensure_ascii=False))


def _checkpoint(cancel: threading.Event) -> None:
    if cancel.is_set():
        raise SourceError('PT-KBC-CANCEL', 'The metadata refresh was cancelled before publication.')


def _consented_plan(request: RefreshRequest) -> MetadataPlan:
    if request.offline:
        raise SourceError('PT-KBC-INPUT', 'Offline mode never refreshes metadata.')
    plan = build_plan(request.file_name)
    raw = request.plan_json
    try:
        if type(raw) is not str or len(raw) > MAX_PLAN_BYTES or len(raw.encode('utf-8')) > MAX_PLAN_BYTES:
            raise ValueError
        captured = load_json(raw.encode('utf-8'))
        if _canonical(captured) != plan.to_json():
            raise ValueError
    except (SourceError, ValueError, TypeError, RecursionError):
        raise SourceError('PT-KBC-CONSENT', 'The metadata preview is invalid or stale; preview it again.') from None
    if request.consent_hosts != plan.hosts or request.consent_plan != plan.plan_sha:
        raise SourceError('PT-KBC-CONSENT', 'Consent must match the exact displayed metadata hosts and plan digest.')
    return plan


def _dates(response: tr.MetadataResponse) -> tuple[str, str]:
    try:
        stamp = response.retrieved_at
        if type(stamp) is not str or len(stamp) != 20 or not stamp.endswith('Z'):
            raise ValueError
        retrieved = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if retrieved.tzinfo != UTC:
            raise ValueError
        last = response.last_modified
        if last is not None:
            if type(last) is not str or date.fromisoformat(last).isoformat() != last:
                raise ValueError
            if date.fromisoformat(last) > retrieved.date():
                raise ValueError
        return (last or retrieved.date().isoformat()), ('http-last-modified' if last else 'retrieved-at')
    except (TypeError, ValueError):
        raise SourceError('PT-KBC-SOURCE', 'Metadata retrieval or source dates are invalid or future-dated.') from None


def refresh(request: RefreshRequest, cancel: threading.Event, *, transport: tr.Transport | None = None,
            publish=None) -> RefreshResult:
    """Fetch exactly one consented metadata file and commit it through the existing workspace publisher.

    There is no binary acquisition or execution. A successful publication is retained even if a caller later
    cancels or cannot display the returned result. Transport/publisher injection is for deterministic testing.
    """
    plan = _consented_plan(request)
    _checkpoint(cancel)
    active = tr.Transport(cancel=cancel) if transport is None else dataclasses.replace(transport, cancel=cancel)
    try:
        response = active.fetch_metadata(plan.file_name, tr.AcquisitionConsent.for_urls((plan.url,)))
        _checkpoint(cancel)
        if response.url != plan.url:
            raise SourceError('PT-KBC-SOURCE', 'The metadata response does not belong to the displayed URL.')
        raw = response.body
        if type(raw) is not bytes or len(raw) > plan.max_response_bytes:
            raise SourceError('PT-KBC-LIMIT', 'The metadata response exceeds its byte limit or has invalid bytes.')
        data_date, basis = _dates(response)
        compressed = raw[:2] == b'\x1f\x8b'
        parsed = wb.parse_rows(raw, plan.file_name, data_date, compressed=compressed)
        if not parsed.rows:
            raise SourceError('PT-KBC-SOURCE', 'The metadata response has no usable build rows.')
    except AcquisitionError as exc:
        raise SourceError(_ERROR_CODES.get(exc.code, 'PT-KBC-ACQUIRE'), exc.message,
                          recoverable=exc.recoverable, details={'acquisition_code': exc.code}) from None
    _checkpoint(cancel)
    if publish is None:
        from ..wiring import save_winbindex_record
        publish = save_winbindex_record
    digest = hashlib.sha256(raw).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='patchtrace-winbindex-refresh-') as folder:
            staged = Path(folder) / 'metadata'
            staged.write_bytes(raw)
            _checkpoint(cancel)
            stored = publish(Path(request.workspace), staged, plan.file_name, data_date)
    except OSError:
        raise SourceError('PT-KBC-STORAGE', 'The metadata staging or publication could not be completed.') from None
    expected_path = f'winbindex/{plan.file_name}@{data_date}.json' + ('.gz' if compressed else '')
    if (stored.get('sha256') != digest or stored.get('bytes') != len(raw)
            or stored.get('file_name') != plan.file_name or stored.get('data_date') != data_date
            or stored.get('stored_as') != expected_path):
        raise SourceError('PT-KBC-STORAGE', 'The metadata publication receipt does not match the fetched bytes.')
    return RefreshResult(plan.file_name, response.url, response.retrieved_at, response.last_modified,
                         basis, data_date, digest, len(raw), expected_path, len(parsed.rows), parsed.skipped,
                         parsed.skipped_bodies, parsed.warnings)
