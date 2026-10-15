"""Consented fetch of monthly CVRF documents (KB-integration-plan 8.1 `kb index sync`, 6 "consent drift"; slice K6).

The only network code of the KB correlator, and it holds no socket code of its own: it drives the hardened
acquisition ``Transport`` (read1 chunks, a watcher that aborts a blocked read on cancel or deadline, bounded
retries with ``Retry-After``). That transport hard-codes the Winbindex and symbol-server hosts, so this module
adds only what differs: the MSRC host, the ``Accept`` header, a same-host redirect loop and error mapping.

Rules that make a fetch safe:

* The plan must be the one this version builds for its months (``net_plan.build_plan``), the consent hosts must equal
  the planned set and the consent digest must equal ``plan_sha``; otherwise nothing is requested (PT-KBC-CONSENT).
* ``offline=True`` never fetches (PT-KBC-INPUT), whatever else is given.
* Only the planned month URLs are requested. A redirect is followed only to the same host over https (port 443, no
  userinfo), at most ``caps.max_redirects`` times; anything else is refused (PT-KBC-SOURCE).
* A document is capped at ``caps.max_bytes_per_document`` and is parsed by the offline importer, so a wrong document
  (another month, XML of an unknown dialect) is rejected exactly like a local import. A fetched document is marked
  ``tls-allowlisted-host``: TLS to an allow-listed host is the only authenticity claim; never "signed" or "trusted".

``fetch_months`` is a generator: one result per month, so the caller stores each document as it arrives and memory
holds one document. Cancelling raises PT-KBC-CANCEL after the documents already yielded; nothing is half written.
"""
from __future__ import annotations

import dataclasses
import hashlib
import re
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from ...acquisition import transport as tr
from ...acquisition.contracts import AcquisitionError
from ..contracts import SourceDoc
from ..limits import DEFAULT_LIMITS, KbcLimits
from .cvrf import SourceError
from .importer import ImportedDocument, gunzip_bounded, import_bytes
from .net_plan import ACCEPT, API_HOST, IndexPlan, build_plan, verify_consent

_MONTH_URL = re.compile(r'/cvrf/v3\.0/cvrf/([0-9]{4}-[A-Z][a-z]{2})')
_ACQUISITION_TO_KBC = {'PT-ACQ-CANCEL': 'PT-KBC-CANCEL', 'PT-ACQ-LIMIT': 'PT-KBC-LIMIT'}
Outcome = Literal['fetched', 'not-published', 'failed']


@dataclass(frozen=True)
class FetchedDocument:
    """Exact bytes of one monthly document (decompressed) and where they came from."""
    month: str
    url: str
    raw: bytes
    sha256: str
    retrieved_at: str


@dataclass(frozen=True)
class FetchResult:
    month: str
    url: str
    state: Outcome
    document: FetchedDocument | None = None
    error: SourceError | None = None


def _issue(exc: AcquisitionError) -> SourceError:
    return SourceError(_ACQUISITION_TO_KBC.get(exc.code, 'PT-KBC-ACQUIRE'), exc.message, recoverable=exc.recoverable,
                       details={'acquisition_code': exc.code})


def _month_of(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    match = _MONTH_URL.fullmatch(parts.path)
    if parts.hostname != API_HOST or match is None:
        raise SourceError('PT-KBC-UNSUPPORTED', 'the plan lists a request that is not a monthly CVRF document')
    return match.group(1)


def _redirect_target(current: str, location: str | None) -> str:
    if not location:
        raise SourceError('PT-KBC-SOURCE', 'the server redirected without a Location')
    target = urllib.parse.urljoin(current, location)
    try:
        parts = urllib.parse.urlsplit(target)
        port = parts.port
    except ValueError:
        raise SourceError('PT-KBC-SOURCE', 'an invalid redirect target was refused') from None
    if (any(not '!' <= ch <= '~' for ch in target) or parts.scheme != 'https' or parts.hostname != API_HOST
            or port not in (None, 443) or parts.username is not None or parts.password is not None):
        raise SourceError('PT-KBC-SOURCE', 'a redirect outside the consented host, or not https, was refused')
    return target


def _with_accept(opener: Callable) -> Callable:
    def open_with_accept(method, url, headers, timeout):
        return opener(method, url, {**headers, 'Accept': ACCEPT}, timeout)
    return open_with_accept


def _check_plan(plan: IndexPlan, limits: KbcLimits) -> None:
    if plan.plan_sha != build_plan(plan.months, limits=limits).plan_sha:
        raise SourceError('PT-KBC-CONSENT', 'the plan is not the one this version builds for those months')
    if any(not r.url.startswith(f'https://{API_HOST}/cvrf/v3.0/cvrf/') for r in plan.requests):
        raise SourceError('PT-KBC-UNSUPPORTED', 'only monthly document requests can be synced; drop the index request')
    if plan.caps.attempts != tr.MAX_ATTEMPTS or plan.caps.retry_after_max_s != tr.MAX_RETRY_AFTER:
        raise SourceError('PT-KBC-LIMIT', 'the plan retry caps differ from the shared transport; use the defaults')


def fetch_months(plan: IndexPlan, *, consent_hosts: Iterable[str], consent_plan: str, offline: bool = False,
                 cancel: threading.Event | None = None, opener: Callable = tr.urllib_open,
                 sleep: Callable[[float, threading.Event | None], None] = tr.default_sleep,
                 clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = lambda: datetime.now(UTC),
                 limits: KbcLimits = DEFAULT_LIMITS) -> Iterator[FetchResult]:
    """Yield one :class:`FetchResult` per planned month, in plan order, after the consent checks pass.

    Raises :class:`SourceError` before any request when offline, unconsented or the plan is not fetchable, and
    PT-KBC-CANCEL when ``cancel`` is set. A month that fails (404, retries exhausted, oversize) is a result, not an
    exception, so the other months are still tried."""
    if offline:
        raise SourceError('PT-KBC-INPUT', 'offline mode never fetches')
    _check_plan(plan, limits)
    verify_consent(plan, consent_hosts=consent_hosts, consent_plan=consent_plan)
    return _fetch(plan, cancel, tr.Transport(opener=_with_accept(opener), cancel=cancel, sleep=sleep, clock=clock,
                                              now=now), limits)


def _fetch(plan: IndexPlan, cancel, transport: tr.Transport, limits: KbcLimits) -> Iterator[FetchResult]:
    plan_deadline = transport.clock() + plan.caps.plan_timeout_s
    for request in plan.requests:
        month = _month_of(request.url)
        if cancel is not None and cancel.is_set():
            raise SourceError('PT-KBC-CANCEL', 'the sync was cancelled')
        if transport.clock() >= plan_deadline:
            yield FetchResult(month, request.url, 'failed', error=SourceError(
                'PT-KBC-ACQUIRE', 'the plan time budget was used up before this month'))
            continue
        try:
            yield FetchResult(month, request.url, 'fetched', document=_fetch_one(
                transport, request.url, month, plan, min(plan_deadline, transport.clock() + plan.caps.request_timeout_s)))
        except AcquisitionError as exc:
            issue = _issue(exc)
            if issue.code == 'PT-KBC-CANCEL':
                raise issue from None
            yield FetchResult(month, request.url, 'failed', error=issue)
        except SourceError as exc:
            state = 'not-published' if (exc.details or {}).get('http') == 404 else 'failed'
            yield FetchResult(month, request.url, state, error=exc)


def _fetch_one(transport: tr.Transport, url: str, month: str, plan: IndexPlan, deadline: float) -> FetchedDocument:
    cap = plan.caps.max_bytes_per_document

    def attempt() -> bytes:
        target, hops = url, 0
        while True:
            response = transport._open('GET', target, plan.caps.request_timeout_s)
            try:
                if response.status in tr.REDIRECT_STATUS:
                    hops += 1
                    if hops > plan.caps.max_redirects:
                        raise SourceError('PT-KBC-SOURCE', 'too many redirects')
                    target = _redirect_target(target, response.headers.get('Location'))
                    continue
                if response.status == 404:
                    raise SourceError('PT-KBC-SOURCE', 'no document is published for this month (HTTP 404)',
                                      details={'http': 404})
                transport._retryable(response)
                if response.status != 200:
                    raise SourceError('PT-KBC-SOURCE', f'the server answered HTTP {response.status}',
                                      details={'http': response.status})
                body = bytearray()
                transport._read(response, body.extend, cap, 'CVRF document', deadline)
                return bytes(body)
            finally:
                response.close()

    raw = transport._with_retries(attempt)
    if raw[:2] == b'\x1f\x8b':
        raw = gunzip_bounded(raw, cap)
    return FetchedDocument(month=month, url=url, raw=raw, sha256=hashlib.sha256(raw).hexdigest(),
                           retrieved_at=tr._stamp(transport.now()))


def to_imported(fetched: FetchedDocument, limits: KbcLimits = DEFAULT_LIMITS) -> ImportedDocument:
    """Parse a fetched document offline and mark it ``https-fetch`` / ``tls-allowlisted-host``.

    Raises :class:`SourceError` for a damaged document, a CSAF or non-CVRF file, or a month other than the one
    requested (the server, or something in between, sent the wrong document). ``doc_id`` derives from kind and bytes
    only, so the same bytes imported locally and fetched are one document."""
    doc = import_bytes(fetched.raw, now=fetched.retrieved_at, limits=limits)
    if doc.source.kind != 'cvrf-month' or doc.source.release_id != fetched.month:
        raise SourceError('PT-KBC-SOURCE', f'the server sent a document that is not the {fetched.month} CVRF month')
    source = SourceDoc(**{**doc.source.model_dump(), 'origin': 'https-fetch', 'uri': fetched.url,
                          'authenticity': 'tls-allowlisted-host'})
    return dataclasses.replace(doc, source=source)
