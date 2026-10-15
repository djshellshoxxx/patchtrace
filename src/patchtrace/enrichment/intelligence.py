"""Bounded HTTPS transport for B3 CVE context (SPEC-07 §8). Explicit consent only.

The only data that leaves the machine is the CVE identifier in the request URL, two fixed
headers, and — for NVD only, when the user supplies one for the session — the `apiKey`
header. No binary bytes, code, paths or notes are ever an input to this module, so they
cannot be sent.

Endpoints, verified live 2026-10-12 (see tests/fixtures/cve/README.md):
- NVD CVE API 2.0: ``https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<CVE>``;
  optional key in the ``apiKey`` request header. Docs:
  https://nvd.nist.gov/developers/vulnerabilities and https://nvd.nist.gov/developers/start-here
  (public rate limit 5 requests / rolling 30 s without a key, 50 with a key). An unknown ID
  returns HTTP 200 with ``totalResults: 0``, which normalization rejects.
- MSRC Security Update Guide API: ``https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/<CVE>``
  returns one per-CVE entity without auth (unknown ID → 404). Reference repository:
  https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API . The CVRF
  ``/cvrf/v3.0/updates/<CVE>`` endpoint was rejected: it only maps a CVE to a monthly CVRF
  document that is far larger than the 4 MiB cap.
"""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import partial

from ..netutil import Cancelled, TooManyAbandoned, interruptible
from .contracts import EnrichmentError

CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,19}', re.ASCII)  # ASCII digits only: \d alone also matches Unicode digits
CVE_MAX_LENGTH = 24
MAX_CVES = 64
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
CONNECT_TIMEOUT = 10.0
TOTAL_TIMEOUT = 30.0
MAX_ATTEMPTS = 3
MAX_REDIRECTS = 3
MAX_RETRY_AFTER = 60
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
# H10: NVD pacing (token bucket of one: minimum spacing between request starts) and 403 handling.
NVD_HOST = 'services.nvd.nist.gov'
NVD_INTERVAL = {False: 6.0, True: 0.6}  # keyed by "an API key is in use"
OVERALL_SLACK = 120.0
ALLOWED_HOSTS = frozenset({'api.msrc.microsoft.com', 'services.nvd.nist.gov'})
PROVIDERS: dict[str, str] = {
    'msrc': 'https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{cve}',
    'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}',
}
KEY_HEADER = {'nvd': 'apiKey'}
_FIXED_HEADERS = (('Accept', 'application/json'), ('User-Agent', 'PatchTrace'))
_CHUNK = 65536


def validate_cve_id(value: object) -> str:
    # fullmatch, not `$`: `$` would accept a trailing newline and smuggle it into a URL.
    if type(value) is not str or len(value) > CVE_MAX_LENGTH or not CVE_PATTERN.fullmatch(value):
        raise EnrichmentError('PT-ENRICH-INPUT', 'invalid CVE identifier')
    return value


def _check_url(url: str) -> None:
    try:
        parts = urllib.parse.urlsplit(url)
        _ = parts.port
    except ValueError:
        raise EnrichmentError('PT-ENRICH-NETWORK', 'redirect to an invalid URL refused') from None
    if (parts.scheme != 'https' or parts.hostname not in ALLOWED_HOSTS or parts.port not in (None, 443)
            or parts.username is not None or parts.password is not None):
        raise EnrichmentError('PT-ENRICH-NETWORK', 'URL outside the HTTPS provider allowlist refused')


@dataclass(frozen=True)
class PlannedRequest:
    """Exact request preview. `key_header` names where a session key *would* go; never its value."""
    provider: str
    cve_id: str
    url: str
    headers: tuple[tuple[str, str], ...]
    key_header: str | None


@dataclass(frozen=True)
class FetchConsent:
    providers: tuple[str, ...]
    urls: frozenset[str]

    @classmethod
    def for_plan(cls, plan: Iterable[PlannedRequest]) -> FetchConsent:
        plan = tuple(plan)
        return cls(tuple(sorted({p.provider for p in plan})), frozenset(p.url for p in plan))


@dataclass(frozen=True)
class RawResponse:
    provider: str
    cve_id: str
    body: bytes = field(repr=False)
    sha256: str
    url: str
    retrieved_at: str


def _providers(providers: Iterable[str]) -> tuple[str, ...]:
    if isinstance(providers, str):
        providers = providers.split(',')
    chosen = tuple(sorted(set(providers)))
    if not chosen or any(p not in PROVIDERS for p in chosen):
        raise EnrichmentError('PT-ENRICH-CONFIG', 'providers must be a non-empty subset of msrc, nvd')
    return chosen


def plan_requests(cve_ids: Iterable[str], providers: Iterable[str]) -> tuple[PlannedRequest, ...]:
    if isinstance(cve_ids, str):
        cve_ids = (cve_ids,)
    ids = list(dict.fromkeys(validate_cve_id(c) for c in cve_ids))
    if not ids:
        raise EnrichmentError('PT-ENRICH-INPUT', 'no CVE identifiers supplied')
    if len(ids) > MAX_CVES:
        raise EnrichmentError('PT-ENRICH-LIMIT', f'at most {MAX_CVES} CVE identifiers per fetch')
    chosen = _providers(providers)
    return tuple(PlannedRequest(provider=p, cve_id=c, url=PROVIDERS[p].format(cve=c),
                                headers=_FIXED_HEADERS, key_header=KEY_HEADER.get(p))
                 for c in ids for p in chosen)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # Returning None makes urllib surface the 3xx as an HTTPError, so the allowlist check
    # below sees every hop instead of urllib following it silently.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_urllib_opener() -> urllib.request.OpenerDirector:
    # ProxyHandler({}) ignores HTTPS_PROXY/ALL_PROXY etc., matching providers.py: an
    # environment proxy would otherwise observe which CVEs an analyst is researching.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class _UrllibResponse:
    def __init__(self, raw):
        self._raw = raw
        self.status = getattr(raw, 'status', None) or raw.code
        self.headers = raw.headers

    def read(self, size: int) -> bytes:
        return self._raw.read(size)

    def read1(self, size: int) -> bytes:
        return self._raw.read1(size)

    def close(self) -> None:
        self._raw.close()


def urllib_open(url: str, headers: Mapping[str, str], timeout: float):
    """Default opener: returns a response for any HTTP status, raises TimeoutError/OSError otherwise."""
    request = urllib.request.Request(url, headers=dict(headers), method='GET')
    try:
        return _UrllibResponse(build_urllib_opener().open(request, timeout=timeout))
    except urllib.error.HTTPError as exc:
        return _UrllibResponse(exc)
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, TimeoutError):
            raise TimeoutError('timed out') from None
        raise ConnectionError('connection failed') from None


def _retry_after(value: str | None, now: datetime) -> int | None:
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit() and len(value) < 10:
        return int(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    return max(0, int((when - now).total_seconds()) + 1)


def pacing_interval(provider: str, has_key: bool) -> float:
    return NVD_INTERVAL[bool(has_key)] if provider == 'nvd' else 0.0


def expected_duration(plan: Iterable[PlannedRequest], has_key: bool) -> float:
    """Minimum seconds the pacing alone will take (NVD only; other providers are unpaced)."""
    nvd = sum(1 for request in plan if request.provider == 'nvd')
    return max(0, nvd - 1) * pacing_interval('nvd', has_key)


def describe_duration(plan: Iterable[PlannedRequest], has_key: bool) -> str:
    """Consent-preview sentence about NVD pacing; empty when NVD is not requested."""
    plan = tuple(plan)
    nvd = sum(1 for request in plan if request.provider == 'nvd')
    if nvd == 0:
        return ''
    seconds = expected_duration(plan, has_key)
    spacing = pacing_interval('nvd', has_key)
    span = f'about {round(seconds)} seconds' if seconds < 90 else f'about {round(seconds / 60)} minutes'
    return (f'{nvd} NVD request(s) are spaced {spacing:g} s apart ({"with" if has_key else "without"} an API '
            f'key): expect {span}.')


class Pacer:
    """Minimum spacing between request starts for one provider; waits are cancellable."""

    def __init__(self, interval: float, clock: Callable[[], float], sleep: Callable, cancel, plan_deadline: float):
        self.interval, self.clock, self.sleep, self.cancel = interval, clock, sleep, cancel
        self.plan_deadline = plan_deadline
        self.next_slot = 0.0

    def acquire(self) -> None:
        while True:
            _cancelled(self.cancel)
            now = self.clock()
            if now >= self.plan_deadline:
                raise EnrichmentError('PT-ENRICH-NETWORK', 'overall fetch deadline exceeded', recoverable=True)
            if now >= self.next_slot:
                break
            if self.next_slot > self.plan_deadline:
                raise EnrichmentError('PT-ENRICH-NETWORK', 'overall fetch deadline exceeded', recoverable=True)
            self.sleep(self.next_slot - now, self.cancel)
        _cancelled(self.cancel)
        self.next_slot = self.clock() + self.interval


def _default_sleep(seconds: float, cancel: threading.Event | None) -> None:
    if cancel is None:
        time.sleep(seconds)
    else:
        cancel.wait(seconds)


class _Retry(Exception):
    def __init__(self, wait: float | None, status: int | None = None):
        self.wait = wait
        self.status = status


def fetch(plan: Iterable[PlannedRequest], consent: FetchConsent, *, api_key: str | None = None,
          opener: Callable | None = None, cancel: threading.Event | None = None,
          clock: Callable[[], float] = time.monotonic,
          sleep: Callable[[float, threading.Event | None], None] = _default_sleep,
          now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> dict[str, dict[str, RawResponse]]:
    """Return ``{cve_id: {provider: RawResponse}}``. Any failure raises EnrichmentError.

    Keyed by CVE first because one plan may cover several CVEs; ``{p: r.body for p, r in
    result[cve].items()}`` is the input to ``cve.normalize``.
    """
    plan = tuple(plan)
    _validate(plan, consent, api_key)
    results, _ = fetch_all(plan, consent, api_key=api_key, opener=opener, cancel=cancel, clock=clock,
                           sleep=sleep, now=now, _validated=True, _fail_fast=True)
    return results


def fetch_all(plan: Iterable[PlannedRequest], consent: FetchConsent, *, api_key: str | None = None,
              opener: Callable | None = None, cancel: threading.Event | None = None,
              clock: Callable[[], float] = time.monotonic,
              sleep: Callable[[float, threading.Event | None], None] = _default_sleep,
              now: Callable[[], datetime] = lambda: datetime.now(UTC), _validated: bool = False,
              _fail_fast: bool = False, overall_timeout: float | None = None,
              ) -> tuple[dict[str, dict[str, RawResponse]], dict[tuple[str, str], EnrichmentError]]:
    """Like `fetch`, but one failing request does not discard the others.

    Returns ``(responses, errors)`` with errors keyed by ``(cve_id, provider)``. Validation
    failures of the plan/consent/key and cancellation still raise immediately.
    """
    plan = tuple(plan)
    if not _validated:
        _validate(plan, consent, api_key)
    opener = opener or urllib_open
    results: dict[str, dict[str, RawResponse]] = {}
    errors: dict[tuple[str, str], EnrichmentError] = {}
    plan_deadline = clock() + (overall_timeout if overall_timeout is not None
                               else expected_duration(plan, api_key is not None) + OVERALL_SLACK)
    pacers: dict[str, Pacer] = {}
    for request in plan:
        headers = dict(request.headers)
        if api_key is not None and request.key_header:
            headers[request.key_header] = api_key
        interval = pacing_interval(request.provider, api_key is not None)
        pacer = None
        if interval > 0:
            pacer = pacers.setdefault(request.provider, Pacer(interval, clock, sleep, cancel, plan_deadline))
        try:
            if clock() >= plan_deadline:
                raise EnrichmentError('PT-ENRICH-NETWORK', 'overall fetch deadline exceeded', recoverable=True)
            body, final_url = _fetch_one(request, headers, opener, cancel, clock, sleep, now, pacer)
        except EnrichmentError as exc:
            if _fail_fast or exc.code == 'PT-ENRICH-CANCEL':
                raise
            errors[(request.cve_id, request.provider)] = exc
            continue
        results.setdefault(request.cve_id, {})[request.provider] = RawResponse(
            provider=request.provider, cve_id=request.cve_id, body=body,
            sha256=hashlib.sha256(body).hexdigest(), url=final_url,
            retrieved_at=now().astimezone(UTC).isoformat(timespec='seconds').replace('+00:00', 'Z'))
    return results, errors


def _validate(plan: tuple[PlannedRequest, ...], consent: FetchConsent, api_key: str | None) -> None:
    if not plan:
        raise EnrichmentError('PT-ENRICH-INPUT', 'empty request plan')
    for request in plan:
        # Re-derive rather than trust: a hand-built PlannedRequest must not widen the URL set.
        expected = plan_requests((request.cve_id,), (request.provider,))[0]
        if request != expected:
            raise EnrichmentError('PT-ENRICH-CONFIG', 'request plan was altered after planning')
        if request.provider not in consent.providers or request.url not in consent.urls:
            raise EnrichmentError('PT-ENRICH-CONFIG', 'request not covered by user consent')
    if api_key is not None and (type(api_key) is not str or not api_key or len(api_key) > 256
                                or any(ord(c) < 33 or ord(c) > 126 for c in api_key)):
        raise EnrichmentError('PT-ENRICH-CONFIG', 'invalid API key')


def _cancelled(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise EnrichmentError('PT-ENRICH-CANCEL', 'CVE fetch cancelled', recoverable=True)


def _fetch_one(request, headers, opener, cancel, clock, sleep, now, pacer=None) -> tuple[bytes, str]:
    deadline = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        _cancelled(cancel)
        if pacer is not None:
            pacer.acquire()
        if deadline is None:
            deadline = clock() + TOTAL_TIMEOUT  # the 30 s budget starts at the actual send, not at pacing waits
        try:
            return _attempt(request.url, headers, opener, cancel, clock, deadline, now)
        except _Retry as retry:
            if attempt == MAX_ATTEMPTS:
                if retry.status == 403:
                    raise EnrichmentError('PT-ENRICH-NETWORK', 'NVD returned HTTP 403 (rate limit or rejected '
                                          'API key) after retries; wait and retry, or check the API key',
                                          recoverable=True) from None
                raise EnrichmentError('PT-ENRICH-NETWORK', 'provider unavailable after retries',
                                      recoverable=True) from None
            wait = float(2 ** (attempt - 1)) if retry.wait is None else float(retry.wait)
            if wait > MAX_RETRY_AFTER:
                raise EnrichmentError('PT-ENRICH-NETWORK', 'provider asked to retry later than 60 s',
                                      recoverable=True) from None
            if clock() + wait >= deadline:
                raise EnrichmentError('PT-ENRICH-NETWORK', 'retry would exceed the 30 s total timeout',
                                      recoverable=True) from None
            sleep(wait, cancel)
    raise AssertionError('unreachable')


def _attempt(url, headers, opener, cancel, clock, deadline, now) -> tuple[bytes, str]:
    for _hop in range(MAX_REDIRECTS + 1):
        _check_url(url)
        remaining = deadline - clock()
        if remaining <= 0:
            raise EnrichmentError('PT-ENRICH-NETWORK', 'total timeout exceeded', recoverable=True)
        try:
            # urllib timeouts are per socket operation, so the connect bound is passed per call
            # and the 30 s total is enforced by the deadline checks around each read.
            timeout = min(CONNECT_TIMEOUT, remaining)
            response = interruptible(partial(opener, url, headers, timeout), cancel, cleanup=lambda r: r.close())
        except Cancelled:
            raise EnrichmentError('PT-ENRICH-CANCEL', 'CVE fetch cancelled', recoverable=True) from None
        except TooManyAbandoned:
            raise EnrichmentError('PT-ENRICH-NETWORK', 'previous requests still closing', recoverable=True) from None
        except TimeoutError:
            raise _Retry(None) from None
        except (OSError, http.client.HTTPException):
            raise EnrichmentError('PT-ENRICH-NETWORK', 'connection failed', recoverable=True) from None
        try:
            status = response.status
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get('Location')
                if not location:
                    raise EnrichmentError('PT-ENRICH-PROVIDER', 'redirect without Location')
                try:
                    target = urllib.parse.urljoin(url, location)
                    moved = urllib.parse.urlsplit(target).hostname != urllib.parse.urlsplit(url).hostname
                except ValueError:
                    raise EnrichmentError('PT-ENRICH-NETWORK', 'invalid URL refused') from None
                if moved:
                    # The NVD key is for NVD only; never forward it to another allowlisted host.
                    headers = {k: v for k, v in headers.items() if k not in KEY_HEADER.values()}
                url = target
                continue
            if status in RETRYABLE_STATUS:
                raise _Retry(_retry_after(response.headers.get('Retry-After'), now()), status)
            if status == 403 and urllib.parse.urlsplit(url).hostname == NVD_HOST:
                # NVD answers throttling with 403 as well as 429; back off instead of failing at once.
                raise _Retry(_retry_after(response.headers.get('Retry-After'), now()), 403)
            if status != 200:
                raise EnrichmentError('PT-ENRICH-PROVIDER', f'provider returned HTTP {status}')
            length = response.headers.get('Content-Length')
            digits = length.strip() if length is not None else ''
            if digits.isascii() and digits.isdigit() and (len(digits) > 12 or int(digits) > MAX_RESPONSE_BYTES):
                raise EnrichmentError('PT-ENRICH-LIMIT', 'provider response exceeds 4 MiB')
            data = bytearray()
            # read1 returns after one socket receive, so the deadline is checked between receives.
            read = getattr(response, 'read1', response.read)
            while True:
                _cancelled(cancel)
                if clock() >= deadline:
                    raise EnrichmentError('PT-ENRICH-NETWORK', 'total timeout exceeded', recoverable=True)
                try:
                    size = min(_CHUNK, MAX_RESPONSE_BYTES + 1 - len(data))
                    chunk = interruptible(partial(read, size), cancel)
                except Cancelled:
                    raise EnrichmentError('PT-ENRICH-CANCEL', 'CVE fetch cancelled', recoverable=True) from None
                except TooManyAbandoned:
                    raise EnrichmentError('PT-ENRICH-NETWORK', 'previous requests still closing',
                                          recoverable=True) from None
                except TimeoutError:
                    raise _Retry(None) from None
                except (OSError, http.client.HTTPException):
                    raise EnrichmentError('PT-ENRICH-NETWORK', 'connection failed while reading',
                                          recoverable=True) from None
                if not chunk:
                    return bytes(data), url
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise EnrichmentError('PT-ENRICH-LIMIT', 'provider response exceeds 4 MiB')
        finally:
            response.close()
    raise EnrichmentError('PT-ENRICH-NETWORK', 'too many redirects')
