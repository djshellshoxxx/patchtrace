"""PW-01 exact ordered request plans and bounded, explicitly consented retrieval.

Building/rendering/parsing a plan is pure. ``fetch_source`` is the only network
entry point; it verifies every plan field and both consent values before opening
anything. The shared acquisition Transport owns retries and bounded body reads.
"""
from __future__ import annotations

import dataclasses
import functools
import hashlib
import itertools
import json
import re
import time
import urllib.parse
from dataclasses import dataclass
from datetime import UTC, datetime

from ...acquisition import transport as tr
from ...acquisition.contracts import AcquisitionError
from ..contracts import domain_id
from . import inventory_http as http
from .cvrf import SourceError

_MAX_PLAN_BYTES = 32 * 1024
_MAX_REDIRECTS = 4
_CAPS = {'support-page': 4 * 1024 * 1024, 'file-inventory': 16 * 1024 * 1024}
_ACCEPT = {'support-page': 'text/html', 'file-inventory': 'text/csv, application/octet-stream;q=0.9'}
_ERROR_CODES = {'PT-ACQ-CANCEL': 'PT-KBC-CANCEL', 'PT-ACQ-LIMIT': 'PT-KBC-LIMIT'}


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False)


@dataclass(frozen=True, slots=True)
class InventoryPlan:
    kind: str
    method: str
    urls: tuple[str, ...]
    hosts: tuple[str, ...]
    headers: tuple[tuple[str, str], ...]
    max_bytes: int
    request_timeout_s: int
    total_timeout_s: int
    max_redirects: int
    attempts: int
    retry_after_max_s: int
    plan_sha: str

    def as_dict(self) -> dict:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return _json(dataclasses.asdict(self))


@dataclass(frozen=True, slots=True)
class FetchedSource:
    kind: str
    original_url: str
    final_url: str
    redirect_chain: tuple[str, ...]
    raw: bytes
    sha256: str
    retrieved_at: str
    plan_sha: str

    def receipt(self) -> dict:
        """JSON-ready provenance of exact received bytes, excluding the bytes themselves."""
        return {'kind': self.kind, 'original_url': self.original_url, 'final_url': self.final_url,
                'redirect_chain': list(self.redirect_chain), 'sha256': self.sha256, 'size': len(self.raw),
                'retrieved_at': self.retrieved_at, 'plan_sha': self.plan_sha}


def build_plan(url: str, *, kind: str = 'file-inventory', redirects=()) -> InventoryPlan:
    """Build an immutable preview for one exact ordered chain; never resolve or request it."""
    if type(kind) is not str or kind not in _CAPS:
        raise SourceError('PT-KBC-INPUT', 'unknown inventory request kind')
    urls = [http.validate_url(url, kind=kind)]
    if isinstance(redirects, (str, bytes)):
        raise SourceError('PT-KBC-INPUT', 'redirects must be an ordered collection of URLs')
    try:
        iterator = iter(redirects)
    except TypeError:
        raise SourceError('PT-KBC-INPUT', 'redirects must be an ordered collection of URLs') from None
    for index, target in enumerate(iterator):
        if index >= _MAX_REDIRECTS:
            raise SourceError('PT-KBC-LIMIT', 'inventory plans permit at most four redirects')
        urls.append(http.validate_url(target, kind=kind))
    if len(set(urls)) != len(urls):
        raise SourceError('PT-KBC-INPUT', 'inventory plans cannot contain a redirect loop')
    body = {'kind': kind, 'method': 'GET', 'urls': tuple(urls),
            'hosts': tuple(sorted({urllib.parse.urlsplit(value).hostname for value in urls})),
            'headers': (*tr.HEADERS, ('Accept', _ACCEPT[kind]), ('Accept-Encoding', 'identity')),
            'max_bytes': _CAPS[kind], 'request_timeout_s': 10, 'total_timeout_s': 60,
            'max_redirects': _MAX_REDIRECTS, 'attempts': tr.MAX_ATTEMPTS, 'retry_after_max_s': tr.MAX_RETRY_AFTER}
    digest = domain_id('kbc.inventory-plan', 1, {'plan_json': _json(body)})
    return InventoryPlan(**body, plan_sha=digest)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate plan key')
        result[key] = value
    return result


def _bad_constant(_value):
    raise ValueError('non-finite plan value')


def parse_plan(raw: str | bytes) -> InventoryPlan:
    """Strict bounded JSON; every supplied field must equal this version's rebuilt plan."""
    if type(raw) not in (str, bytes) or len(raw) > _MAX_PLAN_BYTES:
        raise SourceError('PT-KBC-INPUT', 'inventory plan must be bounded UTF-8 JSON')
    try:
        text = raw.decode('utf-8', errors='strict') if type(raw) is bytes else raw
        if len(text.encode('utf-8')) > _MAX_PLAN_BYTES:
            raise ValueError
        value = json.loads(text, object_pairs_hook=_unique_pairs, parse_constant=_bad_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise SourceError('PT-KBC-INPUT', 'inventory plan is not strict bounded UTF-8 JSON') from None
    if (type(value) is not dict or type(value.get('kind')) is not str or type(value.get('urls')) is not list
            or not value['urls'] or len(value['urls']) > _MAX_REDIRECTS + 1
            or any(type(url) is not str for url in value['urls'])):
        raise SourceError('PT-KBC-INPUT', 'inventory plan must contain a kind and bounded ordered URL list')
    rebuilt = build_plan(value['urls'][0], kind=value['kind'], redirects=value['urls'][1:])
    try:
        canonical = _json(value)
    except (ValueError, TypeError, RecursionError):
        raise SourceError('PT-KBC-INPUT', 'inventory plan contains an invalid JSON value') from None
    if canonical != rebuilt.to_json():
        raise SourceError('PT-KBC-CONSENT', 'inventory plan fields or digest differ; build and review a fresh plan')
    return rebuilt


def _check_plan(plan) -> None:
    try:
        if type(plan) is not InventoryPlan:
            raise ValueError
        parsed = parse_plan(plan.to_json())
        if parsed != plan:
            raise ValueError
    except (ValueError, TypeError, AttributeError, RecursionError, SourceError):
        raise SourceError('PT-KBC-CONSENT', 'inventory plan is not the exact plan this version builds') from None


def render_plan(plan: InventoryPlan) -> str:
    """Render every ordered request, application header and cap covered by consent."""
    _check_plan(plan)
    lines = [f'Inventory retrieval: {plan.kind}', *[f'{index + 1}. GET {url}'
             for index, url in enumerate(plan.urls)], '', f'Hosts: {", ".join(plan.hosts)}']
    lines += [f'Header: {name}: {value}' for name, value in plan.headers]
    lines += [f'Body cap: {plan.max_bytes} bytes; connection timeout: {plan.request_timeout_s} s; '
              f'total timeout: {plan.total_timeout_s} s',
              f'Retries: {plan.attempts} attempts, at most {plan.retry_after_max_s} s per retry wait',
              f'Redirects: exact order above; at most {plan.max_redirects}',
              'An unexpected redirect stops before the changed target is requested.',
              'This preview makes no requests. Retrieved HTML never triggers a linked-file request.',
              f'plan_sha: {plan.plan_sha}']
    return '\n'.join(lines)


def _consent(plan, hosts, digest):
    if isinstance(hosts, (str, bytes)):
        raise SourceError('PT-KBC-CONSENT', 'consent must name the exact planned host set')
    try:
        values = tuple(itertools.islice(hosts, 4))
        valid = len(values) <= 3 and all(type(value) is str for value in values) and set(values) == set(plan.hosts)
    except TypeError:
        valid = False
    if not valid or type(digest) is not str or digest != plan.plan_sha:
        raise SourceError('PT-KBC-CONSENT', 'consent must match the exact inventory hosts and plan digest')


def _drift(plan, urls):
    proposed = build_plan(urls[0], kind=plan.kind, redirects=urls[1:])
    return SourceError('PT-KBC-CONSENT', 'the server changed the ordered request chain; review the proposed plan',
                       details={'proposed_plan': proposed.as_dict(), 'preview': render_plan(proposed)})


def _header_values(headers, name):
    if callable(getattr(headers, 'get_all', None)):
        return headers.get_all(name) or []
    return [value for key, value in headers.items() if type(key) is str and key.casefold() == name.casefold()]


def _framing(response, cap):
    """Return an exact declared byte length, or None for chunked/EOF framing."""
    fields = {name: _header_values(response.headers, name) for name in
              ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Content-Range')}
    if any(len(values) > 1 or any(type(value) is not str for value in values) for values in fields.values()):
        raise SourceError('PT-KBC-SOURCE', 'inventory response has ambiguous framing headers')
    length, transfer, encoding, content_range = (fields[name] for name in fields)
    if content_range or (length and transfer):
        raise SourceError('PT-KBC-SOURCE', 'inventory response has partial or ambiguous framing')
    # Match HTTPResponse's decoder predicate: trimming padding here could accept
    # a header that the reader treats as an unchunked EOF-delimited body.
    if transfer and transfer[0].lower() != 'chunked':
        raise SourceError('PT-KBC-SOURCE', 'inventory response uses an unsupported transfer encoding')
    if encoding and encoding[0].strip().casefold() != 'identity':
        raise SourceError('PT-KBC-SOURCE', 'inventory source used an unrequested content encoding')
    if not length:
        return None
    digits = length[0].strip(' \t')
    if not re.fullmatch(r'[0-9]{1,20}', digits):
        raise SourceError('PT-KBC-SOURCE', 'inventory response has an invalid Content-Length')
    expected = int(digits)
    if expected > cap:
        raise SourceError('PT-KBC-LIMIT', 'inventory response exceeds its byte budget')
    return expected


def fetch_source(plan: InventoryPlan, *, consent_hosts, consent_plan: str, offline: bool = False,
                 cancel=None, opener=None, clock=time.monotonic, now=lambda: datetime.now(UTC),
                 sleep=tr.default_sleep) -> FetchedSource:
    """Return one complete source, or an error without partial results or implicit follow-up.

    A successful receipt consumes exactly the entire approved chain. An earlier
    final response also requires a new plan, keeping receipt replay unambiguous.
    ``opener`` is a trusted injection seam for offline tests; production uses the
    pinned-address HTTPS opener, never the generic acquisition opener.
    """
    if offline:
        raise SourceError('PT-KBC-INPUT', 'offline mode never retrieves inventory sources')
    _check_plan(plan)
    _consent(plan, consent_hosts, consent_plan)
    deadline = clock() + plan.total_timeout_s
    open_request = opener if opener is not None else functools.partial(
        http.urllib_open, kind=plan.kind, cancel=cancel, clock=clock, deadline=deadline)

    def with_headers(method, url, _headers, timeout):
        return open_request(method, url, dict(plan.headers), timeout)

    transport = tr.Transport(opener=with_headers, cancel=cancel, sleep=sleep, clock=clock, now=now)

    def attempt():
        actual = [plan.urls[0]]
        while True:
            transport._live(deadline)
            remaining = deadline - clock()
            response = transport._open('GET', actual[-1], min(plan.request_timeout_s, remaining))
            try:
                transport._live(deadline)
                if response.status in tr.REDIRECT_STATUS:
                    try:
                        target = http.resolve_url(actual[-1], response.headers.get('Location'), kind=plan.kind)
                    except SourceError:
                        raise SourceError('PT-KBC-SOURCE', 'server supplied an unsafe or missing redirect') from None
                    if target in actual:
                        raise SourceError('PT-KBC-SOURCE', 'server supplied a redirect loop')
                    if len(actual) > plan.max_redirects:
                        raise SourceError('PT-KBC-LIMIT', 'server exceeded the inventory redirect limit')
                    if len(actual) >= len(plan.urls) or plan.urls[len(actual)] != target:
                        raise _drift(plan, (*actual, target))
                    actual.append(target)
                    continue
                transport._retryable(response)
                if response.status != 200:
                    raise SourceError('PT-KBC-SOURCE', f'inventory source returned HTTP {response.status}',
                                      details={'http': response.status})
                if tuple(actual) != plan.urls:
                    raise _drift(plan, actual)
                expected = _framing(response, plan.max_bytes)
                body = bytearray()
                transport._read(response, body.extend, plan.max_bytes, 'inventory source', deadline)
                if expected is not None and len(body) != expected:
                    raise SourceError('PT-KBC-SOURCE', 'inventory response does not match its complete declared body')
                transport._live(deadline)
                return bytes(body)
            finally:
                response.close()

    try:
        raw = transport._with_retries(attempt, deadline=deadline)
    except AcquisitionError as exc:
        raise SourceError(_ERROR_CODES.get(exc.code, 'PT-KBC-ACQUIRE'), exc.message,
                          recoverable=exc.recoverable, details={'acquisition_code': exc.code}) from None
    return FetchedSource(kind=plan.kind, original_url=plan.urls[0], final_url=plan.urls[-1],
                         redirect_chain=plan.urls, raw=raw, sha256=hashlib.sha256(raw).hexdigest(),
                         retrieved_at=tr._stamp(now()), plan_sha=plan.plan_sha)
