"""Optional, bounded HTTP transports. Credentials live only in session objects."""
from __future__ import annotations

import http.client
import ipaddress
import json
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import partial

from .netutil import Cancelled, TooManyAbandoned, interruptible

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
TIMEOUT_SECONDS = 120
_READ_BYTES = 64 * 1024
_CANCELLED = 'PT-CANCEL: interpretation cancelled'
_CONNECTION_FAILED = 'PT-PROVIDER: connection failed or timed out; check endpoint and server'


class ProviderError(ValueError):
    pass


class ProviderCancelled(ProviderError):
    pass


@dataclass(frozen=True)
class ProviderConfig:
    kind: str
    endpoint: str
    model: str
    api_key: str = field(default='', repr=False)

    def __post_init__(self) -> None:
        validate_endpoint(self)
        if not self.model.strip() or len(self.model) > 200:
            raise ProviderError('PT-PROVIDER: supply a model name of at most 200 characters')
        if not _printable_ascii(self.api_key):
            raise ProviderError('PT-PROVIDER: invalid credential')


def _printable_ascii(key: str) -> bool:
    # A pasted key may carry a no-break space or smart quote; refuse it here, not after connecting.
    return len(key) <= 4096 and all(' ' <= c <= '~' for c in key)


def validate_endpoint(config: ProviderConfig) -> None:
    try:
        url = urllib.parse.urlsplit(config.endpoint)
        _ = url.port
    except ValueError as exc:
        raise ProviderError('PT-PROVIDER: invalid endpoint URL') from exc
    if (config.kind not in {'ollama', 'openai'} or not url.hostname or url.username is not None
            or url.password is not None or url.fragment or url.query
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in config.endpoint)):
        raise ProviderError('PT-PROVIDER: endpoint must have no credentials, query, or fragment')
    if config.kind == 'openai':
        if url.scheme != 'https':
            raise ProviderError('PT-PROVIDER: remote endpoints require HTTPS')
    else:
        try:
            address = ipaddress.ip_address(url.hostname)
        except ValueError:
            loopback = url.hostname.lower() == 'localhost'
        else:
            # is_loopback follows the embedded IPv4 address on CPython 3.13 but not on 3.12; refusing every
            # mapped literal keeps the verdict independent of the interpreter (SPEC-41 R11).
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                raise ProviderError(
                    'PT-PROVIDER: IPv4-mapped IPv6 addresses are not accepted; use 127.0.0.1 or [::1]')
            loopback = address.is_loopback
        if url.scheme not in {'http', 'https'} or not loopback:
            raise ProviderError('PT-PROVIDER: Ollama endpoint must use a loopback host')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError('PT-PROVIDER: endpoint redirects are refused; configure the final endpoint')


class _CallLimit(threading.Event):
    """Reads as set once the caller cancelled or the call deadline passed, so a blocked step ends at once."""

    def __init__(self, cancel: threading.Event, deadline: float) -> None:
        super().__init__()
        self._cancel = cancel
        self._deadline = deadline

    def is_set(self) -> bool:
        return self._cancel.is_set() or time.monotonic() > self._deadline


def request_completion(config: ProviderConfig, system_prompt: str, context_payload: str,
                       cancel: threading.Event) -> str:
    validate_endpoint(config)
    if cancel.is_set():
        raise ProviderCancelled(_CANCELLED)
    body = _exchange(_build_request(config, system_prompt, context_payload), cancel)
    if cancel.is_set():
        raise ProviderCancelled(_CANCELLED)
    return _completion_text(config.kind, body)


def _build_request(config: ProviderConfig, system_prompt: str,
                   context_payload: str) -> urllib.request.Request:
    messages = [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': context_payload}]
    endpoint = config.endpoint.rstrip('/')
    if config.kind == 'ollama':
        if not endpoint.endswith('/api/chat'):
            endpoint += '/api/chat'
        payload = {'model': config.model, 'messages': messages, 'stream': False, 'format': 'json'}
    else:
        if not endpoint.endswith('/chat/completions'):
            endpoint += '/chat/completions'
        payload = {'model': config.model, 'messages': messages, 'stream': False,
                   'response_format': {'type': 'json_object'}}
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    if config.api_key and config.kind == 'openai':
        headers['Authorization'] = 'Bearer ' + config.api_key
    return urllib.request.Request(endpoint, json.dumps(payload).encode(), headers, method='POST')


def _exchange(request: urllib.request.Request, cancel: threading.Event) -> bytes:
    # Disable environment proxies so localhost code cannot be forwarded to a remote proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    # The socket timeout bounds one operation only; the deadline bounds the whole exchange (spec: 120 s).
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        # H9: the exchange runs through `interruptible`, so cancel and the deadline are observed within
        # ~0.1 s even while a socket call blocks. The worker owns the response and closes it itself;
        # closing from here would wait for a read that is still blocked.
        return interruptible(partial(_fetch, opener, request, cancel, deadline), _CallLimit(cancel, deadline))
    except Cancelled:
        if cancel.is_set():
            raise ProviderCancelled(_CANCELLED) from None
        raise ProviderError(_CONNECTION_FAILED) from None
    except TooManyAbandoned:
        raise ProviderError('PT-PROVIDER: previous requests are still closing; retry shortly') from None
    except ProviderError:
        raise
    except Exception as exc:
        raise _transport_error(exc) from None


def _fetch(opener: urllib.request.OpenerDirector, request: urllib.request.Request, cancel: threading.Event,
           deadline: float) -> bytes:
    with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
        data = bytearray()
        while True:
            if cancel.is_set():
                raise ProviderCancelled(_CANCELLED)
            if time.monotonic() > deadline:
                raise ProviderError(_CONNECTION_FAILED)
            # read1 returns available bytes so a slow-drip server cannot hold one read open.
            chunk = response.read1(min(_READ_BYTES, MAX_RESPONSE_BYTES + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ProviderError('PT-PROVIDER: response exceeds 2 MiB limit')


def _transport_error(exc: Exception) -> ProviderError:
    """Fixed text for any exception from the HTTP stack; peer-supplied text must never reach the UI."""
    if isinstance(exc, urllib.error.HTTPError):
        exc.close()
        return ProviderError(f'PT-PROVIDER: server returned HTTP {exc.code}')
    cause = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(cause, ssl.SSLError):
        return ProviderError('PT-PROVIDER: TLS handshake or certificate verification failed; '
                             'check the endpoint and its certificate')
    if isinstance(exc, http.client.HTTPException):
        return ProviderError('PT-PROVIDER: server closed the connection or sent an invalid HTTP response')
    if isinstance(exc, OSError):
        return ProviderError(_CONNECTION_FAILED)
    return ProviderError(f'PT-PROVIDER: transport failed unexpectedly ({type(exc).__name__})')


def _completion_text(kind: str, body: bytes) -> str:
    try:
        result = json.loads(body.decode('utf-8'))
        message = result['message'] if kind == 'ollama' else result['choices'][0]['message']
        text = message['content']
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        raise ProviderError('PT-PROVIDER: malformed provider envelope') from None
    if not isinstance(text, str):
        raise ProviderError('PT-PROVIDER: malformed provider envelope')
    return text
