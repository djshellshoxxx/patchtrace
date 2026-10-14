"""Optional, bounded HTTP transports. Credentials live only in session objects."""
from __future__ import annotations

import ipaddress
import json
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
        if len(self.api_key) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in self.api_key):
            raise ProviderError('PT-PROVIDER: invalid credential')


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
            loopback = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            loopback = url.hostname.lower() == 'localhost'
        if url.scheme not in {'http', 'https'} or not loopback:
            raise ProviderError('PT-PROVIDER: Ollama endpoint must use a loopback host')


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ProviderError('PT-PROVIDER: endpoint redirects are refused; configure the final endpoint')


def request_completion(config: ProviderConfig, system_prompt: str, context_payload: str,
                       cancel: threading.Event) -> str:
    validate_endpoint(config)
    if cancel.is_set():
        raise ProviderCancelled('PT-CANCEL: interpretation cancelled')
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
    request = urllib.request.Request(endpoint, json.dumps(payload).encode(), headers, method='POST')
    # Disable environment proxies so localhost code cannot be forwarded to a remote proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    # The socket timeout bounds each read only; the deadline bounds the whole exchange (spec: 120 s).
    deadline = time.monotonic() + TIMEOUT_SECONDS
    try:
        # H9: connect and each read run through `interruptible`, so cancel is observed within ~0.1 s
        # even while the socket call blocks; the connection is closed on cancel.
        try:
            response = interruptible(lambda: opener.open(request, timeout=TIMEOUT_SECONDS), cancel,
                                     cleanup=lambda r: r.close())
        except Cancelled:
            raise ProviderCancelled('PT-CANCEL: interpretation cancelled') from None
        except TooManyAbandoned:
            raise ProviderError('PT-PROVIDER: previous requests are still closing; retry shortly') from None
        with response:
            data = bytearray()
            while True:
                if cancel.is_set():
                    raise ProviderCancelled('PT-CANCEL: interpretation cancelled')
                if time.monotonic() > deadline:
                    raise ProviderError('PT-PROVIDER: connection failed or timed out; check endpoint and server')
                # read1 returns available bytes so a slow-drip server cannot hold one read open.
                size = min(65536, MAX_RESPONSE_BYTES + 1 - len(data))
                try:
                    chunk = interruptible(partial(response.read1, size), cancel)
                except Cancelled:
                    raise ProviderCancelled('PT-CANCEL: interpretation cancelled') from None
                except TooManyAbandoned:
                    raise ProviderError('PT-PROVIDER: previous requests are still closing; retry shortly') from None
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise ProviderError('PT-PROVIDER: response exceeds 2 MiB limit')
        if cancel.is_set():
            raise ProviderCancelled('PT-CANCEL: interpretation cancelled')
        result = json.loads(data.decode('utf-8'))
        if config.kind == 'ollama':
            text = result['message']['content']
        else:
            text = result['choices'][0]['message']['content']
        if not isinstance(text, str):
            raise ValueError('content is not text')
        return text
    except ProviderError:
        raise
    except urllib.error.HTTPError as exc:
        raise ProviderError(f'PT-PROVIDER: server returned HTTP {exc.code}') from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise ProviderError('PT-PROVIDER: connection failed or timed out; check endpoint and server') from None
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):
        raise ProviderError('PT-PROVIDER: malformed provider envelope') from None
