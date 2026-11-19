"""Malformed CSAF redirect targets stay within the typed transport boundary; no network."""
from __future__ import annotations

import hashlib
from io import BytesIO
from types import SimpleNamespace

import pytest

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf.transport import CsafConsent, CsafTransport

URL = 'https://msrc.microsoft.com/csaf/start.json'
NEXT = 'https://msrc.microsoft.com/csaf/next.json'


class Response(BytesIO):
    def __init__(self, status, *, body=b'', headers=None):
        super().__init__(body)
        self.status, self.headers = status, headers or {}


def client_for(*responses):
    calls, cached = [], []

    def opener(url, headers, timeout):
        calls.append(url)
        return responses[len(calls) - 1]

    client = CsafTransport(CsafConsent.for_hosts(['msrc.microsoft.com']), opener=opener,
                           cache=SimpleNamespace(put=cached.append))
    return client, calls, cached


@pytest.mark.parametrize('location', [
    'https://[', '//[::1', 'https://[not-an-ip]/csaf/x', 'https://[127.0.0.1]/csaf/x',
])
def test_malformed_redirect_is_typed_closed_and_not_cached(location):
    response = Response(302, headers={'Location': location})
    client, calls, cached = client_for(response)
    try:
        with pytest.raises(IntelError) as error:
            client.get(URL, 'document')
        assert error.value.code == 'PT-INTEL-CONFIG'
        assert error.value.message == 'invalid URL refused'
    finally:
        assert calls == [URL]
        assert response.closed
        assert cached == []


@pytest.mark.parametrize('location', ['/csaf/next.json', 'next.json', NEXT])
def test_valid_redirect_preserves_exact_requested_and_final_url(location):
    body = b'{"fixture":true}'
    redirect = Response(302, headers={'Location': location})
    success = Response(200, body=body)
    client, calls, cached = client_for(redirect, success)
    result = client.get(URL, 'document')
    assert (result.url, result.final_url, result.body, result.sha256) == (
        URL, NEXT, body, hashlib.sha256(body).hexdigest())
    assert calls == [URL, NEXT] and cached == [result]
    assert redirect.closed and success.closed


@pytest.mark.parametrize('location', [
    'file:///tmp/csaf-unread', 'https://example.invalid/csaf/x', 'https://msrc.microsoft.com:8443/csaf/x',
])
def test_disallowed_redirect_is_refused_before_dispatch(location):
    response = Response(302, headers={'Location': location})
    client, calls, cached = client_for(response)
    with pytest.raises(IntelError) as error:
        client.get(URL, 'document')
    assert error.value.code == 'PT-INTEL-CONFIG'
    assert calls == [URL] and response.closed and cached == []
