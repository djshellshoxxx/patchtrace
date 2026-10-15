"""B3 bounded transport. All tests use an injected fake opener: no live network."""
from __future__ import annotations

import threading
import urllib.request

import pytest

from patchtrace.enrichment import intelligence as it
from patchtrace.enrichment.contracts import EnrichmentError

CVE = 'CVE-2024-38063'
BODY = b'{"synthetic": true}'
KEY = 'sk-SESSION-SECRET-123'


class Resp:
    def __init__(self, status=200, body=BODY, headers=None, chunk=None):
        self.status = status
        self.headers = headers or {}
        self._body = body
        self._chunk = chunk
        self.closed = False

    def read(self, size):
        n = min(size, self._chunk or size)
        out, self._body = self._body[:n], self._body[n:]
        return out

    def close(self):
        self.closed = True


class Opener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        item = self.responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, seconds, cancel):
        self.sleeps.append(seconds)
        self.t += seconds


def run(opener, providers=('nvd',), clock=None, **kw):
    plan = it.plan_requests([CVE], providers)
    clock = clock or Clock()
    return it.fetch(plan, it.FetchConsent.for_plan(plan), opener=opener, clock=clock, sleep=clock.sleep, **kw)


def code(exc_info):
    return exc_info.value.code


# --- planning ---------------------------------------------------------------

def test_plan_exact_urls_and_headers_without_secret():
    plan = it.plan_requests([CVE, CVE], 'nvd,msrc')
    assert [(p.provider, p.url) for p in plan] == [
        ('msrc', 'https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/CVE-2024-38063'),
        ('nvd', 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38063')]
    assert all(dict(p.headers) == {'Accept': 'application/json', 'User-Agent': 'PatchTrace'} for p in plan)
    assert [p.key_header for p in plan] == [None, 'apiKey']


@pytest.mark.parametrize('bad', ['CVE-2024-123', 'CVE-2024-38063\n', 'CVE-2024-38063/../x', 'cve-2024-38063',
                                 'CVE-2024-' + '1' * 20, 'CVE-2024-38063?x=1', None, 20243806,
                                 'CVE-\uff12\uff10\uff12\uff14-\uff13\uff18\uff10\uff16\uff13',
                                 'CVE-2024-\u0663\u0668\u0660\u0666\u0663'])  # non-ASCII digits
def test_invalid_cve_rejected_before_any_io(bad):
    opener = Opener()
    with pytest.raises(EnrichmentError) as exc:
        plan = it.plan_requests([bad], ['nvd'])
        it.fetch(plan, it.FetchConsent.for_plan(plan), opener=opener)
    assert code(exc) == 'PT-ENRICH-INPUT' and opener.calls == []


def test_plan_limits_and_providers():
    with pytest.raises(EnrichmentError):
        it.plan_requests([], ['nvd'])
    with pytest.raises(EnrichmentError):
        it.plan_requests([CVE], ['nvd', 'evil'])
    with pytest.raises(EnrichmentError):
        it.plan_requests([CVE], [])
    with pytest.raises(EnrichmentError) as exc:
        it.plan_requests([f'CVE-2024-{1000 + i}' for i in range(65)], ['nvd'])
    assert code(exc) == 'PT-ENRICH-LIMIT'


def test_consent_must_cover_every_url_and_provider():
    plan = it.plan_requests([CVE], ['nvd', 'msrc'])
    partial = it.FetchConsent.for_plan(plan[:1])
    opener = Opener()
    with pytest.raises(EnrichmentError) as exc:
        it.fetch(plan, partial, opener=opener)
    assert code(exc) == 'PT-ENRICH-CONFIG' and opener.calls == []


def test_tampered_plan_rejected():
    plan = it.plan_requests([CVE], ['nvd'])
    forged = (it.PlannedRequest('nvd', CVE, 'https://services.nvd.nist.gov/x?path=/etc', plan[0].headers, 'apiKey'),)
    consent = it.FetchConsent(('nvd',), frozenset({forged[0].url}))
    opener = Opener()
    with pytest.raises(EnrichmentError):
        it.fetch(forged, consent, opener=opener)
    assert opener.calls == []


# --- privacy and secrets -----------------------------------------------------

def test_privacy_requests_contain_only_cve_and_key_header():
    opener = Opener(Resp(), Resp())
    result = run(opener, providers=('nvd', 'msrc'), api_key=KEY)
    (msrc_url, msrc_headers, _), (nvd_url, nvd_headers, _) = opener.calls
    for url in (msrc_url, nvd_url):
        assert url.endswith(CVE) and url.count('?') <= 1
    assert msrc_headers == {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
    assert nvd_headers == {'Accept': 'application/json', 'User-Agent': 'PatchTrace', 'apiKey': KEY}
    raw = result[CVE]['nvd']
    assert KEY not in repr(result) and KEY not in raw.url and raw.sha256 == it.hashlib.sha256(BODY).hexdigest()
    assert raw.retrieved_at.endswith('Z')


def test_key_absent_without_key_and_never_in_errors():
    opener = Opener(Resp())
    run(opener)
    assert 'apiKey' not in opener.calls[0][1]
    with pytest.raises(EnrichmentError) as exc:
        run(Opener(Resp(status=403), Resp(status=403), Resp(status=403)), api_key=KEY)
    assert KEY not in str(exc.value) and exc.value.__cause__ is None
    with pytest.raises(EnrichmentError):
        run(Opener(), api_key='bad key\n')


def test_key_not_forwarded_across_hosts_on_redirect():
    opener = Opener(Resp(status=302, headers={'Location': 'https://api.msrc.microsoft.com/x'}), Resp())
    run(opener, api_key=KEY)
    assert 'apiKey' in opener.calls[0][1] and 'apiKey' not in opener.calls[1][1]


def test_environment_proxies_ignored(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:8080')
    monkeypatch.setenv('ALL_PROXY', 'http://proxy.invalid:8080')
    director = it.build_urllib_opener()
    # Without ProxyHandler({}) urllib would install an env-configured ProxyHandler here.
    assert any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
               for h in urllib.request.build_opener().handlers)  # control: env proxy is picked up
    assert not [h for h in director.handlers if isinstance(h, urllib.request.ProxyHandler)]


# --- redirects, limits ---------------------------------------------------------

def test_redirect_within_allowlist_followed_and_recorded():
    target = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38063&x=1'
    opener = Opener(Resp(status=301, headers={'Location': target}), Resp())
    assert run(opener)[CVE]['nvd'].url == target


@pytest.mark.parametrize('location', ['https://evil.example/x', 'http://services.nvd.nist.gov/x',
                                      'https://services.nvd.nist.gov:8443/x', 'https://u:p@services.nvd.nist.gov/'])
def test_redirect_off_allowlist_refused(location):
    opener = Opener(Resp(status=302, headers={'Location': location}))
    with pytest.raises(EnrichmentError) as exc:
        run(opener)
    assert code(exc) == 'PT-ENRICH-NETWORK' and len(opener.calls) == 1


def test_redirect_limit():
    hop = {'Location': 'https://services.nvd.nist.gov/again'}
    opener = Opener(*[Resp(status=307, headers=hop) for _ in range(4)])
    with pytest.raises(EnrichmentError):
        run(opener)
    assert len(opener.calls) == 4  # original + 3 redirects


def test_oversized_stream_stopped_at_cap():
    resp = Resp(body=b'x' * (it.MAX_RESPONSE_BYTES + 10), chunk=1 << 20)
    with pytest.raises(EnrichmentError) as exc:
        run(Opener(resp))
    assert code(exc) == 'PT-ENRICH-LIMIT' and resp.closed
    assert len(resp._body) == 10 - 1  # read stopped one byte past the cap


def test_content_length_over_cap_rejected_before_read():
    resp = Resp(headers={'Content-Length': str(it.MAX_RESPONSE_BYTES + 1)})
    with pytest.raises(EnrichmentError):
        run(Opener(resp))
    assert resp._body == BODY


def test_non_200_not_retried():
    opener = Opener(Resp(status=404), Resp())
    with pytest.raises(EnrichmentError) as exc:
        run(opener)
    assert code(exc) == 'PT-ENRICH-PROVIDER' and len(opener.calls) == 1


def test_connection_error_not_retried():
    opener = Opener(ConnectionError('x'), Resp())
    with pytest.raises(EnrichmentError) as exc:
        run(opener)
    assert code(exc) == 'PT-ENRICH-NETWORK' and len(opener.calls) == 1


def test_malformed_body_returned_without_retry():
    opener = Opener(Resp(body=b'{not json'), Resp())
    assert run(opener)[CVE]['nvd'].body == b'{not json' and len(opener.calls) == 1


# --- retry --------------------------------------------------------------------

def test_retry_on_503_then_success_with_backoff():
    clock = Clock()
    opener = Opener(Resp(status=503), TimeoutError(), Resp())
    run(opener, clock=clock)
    # H10: NVD pacing tops each backoff up to the 6 s keyless spacing (deliberate re-baseline).
    assert len(opener.calls) == 3 and clock.sleeps == [1.0, 5.0, 2.0, 4.0]


def test_retry_after_honoured_and_attempts_capped():
    clock = Clock()
    opener = Opener(*[Resp(status=429, headers={'Retry-After': '5'}) for _ in range(4)])
    with pytest.raises(EnrichmentError) as exc:
        run(opener, clock=clock)
    assert code(exc) == 'PT-ENRICH-NETWORK' and exc.value.recoverable
    assert len(opener.calls) == 3 and clock.sleeps == [5.0, 1.0, 5.0, 1.0]


def test_retry_after_over_60_not_waited():
    clock = Clock()
    opener = Opener(Resp(status=503, headers={'Retry-After': '61'}), Resp())
    with pytest.raises(EnrichmentError):
        run(opener, clock=clock)
    assert clock.sleeps == [] and len(opener.calls) == 1


def test_retry_that_would_exceed_total_timeout_refused():
    clock = Clock()
    clock.t = 0.0
    opener = Opener(Resp(status=503, headers={'Retry-After': '31'}), Resp())
    with pytest.raises(EnrichmentError):
        run(opener, clock=clock)
    assert clock.sleeps == []


def test_connect_timeout_passed_and_bounded():
    opener = Opener(Resp())
    run(opener)
    assert opener.calls[0][2] == it.CONNECT_TIMEOUT


def test_cancel_during_backoff_sleep():
    cancel = threading.Event()
    clock = Clock()

    def sleep(seconds, ev):
        assert ev is cancel
        cancel.set()

    plan = it.plan_requests([CVE], ['nvd'])
    opener = Opener(Resp(status=502), Resp())
    with pytest.raises(EnrichmentError) as exc:
        it.fetch(plan, it.FetchConsent.for_plan(plan), opener=opener, cancel=cancel, clock=clock, sleep=sleep)
    assert code(exc) == 'PT-ENRICH-CANCEL' and len(opener.calls) == 1


def test_cancel_before_start_makes_no_request():
    cancel = threading.Event()
    cancel.set()
    opener = Opener(Resp())
    with pytest.raises(EnrichmentError):
        run(opener, cancel=cancel)
    assert opener.calls == []


def test_default_sleep_is_cancellable():
    cancel = threading.Event()
    cancel.set()
    it._default_sleep(30, cancel)  # returns immediately when cancelled


def test_transport_imports_no_qt():
    import sys
    assert 'PySide6' not in {m.split('.')[0] for m in sys.modules if m.startswith('patchtrace.enrichment.intel')}


# --- partial results (audit round 3) ---------------------------------------

def test_fetch_all_keeps_successful_provider_when_other_fails():
    plan = it.plan_requests([CVE], ('msrc', 'nvd'))  # msrc first
    clock = Clock()
    results, errors = it.fetch_all(plan, it.FetchConsent.for_plan(plan), opener=Opener(Resp(404), Resp()),
                                   clock=clock, sleep=clock.sleep)
    assert set(results[CVE]) == {'nvd'} and results[CVE]['nvd'].body == BODY
    assert set(errors) == {(CVE, 'msrc')} and errors[(CVE, 'msrc')].code == 'PT-ENRICH-PROVIDER'


def test_fetch_all_cancellation_aborts_immediately():
    plan = it.plan_requests([CVE], ('msrc', 'nvd'))
    cancel = threading.Event()
    cancel.set()
    opener = Opener(Resp(), Resp())
    with pytest.raises(EnrichmentError) as exc:
        it.fetch_all(plan, it.FetchConsent.for_plan(plan), opener=opener, cancel=cancel)
    assert code(exc) == 'PT-ENRICH-CANCEL' and opener.calls == []


def test_fetch_remains_fail_fast():
    plan = it.plan_requests([CVE], ('msrc', 'nvd'))
    opener = Opener(Resp(404), Resp())
    with pytest.raises(EnrichmentError):
        it.fetch(plan, it.FetchConsent.for_plan(plan), opener=opener)
    assert len(opener.calls) == 1


def test_malformed_redirect_location_is_typed_and_batch_survives():
    bad = Resp(status=302, headers={'Location': 'https://[x'})
    plan = it.plan_requests([CVE], ('msrc', 'nvd'))
    clock = Clock()
    results, errors = it.fetch_all(plan, it.FetchConsent.for_plan(plan), opener=Opener(bad, Resp()),
                                   clock=clock, sleep=clock.sleep)
    assert set(results[CVE]) == {'nvd'}
    assert errors[(CVE, 'msrc')].code == 'PT-ENRICH-NETWORK' and '[x' not in str(errors[(CVE, 'msrc')])
