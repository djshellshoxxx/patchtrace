"""H10: NVD pacing, 403 handling and overall deadline (SPEC-07h). Injected clock; no live network."""
import threading
import time

import pytest

from patchtrace.enrichment import intelligence as it
from patchtrace.enrichment.contracts import EnrichmentError

BODY = b'{"synthetic": true}'
KEY = 'sk-SESSION-SECRET-123'
CVES = ['CVE-2024-38063', 'CVE-2024-38064', 'CVE-2024-38065', 'CVE-2024-38066']


class Resp:
    def __init__(self, status=200, headers=None):
        self.status, self.headers, self._body = status, headers or {}, BODY

    def read(self, size):
        out, self._body = self._body[:size], self._body[size:]
        return out

    def close(self):
        pass


class Opener:
    def __init__(self, *responses, default=None):
        self.responses, self.default, self.calls = list(responses), default, []

    def __call__(self, url, headers, timeout):
        self.calls.append(url)
        return self.responses.pop(0) if self.responses else self.default()


class Clock:
    def __init__(self):
        self.t = 0.0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, seconds, cancel):
        self.sleeps.append(seconds)
        self.t += seconds


def go(opener, cves, providers=('nvd',), **kw):
    plan = it.plan_requests(cves, providers)
    clock = Clock()
    result = it.fetch_all(plan, it.FetchConsent.for_plan(plan), opener=opener, clock=clock, sleep=clock.sleep, **kw)
    return result, clock


def test_keyless_nvd_is_spaced_six_seconds():
    opener = Opener(default=Resp)
    (results, errors), clock = go(opener, CVES[:3])
    assert len(opener.calls) == 3 and not errors and len(results) == 3
    assert sum(clock.sleeps) == pytest.approx(12.0)


def test_keyed_nvd_is_spaced_point_six_seconds():
    (results, errors), clock = go(Opener(default=Resp), CVES[:3], api_key=KEY)
    assert sum(clock.sleeps) == pytest.approx(1.2) and not errors


def test_msrc_is_not_paced():
    (results, errors), clock = go(Opener(default=Resp), CVES, providers=('msrc',))
    assert clock.sleeps == [] and len(results) == 4


def test_nvd_403_is_retried_with_backoff_then_succeeds():
    opener = Opener(Resp(403), Resp(403), Resp(200))
    (results, errors), clock = go(opener, CVES[:1])
    assert len(opener.calls) == 3 and not errors and CVES[0] in results and clock.sleeps


def test_nvd_persistent_403_is_recoverable_network_error_without_key_text():
    opener = Opener(default=lambda: Resp(403))
    (results, errors), _ = go(opener, CVES[:1], api_key=KEY)
    exc = errors[(CVES[0], 'nvd')]
    assert exc.code == 'PT-ENRICH-NETWORK' and exc.recoverable and '403' in str(exc) and KEY not in str(exc)
    assert len(opener.calls) == it.MAX_ATTEMPTS


def test_msrc_403_stays_a_provider_error():
    (results, errors), _ = go(Opener(default=lambda: Resp(403)), CVES[:1], providers=('msrc',))
    assert errors[(CVES[0], 'msrc')].code == 'PT-ENRICH-PROVIDER'


def test_overall_deadline_keeps_results_and_fails_the_rest():
    (results, errors), _ = go(Opener(default=Resp), CVES, overall_timeout=10.0)
    assert list(results) == CVES[:2]  # sends at t=0 and t=6; t=12 would pass the 10 s plan deadline
    assert {key[0] for key in errors} == set(CVES[2:])
    assert all(e.code == 'PT-ENRICH-NETWORK' and e.recoverable and 'deadline' in str(e) for e in errors.values())


def test_cancel_during_pacing_sleep_returns_quickly():
    plan = it.plan_requests(CVES[:2], ('nvd',))
    cancel = threading.Event()
    threading.Timer(0.1, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(EnrichmentError) as exc:
        it.fetch_all(plan, it.FetchConsent.for_plan(plan), opener=Opener(default=Resp), cancel=cancel)
    assert exc.value.code == 'PT-ENRICH-CANCEL' and time.monotonic() - start < 2.5  # 5x slack for shared CI; without cancel the 6 s pacing sleep runs


def test_expected_duration_text_for_consent_preview():
    plan = it.plan_requests(CVES, ('nvd', 'msrc'))
    assert it.expected_duration(plan, has_key=False) == pytest.approx(18.0)
    assert it.expected_duration(plan, has_key=True) == pytest.approx(1.8)
    assert 'about 18 seconds' in it.describe_duration(plan, has_key=False)
    assert 'NVD' in it.describe_duration(plan, has_key=False)
    assert it.describe_duration(it.plan_requests(CVES, ('msrc',)), has_key=False) == ''
    many = it.plan_requests([f'CVE-2024-{n:05d}' for n in range(1, 41)], ('nvd',))
    assert 'about 4 minutes' in it.describe_duration(many, has_key=False)
