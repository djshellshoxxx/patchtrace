"""Injected CVRF network-boundary controls; no live source evidence."""
from __future__ import annotations

import threading
from datetime import UTC, datetime

import pytest
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.cvrf_fetch import fetch_months
from patchtrace.kbcorrelation.sources.net_plan import build_plan

pytestmark = pytest.mark.usefixtures('no_sockets')


class Response:
    def __init__(self, status, **headers):
        self.status, self.headers, self.closed = status, headers, False

    def read(self, size):
        return b''

    def close(self):
        self.closed = True


def fetch(plan, opener, **kwargs):
    return list(fetch_months(plan, consent_hosts=plan.hosts, consent_plan=plan.plan_sha,
                             opener=opener, now=lambda: datetime(2099, 2, 15, tzinfo=UTC), **kwargs))


@pytest.mark.parametrize('location', ['https://[', 'https://api.msrc.microsoft.com\uff0fother'])
def test_malformed_redirect_is_a_typed_month_failure_and_later_month_continues(location):
    plan = build_plan(['2099-Feb', '2099-Mar'])
    responses = [Response(302, Location=location), Response(404)]
    calls = []

    def opener(method, url, headers, timeout):
        calls.append(url)
        return responses[len(calls) - 1]

    results = fetch(plan, opener)
    assert [r.state for r in results] == ['failed', 'not-published']
    assert results[0].error.code == 'PT-KBC-SOURCE'
    assert calls == [r.url for r in plan.requests]
    assert all(r.closed for r in responses)


def test_cancel_during_redirect_headers_prevents_followup_request():
    plan = build_plan(['2099-Feb'])
    cancel = threading.Event()
    response = Response(302, Location='/next')
    calls = []

    def opener(method, url, headers, timeout):
        calls.append(url)
        cancel.set()
        return response

    with pytest.raises(SourceError) as error:
        fetch(plan, opener, cancel=cancel)
    assert error.value.code == 'PT-KBC-CANCEL'
    assert len(calls) == 1 and response.closed


def test_deadline_exhausted_during_redirect_headers_prevents_followup_request():
    limits = KbcLimits(request_timeout_s=5, plan_timeout_s=5)
    plan = build_plan(['2099-Feb'], limits=limits)
    elapsed = [0.0]
    response = Response(302, Location='/next')
    calls = []

    def opener(method, url, headers, timeout):
        calls.append(url)
        elapsed[0] = 5.0
        return response

    (result,) = fetch(plan, opener, limits=limits, clock=lambda: elapsed[0])
    assert result.state == 'failed' and result.error.code == 'PT-KBC-ACQUIRE'
    assert len(calls) == 1 and response.closed


@pytest.mark.parametrize('status', [429, 503])
def test_retry_after_beyond_remaining_budget_does_not_sleep_or_reopen(status):
    limits = KbcLimits(request_timeout_s=5, plan_timeout_s=5)
    plan = build_plan(['2099-Feb'], limits=limits)
    elapsed = [0.0]
    response = Response(status, **{'Retry-After': '7'})
    calls, sleeps = [], []

    def opener(method, url, headers, timeout):
        calls.append(url)
        return response

    def sleep(seconds, cancel):
        sleeps.append(seconds)
        elapsed[0] += seconds

    (result,) = fetch(plan, opener, limits=limits, clock=lambda: elapsed[0], sleep=sleep)
    assert result.state == 'failed' and result.error.code == 'PT-KBC-ACQUIRE'
    assert sleeps == [] and len(calls) == 1 and response.closed


def test_redirect_connection_timeout_uses_remaining_document_budget():
    limits = KbcLimits(request_timeout_s=5, plan_timeout_s=5)
    plan = build_plan(['2099-Feb'], limits=limits)
    elapsed, calls = [0.0], []
    responses = [Response(302, Location='/next'), Response(404)]

    def opener(method, url, headers, timeout):
        calls.append(timeout)
        elapsed[0] = 3.0
        return responses[len(calls) - 1]

    (result,) = fetch(plan, opener, limits=limits, clock=lambda: elapsed[0])
    assert result.state == 'not-published'
    assert calls == [5.0, 2.0]
    assert all(r.closed for r in responses)


@pytest.mark.parametrize('retry_after, expected_wait', [('2', 2.0), ('0', 0.0), (None, 1.0)])
def test_retry_within_budget_retains_server_delay_and_can_succeed(retry_after, expected_wait):
    limits = KbcLimits(request_timeout_s=5, plan_timeout_s=5)
    plan = build_plan(['2099-Feb'], limits=limits)
    elapsed, calls, sleeps = [0.0], [], []
    headers = {} if retry_after is None else {'Retry-After': retry_after}
    responses = [Response(429, **headers), Response(200)]

    def opener(method, url, headers, timeout):
        calls.append((url, timeout))
        return responses[len(calls) - 1]

    def sleep(seconds, cancel):
        sleeps.append(seconds)
        elapsed[0] += seconds

    (result,) = fetch(plan, opener, limits=limits, clock=lambda: elapsed[0], sleep=sleep)
    assert result.state == 'fetched'
    assert sleeps == [expected_wait]
    assert calls == [(plan.requests[0].url, 5.0), (plan.requests[0].url, 5.0 - expected_wait)]
    assert all(r.closed for r in responses)


def test_retry_wait_that_overshoots_deadline_never_reopens():
    limits = KbcLimits(request_timeout_s=5, plan_timeout_s=5)
    plan = build_plan(['2099-Feb'], limits=limits)
    elapsed, calls = [0.0], []
    response = Response(503, **{'Retry-After': '1'})

    def opener(method, url, headers, timeout):
        calls.append(url)
        return response

    def sleep(seconds, cancel):
        elapsed[0] = 6.0

    (result,) = fetch(plan, opener, limits=limits, clock=lambda: elapsed[0], sleep=sleep)
    assert result.state == 'failed' and result.error.code == 'PT-KBC-ACQUIRE'
    assert calls == [plan.requests[0].url] and response.closed
