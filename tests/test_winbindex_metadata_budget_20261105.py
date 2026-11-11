"""Injected clocks/openers prove metadata operation bounds; no live endpoints."""
from __future__ import annotations

import threading

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_acquisition_transport import META, NAME, Resp, consent

from patchtrace.acquisition import transport as tr
from patchtrace.acquisition.contracts import AcquisitionError

pytestmark = pytest.mark.usefixtures('no_sockets')


def test_metadata_retry_wait_cannot_consume_the_entire_remaining_budget():
    elapsed, calls, sleeps, responses = [0.0], [], [], []

    def opener(*args):
        calls.append(args)
        response = Resp(429, headers={'Retry-After': '60'}) if len(calls) < 3 else Resp(200, b'raw')
        responses.append(response)
        return response

    def sleep(seconds, cancel):
        sleeps.append(seconds)
        elapsed[0] += seconds

    transport = tr.Transport(opener=opener, sleep=sleep, clock=lambda: elapsed[0])
    with pytest.raises(AcquisitionError) as error:
        transport.fetch_metadata(NAME, consent(META))
    assert error.value.code == 'PT-ACQ-NETWORK' and error.value.recoverable
    assert len(calls) == 2 and sleeps == [60.0]
    assert all(response.closed for response in responses)


@pytest.mark.parametrize('cancelled', [False, True], ids=['deadline', 'cancel'])
def test_expired_or_cancelled_headers_are_not_reported_as_not_found(cancelled):
    elapsed, event = [0.0], threading.Event()
    response = Resp(404)

    def opener(*args):
        if cancelled:
            event.set()
        else:
            elapsed[0] = tr.METADATA_DEADLINE
        return response

    transport = tr.Transport(opener=opener, cancel=event, clock=lambda: elapsed[0])
    with pytest.raises(AcquisitionError) as error:
        transport.fetch_metadata(NAME, consent(META))
    assert error.value.code == ('PT-ACQ-CANCEL' if cancelled else 'PT-ACQ-NETWORK')
    assert response.closed


def test_retry_connection_timeout_uses_remaining_metadata_budget():
    elapsed, timeouts, responses = [0.0], [], []

    def opener(method, url, headers, timeout):
        timeouts.append(timeout)
        if len(timeouts) == 1:
            elapsed[0] = tr.METADATA_DEADLINE - 4
            response = Resp(503, headers={'Retry-After': '2'})
        else:
            response = Resp(200, b'raw metadata')
        responses.append(response)
        return response

    transport = tr.Transport(opener=opener, clock=lambda: elapsed[0],
                             sleep=lambda seconds, cancel: elapsed.__setitem__(0, elapsed[0] + seconds))
    result = transport.fetch_metadata(NAME, consent(META))
    assert timeouts == [tr.TIMEOUT, 2.0]
    assert result.body == b'raw metadata' and result.url == META
    assert all(response.closed for response in responses)


def test_overshooting_sleep_never_opens_another_request():
    elapsed, calls = [0.0], []
    response = Resp(503, headers={'Retry-After': '1'})

    def opener(*args):
        calls.append(args)
        return response if len(calls) == 1 else Resp(200, b'raw')

    transport = tr.Transport(opener=opener, clock=lambda: elapsed[0],
                             sleep=lambda *_: elapsed.__setitem__(0, tr.METADATA_DEADLINE + 1))
    with pytest.raises(AcquisitionError) as error:
        transport.fetch_metadata(NAME, consent(META))
    assert error.value.code == 'PT-ACQ-NETWORK' and len(calls) == 1 and response.closed


def test_exhausted_budget_before_first_attempt_never_calls_opener():
    calls, clock_calls = [], []

    def clock():
        clock_calls.append(None)
        return 0 if len(clock_calls) == 1 else tr.METADATA_DEADLINE

    def opener(*args):
        calls.append(args)
        return Resp(404)

    with pytest.raises(AcquisitionError) as error:
        tr.Transport(opener=opener, clock=clock).fetch_metadata(NAME, consent(META))
    assert error.value.code == 'PT-ACQ-NETWORK' and calls == []


def test_within_budget_retry_preserves_delay_headers_and_source(monkeypatch):
    monkeypatch.setattr(tr, 'METADATA_DEADLINE', 5.0)
    elapsed, calls, sleeps = [0.0], [], []
    responses = [Resp(429, headers={'Retry-After': '2'}), Resp(200, b'exact raw')]

    def opener(*args):
        calls.append(args)
        return responses[len(calls) - 1]

    def sleep(seconds, cancel):
        sleeps.append(seconds)
        elapsed[0] += seconds

    result = tr.Transport(opener=opener, clock=lambda: elapsed[0], sleep=sleep).fetch_metadata(NAME, consent(META))
    assert result.body == b'exact raw' and result.url == META
    assert [call[3] for call in calls] == [5.0, 3.0]
    assert all(call[:3] == ('GET', META, {'User-Agent': 'PatchTrace'}) for call in calls)
    assert sleeps == [2.0] and all(response.closed for response in responses)
