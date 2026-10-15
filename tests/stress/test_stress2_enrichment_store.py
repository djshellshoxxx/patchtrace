"""QA-S2 enrichment store writers: many publishes through one shared store with lock-serialised threads, the
body-size and non-finite-number refusals, and hostile body text round-trips. Synthetic data, one project per test.
"""
from __future__ import annotations

import os
import threading
import uuid

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.enrichment.storage import MAX_ROW, EnrichmentStore, Guard
from patchtrace.service import ProjectService

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))
HOSTILE = 'line\nbreak \x1b[2J ‮ rtl ​ zero-width \x00 nul ퟿ end'


@pytest.fixture
def shared(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    run = next(r for r in service.project.runs if r.raw_sha256)
    guard = Guard(service.project.id, run.id, run.raw_sha256, 'c' * 64)
    store = EnrichmentStore(service.store)
    store.ensure()
    yield store, guard, service.project.revision
    if not service.store.closed:
        service.close()


def _run_threads(target, count: int) -> None:
    threads = [threading.Thread(target=target, args=(number,)) for number in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


@pytest.mark.xfail(strict=True, reason='QA-S2-2: the project connection is bound to its creating thread (persistence.py '
                   'sqlite3.connect without check_same_thread), so lock-serialised writer threads all fail with '
                   'ProgrammingError')
def test_lock_serialised_writers_keep_every_row(shared):
    store, guard, revision = shared
    gate = threading.Lock()
    per_thread = 20 * SCALE
    failures: list[BaseException] = []

    def writer(number: int) -> None:
        for index in range(per_thread):
            try:
                with gate:
                    store.publish('ranking', guard, guard, revision, 'complete', {'t': number, 'i': index},
                                  f'w{number}-{index}')
            except BaseException as error:  # noqa: BLE001 - collected and asserted below
                failures.append(error)

    _run_threads(writer, 6)
    assert failures == []
    assert len(store.entries('ranking', guard)) == 6 * per_thread


def test_many_small_rows_read_back_exactly(shared):
    store, guard, revision = shared
    count = 1_000 * SCALE
    for index in range(count):
        store.publish('ranking', guard, guard, revision, 'complete', {'i': index}, f'row-{index:06d}')
    rows = store.entries('ranking', guard)
    assert len(rows) == count
    assert sorted(row.body['i'] for row in rows) == list(range(count))


@settings(max_examples=25, deadline=None, database=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
@given(st.text(max_size=200))
def test_hostile_text_round_trips_byte_for_byte(shared, text):
    store, guard, revision = shared
    entry = store.publish('ranking', guard, guard, revision, 'complete', {'text': text}, f'h-{uuid.uuid4().hex}')
    assert entry.body == {'text': text}


def test_hostile_body_round_trips_exactly(shared):
    store, guard, revision = shared
    store.publish('ranking', guard, guard, revision, 'complete', {'text': HOSTILE}, 'hostile-fixed')
    assert store.current('ranking', guard).body == {'text': HOSTILE}


def test_body_over_the_row_cap_is_refused_with_a_typed_error(shared):
    store, guard, revision = shared
    body = {'blob': 'x' * (MAX_ROW + 1024)}
    with pytest.raises(EnrichmentError) as info:
        store.publish('ranking', guard, guard, revision, 'complete', body, 'too-big')
    assert info.value.code.startswith('PT-ENRICH-')


@pytest.mark.xfail(strict=True, reason='QA-S2-3: a non-finite number in a body escapes publish as a raw ValueError '
                   '(json allow_nan=False), not a typed PT-ENRICH-INPUT')
def test_non_finite_number_in_body_is_a_typed_refusal(shared):
    store, guard, revision = shared
    with pytest.raises(EnrichmentError) as info:
        store.publish('ranking', guard, guard, revision, 'complete', {'score': float('nan')}, 'nan-body')
    assert info.value.code == 'PT-ENRICH-INPUT'


def test_unknown_kind_is_a_typed_refusal(shared):
    store, guard, revision = shared
    with pytest.raises(EnrichmentError) as info:
        store.publish('not-a-kind', guard, guard, revision, 'complete', {}, 'bad-kind')
    assert info.value.code == 'PT-ENRICH-INPUT'
