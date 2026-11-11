"""Total query deadlines over real SQLite rows; the clock never sleeps."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from diaphora_support import make_result, row

from patchtrace.diaphora import sqlite_guard as guard
from patchtrace.diaphora.contracts import DiaphoraError


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=1000.0)
    monkeypatch.setattr(guard, 'time', SimpleNamespace(monotonic=lambda: state.now))
    return state


def test_slow_row_consumption_cannot_refresh_query_budget(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row() for _ in range(150)])
    seen = []
    with guard.open_snapshot(path) as snap:
        with pytest.raises(DiaphoraError) as failure:
            for item in snap.rows('results', 150):
                seen.append(item)
                clock.now += 1.0
        assert failure.value.code == 'PT-DIAPHORA-LIMIT'
    assert 0 < len(seen) < 150


def test_other_query_does_not_extend_active_rows_deadline(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row(), row(), row()])
    with guard.open_snapshot(path) as snap:
        rows = snap.rows('results', 3)
        next(rows)
        clock.now += guard.DEADLINE_SECONDS - 1
        assert snap.count('results') == 3
        clock.now += 2
        with pytest.raises(DiaphoraError) as failure:
            next(rows)
        assert failure.value.code == 'PT-DIAPHORA-LIMIT'


def test_each_new_query_has_its_own_budget(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row(), row()])
    with guard.open_snapshot(path) as snap:
        assert len(list(snap.rows('results', 2))) == 2
        clock.now += 10 * guard.DEADLINE_SECONDS
        assert snap.count('results') == 2
        assert len(list(snap.rows('results', 2))) == 2


def test_elapsed_execution_is_checked_before_first_row(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row()])
    with guard.open_snapshot(path) as snap:
        def elapsed(_sql):
            clock.now += guard.DEADLINE_SECONDS + 1
        snap.conn.set_trace_callback(elapsed)
        with pytest.raises(DiaphoraError) as failure:
            next(snap.rows('results', 1))
        assert failure.value.code == 'PT-DIAPHORA-LIMIT'


def test_last_row_processing_remains_within_query_budget(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row()])
    with guard.open_snapshot(path) as snap:
        rows = snap.rows('results', 1)
        next(rows)
        clock.now += guard.DEADLINE_SECONDS + 1
        with pytest.raises(DiaphoraError) as failure:
            next(rows)
        assert failure.value.code == 'PT-DIAPHORA-LIMIT'


def test_cancel_interrupts_small_iterator_below_sqlite_progress_interval(tmp_path, clock):
    path = make_result(tmp_path / 'result.diaphora', [row(), row(), row()])
    cancel = threading.Event()
    with guard.open_snapshot(path, cancel) as snap:
        rows = snap.rows('results', 3)
        next(rows)
        cancel.set()
        with pytest.raises(DiaphoraError) as failure:
            next(rows)
        assert failure.value.code == 'PT-DIAPHORA-CANCEL'


def test_abandoned_iterator_closes_after_snapshot_exit(tmp_path):
    path = make_result(tmp_path / 'result.diaphora', [row(), row()])
    with guard.open_snapshot(path) as snap:
        rows = snap.rows('results', 2)
        next(rows)
    rows.close()
