"""Offline preparation controls; injected copies/engines are not native rz-diff acceptance."""
from __future__ import annotations

import hashlib
import threading
from types import SimpleNamespace

import pytest
from test_secondary_scheduler import GOOD, PyEngine, project

from patchtrace.ingestion import MAX_ARTIFACT_BYTES
from patchtrace.secondary import scheduler
from patchtrace.secondary.bindiff_inputs import copy_and_hash
from patchtrace.secondary.contracts import SecondaryError
from patchtrace.secondary.registry import RawResult


class Reading(PyEngine):
    reads_artifacts = True

    def __init__(self, clock, probe_cost=0):
        super().__init__('unused')
        self.clock, self.probe_cost, self.jobs = clock, probe_cost, []

    def probe(self, env, cancel):
        self.clock[0] += self.probe_cost
        return super().probe(env, cancel)

    def run(self, cap, job):
        self.jobs.append(job)
        return RawResult(0, GOOD.encode(), '', None, None)


def run(tmp_path, monkeypatch, *, copy_cost=0, timeout=10, cancel_during_copy=False, probe_cost=0):
    clock, cancel, limits = [0.0], threading.Event(), []
    engine = Reading(clock, probe_cost)
    monkeypatch.setattr(scheduler, 'time', SimpleNamespace(monotonic=lambda: clock[0]))

    def copy(source, target, *, max_bytes, check=None):
        limits.append(max_bytes)
        clock[0] += copy_cost
        if cancel_during_copy:
            cancel.set()
        if check is not None:
            check()
        data = source.read_bytes()
        target.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    monkeypatch.setattr(scheduler, 'copy_and_hash', copy)
    outcome, = scheduler.run_engines(project(tmp_path), ['rz-diff'], cancel=cancel, env={},
                                    per_engine_timeout={'rz-diff': timeout}, registry={'rz-diff': engine})
    return outcome, engine.jobs, limits


def test_cancel_during_copy_prevents_engine_start(tmp_path, monkeypatch):
    outcome, jobs, _ = run(tmp_path, monkeypatch, cancel_during_copy=True)
    assert outcome.run.status == 'cancelled' and outcome.run.error_code == 'PT-SECONDARY-CANCEL'
    assert not jobs and outcome.match_set is None


def test_preparation_exhausts_engine_deadline(tmp_path, monkeypatch):
    outcome, jobs, _ = run(tmp_path, monkeypatch, copy_cost=10)
    assert outcome.run.status == 'timeout' and outcome.run.error_code == 'PT-SECONDARY-TIMEOUT'
    assert not jobs and outcome.match_set is None


def test_copy_consumes_budget_but_probe_is_outside_it(tmp_path, monkeypatch):
    outcome, jobs, limits = run(tmp_path, monkeypatch, copy_cost=2, probe_cost=100)
    assert outcome.run.status == 'ok' and len(jobs) == 1
    assert jobs[0].deadline_seconds == 6
    assert limits == [MAX_ARTIFACT_BYTES, MAX_ARTIFACT_BYTES]
    assert all(not path.exists() for path in (jobs[0].older, jobs[0].newer))


@pytest.mark.parametrize('size', [0, 3 << 20])
def test_copy_checks_before_read_and_preserves_source_on_cancel(tmp_path, size):
    source, target = tmp_path / 'source.bin', tmp_path / 'private.bin'
    data = b'x' * size
    source.write_bytes(data)

    def cancel():
        raise SecondaryError('PT-SECONDARY-CANCEL', 'cancelled')

    with pytest.raises(SecondaryError) as caught:
        copy_and_hash(source, target, check=cancel)
    assert caught.value.code == 'PT-SECONDARY-CANCEL'
    assert source.read_bytes() == data
    assert not target.exists() or target.stat().st_size == 0


def test_copy_checks_between_chunks(tmp_path):
    source, target = tmp_path / 'source.bin', tmp_path / 'private.bin'
    data = b'x' * (3 << 20)
    source.write_bytes(data)
    calls = []

    def cancel():
        calls.append(1)
        if len(calls) == 2:
            raise SecondaryError('PT-SECONDARY-CANCEL', 'cancelled')

    with pytest.raises(SecondaryError):
        copy_and_hash(source, target, check=cancel)
    assert len(calls) == 2 and target.stat().st_size == 1 << 20
    assert source.read_bytes() == data
    assert copy_and_hash(source, tmp_path / 'complete.bin', check=lambda: None) == hashlib.sha256(data).hexdigest()
