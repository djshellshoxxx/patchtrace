"""Issue #120 P2: rz-diff artifact preparation honours cancellation and the engine deadline, and its copy cap is the
import cap (not 1 TiB). Offline; the slow copy is injected."""
from __future__ import annotations

import hashlib
import threading
import time

import pytest
from test_secondary_scheduler import OLD_BYTES, PyEngine, project

from patchtrace.ingestion import MAX_ARTIFACT_BYTES
from patchtrace.secondary import scheduler
from patchtrace.secondary.bindiff_inputs import copy_and_hash
from patchtrace.secondary.contracts import SecondaryError


class Reading(PyEngine):
    reads_artifacts = True
    ran = False

    def run(self, cap, job):
        type(self).ran = True
        return super().run(cap, job)


@pytest.fixture(autouse=True)
def _reset():
    Reading.ran = False


def slow_copier(cancel_after_chunk: threading.Event | None = None):
    """A copier that 'reads chunks' forever and only stops when its `check` hook raises (bounded to 10 s)."""
    seen = {'max_bytes': None, 'chunks': 0}

    def fake(source, target, *, max_bytes, check=None):
        seen['max_bytes'] = max_bytes
        end = time.monotonic() + 10
        while time.monotonic() < end:
            seen['chunks'] += 1
            if cancel_after_chunk is not None:
                cancel_after_chunk.set()
            if check is not None:
                check()
            time.sleep(0.01)
        target.write_bytes(OLD_BYTES)
        return hashlib.sha256(OLD_BYTES).hexdigest()
    return fake, seen


def run(tmp_path, monkeypatch, fake, *, cancel, timeout=30.0):
    monkeypatch.setattr(scheduler, 'copy_and_hash', fake)
    return scheduler.run_engines(
        project(tmp_path), ['rz-diff'], cancel=cancel, env={}, per_engine_timeout={'rz-diff': timeout},
        registry={'rz-diff': Reading('exit 0')})[0]


def test_a120_cancel_during_the_copy_stops_it_before_the_engine_starts(tmp_path, monkeypatch):
    cancel = threading.Event()
    fake, seen = slow_copier(cancel)
    started = time.monotonic()
    out = run(tmp_path, monkeypatch, fake, cancel=cancel)
    assert out.run.status == 'cancelled' and not Reading.ran
    assert time.monotonic() - started < 5 and seen['chunks'] >= 1


def test_a120_the_engine_deadline_covers_the_copy(tmp_path, monkeypatch):
    fake, _ = slow_copier()
    started = time.monotonic()
    out = run(tmp_path, monkeypatch, fake, cancel=threading.Event(), timeout=0.2)
    assert out.run.status == 'timeout' and not Reading.ran
    assert time.monotonic() - started < 5


def test_a120_the_copy_cap_is_the_import_cap(tmp_path, monkeypatch):
    seen = {}

    def fake(source, target, *, max_bytes, check=None):
        seen['max_bytes'] = max_bytes
        raise SecondaryError('PT-SECONDARY-LIMIT', 'stop here')
    run(tmp_path, monkeypatch, fake, cancel=threading.Event())
    assert seen['max_bytes'] <= MAX_ARTIFACT_BYTES


def test_a120_copy_and_hash_calls_its_check_between_chunks_and_removes_nothing_silently(tmp_path):
    source = tmp_path / 's.bin'
    source.write_bytes(b'x' * (3 << 20))
    calls = []

    def check():
        calls.append(1)
        if len(calls) == 2:
            raise SecondaryError('PT-SECONDARY-CANCEL', 'cancelled')
    with pytest.raises(SecondaryError) as caught:
        copy_and_hash(source, tmp_path / 'd.bin', check=check)
    assert caught.value.code == 'PT-SECONDARY-CANCEL' and len(calls) == 2
    assert copy_and_hash(source, tmp_path / 'e.bin', check=lambda: None) == hashlib.sha256(b'x' * (3 << 20)).hexdigest()
