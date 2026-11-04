"""SPEC-28 §9 invariant 3 (amendment H-C): an rz-diff stdout flood is stopped at the stdout limit, not the deadline."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path

import pytest
from test_secondary_scheduler import GOOD, PyEngine, project

from patchtrace.jobs import ProcessResult
from patchtrace.secondary import rzdiff
from patchtrace.secondary.contracts import Capability, SecondaryError
from patchtrace.secondary.registry import EngineJob, RzDiffAdapter
from patchtrace.secondary.scheduler import run_engines

FLOOD = 'import sys\nwhile True:\n    sys.stdout.buffer.write(b"x" * 65536)\n    sys.stdout.buffer.flush()'
CAP = Capability(engine='rz-diff', supported=True, version='0.9.1', path='/opt/rz-diff', supports_json=True)


def capture(seen: dict, result: ProcessResult):
    def runner(argv, **kwargs):
        seen.update(kwargs)
        return result
    return runner


def artifacts(tmp_path: Path) -> tuple[Path, Path, str, str]:
    (tmp_path / 'old').write_bytes(b'old')
    (tmp_path / 'new').write_bytes(b'new')
    return (tmp_path / 'old', tmp_path / 'new', hashlib.sha256(b'old').hexdigest(),
            hashlib.sha256(b'new').hexdigest())


def test_rzdiff_flood_is_stopped_at_the_limit_not_the_deadline(tmp_path):
    started = time.monotonic()
    [out] = run_engines(project(tmp_path), ['rz-diff'], cancel=threading.Event(), env=dict(os.environ),
                        registry={'rz-diff': PyEngine(FLOOD)}, per_engine_timeout={'rz-diff': 30.0},
                        stdout_limit=1000)
    elapsed = time.monotonic() - started
    assert (out.run.status, out.run.error_code) == ('failed', 'PT-SECONDARY-LIMIT')
    assert out.run.provenance.get('failure_kind') == 'output-limit' and out.match_set is None
    assert elapsed < 20


def test_adapter_run_passes_the_job_stdout_limit(tmp_path):
    seen: dict = {}
    job = EngineJob(tmp_path / 'old', tmp_path / 'new', 'a' * 64, 'b' * 64, {}, tmp_path, threading.Event(), 60.0,
                    capture(seen, ProcessResult(0, GOOD)), 1000)
    RzDiffAdapter().run(CAP, job)
    assert seen['max_output_bytes'] == 1000 and seen['log_limit'] == 1001


def test_run_rzdiff_passes_max_output_bytes(tmp_path):
    older, newer, old_sha, new_sha = artifacts(tmp_path)
    seen: dict = {}
    rzdiff.run_rzdiff(CAP, older, newer, old_sha, new_sha, env={}, cancel=threading.Event(),
                      runner=capture(seen, ProcessResult(0, GOOD)))
    assert seen['max_output_bytes'] == rzdiff.STDOUT_LIMIT and seen['log_limit'] == rzdiff.STDOUT_LIMIT + 1


def test_run_rzdiff_maps_output_limit_to_limit(tmp_path):
    older, newer, old_sha, new_sha = artifacts(tmp_path)
    with pytest.raises(SecondaryError) as info:
        rzdiff.run_rzdiff(CAP, older, newer, old_sha, new_sha, env={}, cancel=threading.Event(),
                          runner=capture({}, ProcessResult(-9, 'x' * 100, 'output-limit')))
    assert (info.value.code, info.value.kind) == ('PT-SECONDARY-LIMIT', 'output-limit')
