"""Benchmark-style regression gates for the derived-cache objective (SPEC-07 §14). Synthetic workload
from tools/bench_enrichment.py; local Linux numbers are recorded in docs/qa.md.

Deterministic guards catch the regressions that matter (a cache hit re-running detectors or the line
alignment, WIL scanning flag-free functions, the collector left disabled); the wall-clock ceilings are
deliberately generous (several times the local measurement) so slow CI runners never flake.
"""
from __future__ import annotations

import gc
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from bench_enrichment import build_project  # noqa: E402

from patchtrace.enrichment import pipeline, signals, views, wil  # noqa: E402
from patchtrace.enrichment.cache import CacheConfig, DerivedCache  # noqa: E402

PAIRS = 2000
HIT_CEILING = 5.0   # seconds; measured about 0.25 s locally
COLD_CEILING = 20.0  # seconds; measured about 1.2 s locally


@pytest.fixture(scope='module')
def project():
    return build_project(PAIRS, PAIRS * 10)


def _best(fn, repeat=2):
    best = float('inf')
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - start)
    return best


def test_cache_hit_runs_no_detector_and_no_alignment(project, tmp_path, monkeypatch):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    options = pipeline.PipelineOptions(cache=cache)
    cold = pipeline.run(project, options)
    calls = {'detect': 0, 'hunks': 0}
    real_detect, real_hunks = signals.detect, views.diff_hunks

    def detect(*a, **k):
        calls['detect'] += 1
        return real_detect(*a, **k)

    def hunks(*a, **k):
        calls['hunks'] += 1
        return real_hunks(*a, **k)
    monkeypatch.setattr(signals, 'detect', detect)
    monkeypatch.setattr(views, 'diff_hunks', hunks)
    hit = pipeline.run(project, options)
    assert calls == {'detect': 0, 'hunks': 0}
    assert hit.ranking == cold.ranking and hit.stage_ids == cold.stage_ids


def test_wil_skips_flag_free_functions(project, monkeypatch):
    cleaned = []
    real = wil.clean_lines
    monkeypatch.setattr(wil, 'clean_lines', lambda lines: cleaned.append(1) or real(lines))
    sample = project.model_copy(update={'matches': project.matches[:50]})
    result = pipeline.run(sample)
    assert cleaned == [] and result.transitions == ()


def test_collector_state_restored(project):
    assert gc.isenabled()
    small = project.model_copy(update={'matches': project.matches[:20]})
    pipeline.run(small)
    assert gc.isenabled()
    gc.disable()
    try:
        pipeline.run(small)
        assert not gc.isenabled()  # a caller's own setting is respected
    finally:
        gc.enable()
    errors = []

    def worker():
        try:
            pipeline.run(small)
        except Exception as exc:  # noqa: BLE001 - reported below
            errors.append(exc)
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == [] and gc.isenabled()


def test_cache_hit_and_cold_within_ceilings(project, tmp_path):
    cache = DerivedCache(CacheConfig(root=tmp_path / 'cache'))
    options = pipeline.PipelineOptions(cache=cache)
    cold = _best(lambda: pipeline.run(project), repeat=1)
    pipeline.run(project, options)
    hit = _best(lambda: pipeline.run(project, options))
    assert cold < COLD_CEILING, f'cold pipeline {cold:.2f} s for {PAIRS} pairs'
    assert hit < HIT_CEILING, f'derived-cache hit {hit:.2f} s for {PAIRS} pairs'
    assert hit < cold, f'cache hit ({hit:.2f} s) not faster than a cold run ({cold:.2f} s)'
