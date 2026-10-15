"""QA-CLI performance record: 10k-pair enrichment ranking, large project open, memory and descriptor growth over
repeated opens.

Timings are RECORDED, never asserted against the SPEC-07 objectives (derived-cache hit 500 ms; the measured value is
kept in docs/audits/20261015-qa-cli-persistence.md). Assertions are correctness and bounded-growth checks only."""
from __future__ import annotations

import gc
import importlib.util
import os
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from uuid import uuid4

import pytest
from cli_stress_support import make_sample

from patchtrace.enrichment import pipeline
from patchtrace.enrichment.cache import CacheConfig, DerivedCache
from patchtrace.sample import create_sample
from patchtrace.service import ProjectService

ROOT = Path(__file__).resolve().parents[2]
PAIRS = 10_000
LINES = 100_000
OPEN_CYCLES = 100
MEMORY_GROWTH_LIMIT_BYTES = 1024 * 1024


def _bench_module():
    spec = importlib.util.spec_from_file_location('bench_enrichment', ROOT / 'tools' / 'bench_enrichment.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _peak_rss_mib() -> float | None:
    try:
        import resource  # POSIX only; Windows records no figure rather than a false 0
    except ImportError:
        return None
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)  # KiB on Linux


def _record(request, name: str, seconds: float) -> None:
    request.node.user_properties.append((name, round(seconds, 4)))
    print(f'QA-CLI-PERF {name}={seconds:.4f}s', file=sys.stderr)


def test_ranking_10k_pairs_cold_and_cache_hit_are_recorded(request):
    project = _bench_module().build_project(PAIRS, LINES)
    with tempfile.TemporaryDirectory(prefix='qa-cli-perf-') as directory:
        cache = DerivedCache(CacheConfig(root=Path(directory)))
        started = time.perf_counter()
        cold_result = pipeline.run(project, pipeline.PipelineOptions(cache=cache))  # first run fills the cache
        cold = time.perf_counter() - started
        assert cold_result.status.status == 'complete'
        assert len(cold_result.ranking.entries) == PAIRS
        started = time.perf_counter()
        hit_result = pipeline.run(project, pipeline.PipelineOptions(cache=cache))
        hit = time.perf_counter() - started
    assert hit_result.ranking == cold_result.ranking, 'a cache hit must reproduce the cold ranking exactly'
    _record(request, 'ranking_10k_cold_with_cache_write_seconds', cold)
    _record(request, 'ranking_10k_cache_hit_seconds', hit)
    _record(request, 'spec07_cache_hit_objective_seconds', 0.5)
    peak = _peak_rss_mib()
    if peak is not None:  # process-lifetime peak: includes the fixture build, so an upper bound for the run
        request.node.user_properties.append(('process_peak_rss_mib', peak))
        print(f'QA-CLI-PERF process_peak_rss_mib={peak}', file=sys.stderr)


def test_large_project_open_time_is_recorded(tmp_path, request):
    service = create_sample(tmp_path / 'large')
    template = service.project.matches[0]
    matches = list(service.project.matches)
    for _ in range(10_000 - len(matches)):
        matches.append(template.model_copy(update={
            'id': uuid4().hex,
            'older': [f.model_copy(update={'id': uuid4().hex}) for f in template.older],
            'newer': [f.model_copy(update={'id': uuid4().hex}) for f in template.newer]}))
    service.project = service.store.save(service.project.model_copy(
        update={'matches': matches, 'interpretations': [], 'annotations': []}))
    path = service.root
    service.close()
    started = time.perf_counter()
    reopened = ProjectService.open(path)
    elapsed = time.perf_counter() - started
    try:
        assert len(reopened.project.matches) == 10_000
    finally:
        reopened.close()
    _record(request, 'open_10k_matches_seconds', elapsed)


def test_repeated_opens_do_not_grow_memory_or_descriptors(tmp_path, request):
    root = make_sample(tmp_path / 'case')
    for _ in range(20):  # warm caches (imports, pydantic schemas) before the baseline
        ProjectService.open(root).close()
    gc.collect()
    tracemalloc.start()
    try:
        baseline = tracemalloc.get_traced_memory()[0]
        for _ in range(OPEN_CYCLES):
            ProjectService.open(root).close()
        gc.collect()
        growth = tracemalloc.get_traced_memory()[0] - baseline
    finally:
        tracemalloc.stop()
    request.node.user_properties.append(('traced_growth_bytes', growth))
    assert growth < MEMORY_GROWTH_LIMIT_BYTES, f'{growth} bytes retained after {OPEN_CYCLES} open/close cycles'


@pytest.mark.skipif(not os.path.isdir('/proc/self/fd'), reason='descriptor table is read from /proc (Linux)')
def test_repeated_opens_leak_no_descriptors(tmp_path):
    root = make_sample(tmp_path / 'case')
    before = len(os.listdir('/proc/self/fd'))
    for _ in range(OPEN_CYCLES):
        ProjectService.open(root).close()
    assert len(os.listdir('/proc/self/fd')) <= before
