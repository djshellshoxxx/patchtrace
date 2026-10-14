"""Reproducible enrichment benchmark (SPEC-07 §12 objectives: 10,000 pairs / 100,000 lines).

Synthetic, labelled workload: N modified 1:1 matches, each with ~L/N decompiled lines per side and
one inserted bounds check per pairing, so every detector path does real work. Measures wall time
and peak RSS of views+signals+wil+ranking, and a derived-cache hit. Run from the repository root:

    python tools/bench_enrichment.py [--pairs 10000] [--lines 100000] [--repeat 3] [--json]

`--repeat N` reports the best of N timings per measurement (shared hosts are noisy).
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from pathlib import Path


def build_project(pairs: int, lines: int):
    from patchtrace.models import AnalysisRun, Artifact, ComparisonProject, FunctionMatch, FunctionRecord
    per = max(4, lines // pairs // 2)
    older_art = Artifact(side='older', name='old.sys', sha256='1' * 64, size=1, relative_path=f'artifacts/{"1" * 64}.bin')
    newer_art = Artifact(side='newer', name='new.sys', sha256='2' * 64, size=1, relative_path=f'artifacts/{"2" * 64}.bin')
    run = AnalysisRun(status='completed', raw_path='runs/x/raw.json', raw_sha256='3' * 64)
    matches = []
    for i in range(pairs):
        body = [f'  local_{j} = param_1[{j}] + {j};' for j in range(per - 3)]
        old = '\n'.join([f'int FUN_{i:08x}(int *param_1, uint n) {{', *body, '  memcpy(dst, param_1, n);', '}'])
        new = '\n'.join([f'int FUN_{i:08x}(int *param_1, uint n) {{', *body, '  if (0x40 < n) return -0x3ffffff3;',
                         '  memcpy(dst, param_1, n);', '}'])
        o = FunctionRecord(artifact_id=older_art.id, run_id=run.id, name=f'FUN_{i:08x}', address=f'{0x140001000 + i * 64:x}', code=old)
        n = FunctionRecord(artifact_id=newer_art.id, run_id=run.id, name=f'FUN_{i:08x}', address=f'{0x140001000 + i * 64:x}', code=new)
        matches.append(FunctionMatch(run_id=run.id, older=[o], newer=[n], category='modified', quality='high'))
    return ComparisonProject.model_construct(name='benchmark (synthetic)', artifacts=[older_art, newer_art],
                                             runs=[run], matches=matches, interpretations=[], annotations=[],
                                             revision=0, id='bench', schema_version=1, created='', sample=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--pairs', type=int, default=10_000)
    parser.add_argument('--lines', type=int, default=100_000)
    parser.add_argument('--repeat', type=int, default=1, help='best of N timings per measurement')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    from patchtrace.enrichment import pipeline
    from patchtrace.enrichment.cache import CacheConfig, DerivedCache
    t0 = time.perf_counter()
    project = build_project(args.pairs, args.lines)
    build = time.perf_counter() - t0
    repeat = max(1, args.repeat)
    cold = warm = float('inf')
    for _ in range(repeat):
        t1 = time.perf_counter()
        result = pipeline.run(project)
        cold = min(cold, time.perf_counter() - t1)
    with tempfile.TemporaryDirectory() as directory:
        cache = DerivedCache(CacheConfig(root=Path(directory)))
        pipeline.run(project, pipeline.PipelineOptions(cache=cache))
        for _ in range(repeat):
            t2 = time.perf_counter()
            hit = pipeline.run(project, pipeline.PipelineOptions(cache=cache))
            warm = min(warm, time.perf_counter() - t2)
    try:
        import resource  # POSIX only
        rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except ImportError:
        rss_kib = 0
    report = {
        'workload': 'synthetic', 'pairs': args.pairs, 'lines_total': sum(
            len(f.code.splitlines()) for m in project.matches for f in m.older + m.newer),
        'build_seconds': round(build, 2), 'pipeline_cold_seconds': round(cold, 2),
        'pipeline_cache_hit_seconds': round(warm, 2), 'repeat': repeat, 'peak_rss_mib': round(rss_kib / 1024, 1),
        'status': result.status.status, 'identical_on_hit': hit.ranking == result.ranking,
        'top_score': result.ranking.entries[0].score if result.ranking.entries else None,
        'python': sys.version.split()[0], 'platform': platform.platform(), 'machine': platform.machine(),
    }
    print(json.dumps(report, indent=None if args.json else 2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
