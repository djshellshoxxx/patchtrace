"""C6 §9 performance bound: 10k matches, 2 secondary engines, load+assess+build off the GUI thread.

Generous 5x wall-clock ceiling over the spec target (1.5 s) so shared CI runners do not flake; the
quadratic lookup this guards against grows to minutes at this size.
"""
from __future__ import annotations

import time

from test_evidence_view import bd, gmatch, mset, rz

from patchtrace.secondary.evidence_view import build_view_model, filter_rows

N = 10_000


def test_ten_thousand_matches_build_within_bound():
    matches = [gmatch(f'm{i:05}', f'{0x10000 + i:x}', f'{0x20000 + i:x}', f'fn{i}') for i in range(N)]
    sets = (mset('bindiff', *[bd(0x10000 + i, 0x20000 + (i if i % 7 else i + 1), sim=i % 1000)
                              for i in range(N)]),
            mset('rz-diff', *[rz(0x10000 + i, 0x20000 + i, sim=(i * 7) % 1000) for i in range(0, N, 3)]))
    start = time.perf_counter()
    vm = build_view_model(project_id='p', run_id='r', revision=0, older_sha256='a' * 64, newer_sha256='b' * 64,
                          matches=matches, sets=sets)
    elapsed = time.perf_counter() - start
    assert len(vm.rows) == N and vm.counts['contested'] > 0
    assert elapsed < 7.5, elapsed
    start = time.perf_counter()
    filter_rows(vm.rows, {'agree', 'contested', 'single-engine', 'unknown'}, '0x1a', True)
    assert time.perf_counter() - start < 0.5
