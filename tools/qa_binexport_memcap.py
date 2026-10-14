"""Measure BinExport worker memory behaviour under `jobs.run_process(memory_limit_bytes=...)` (SPEC-10b U1/U7).

usage: qa_binexport_memcap.py [--records N] [--caps MiB,MiB,...] [--alloc]

For each cap, a child started through `run_process` (Windows Job Object limit / Linux RLIMIT_AS) runs the
in-process pipeline on a synthetic N-record file (meta + call graph + N tiny string_table records, the §1 DoS
shape) and prints its own peak (Linux VmPeak, Windows peak commit) and outcome. `--alloc` instead grows a
bytearray in 64 MiB steps to 2x the cap, to show what the child sees at the limit. Prints one JSON line per
case for docs/qa.md. Runs from the source tree only; not a test (numbers are machine-specific).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHA = 'c' * 64

PIPELINE_CHILD = r'''
import json, sys, time
from patchtrace.secondary.binexport_limits import BinExportLimits, Budget, peak_memory_bytes
from patchtrace.secondary.binexport_pipeline import inspect_binexport
from patchtrace.secondary.contracts import SecondaryError
src, snap, cap = sys.argv[1], sys.argv[2], int(sys.argv[3])
start = time.perf_counter()
try:
    s = inspect_binexport(src, snap, artifact_sha256='%s', role='older', budget=Budget(),
                          limits=BinExportLimits(memory_bytes=cap))
    outcome = 'ok'
except SecondaryError as exc:
    outcome = f'{exc.code}:{exc.reason}'
except MemoryError:
    outcome = 'MemoryError'
print(json.dumps({'outcome': outcome, 'peak': peak_memory_bytes(), 'seconds': round(time.perf_counter() - start, 2)}))
''' % SHA

ALLOC_CHILD = r'''
import json, sys
from patchtrace.secondary.binexport_limits import peak_memory_bytes
cap, held, step = int(sys.argv[1]), [], 64 * 1024 * 1024
try:
    while sum(map(len, held)) < 2 * cap:
        held.append(bytearray(step))
    outcome = 'no-limit-hit'
except MemoryError:
    outcome = 'MemoryError'
print(json.dumps({'outcome': outcome, 'held_mib': sum(map(len, held)) >> 20, 'peak': peak_memory_bytes()}))
'''


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(number: int, payload: bytes) -> bytes:
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def synthetic(records: int) -> bytes:
    meta = field(2, SHA.encode()) + field(1, b'synthetic.sys') + field(3, b'x86-64')  # id, name, arch
    graph = field(1, b'\x08\x80\x20')  # one vertex, address 0x1000
    return field(1, meta) + field(8, graph) + field(9, b'hello') * records


def main(argv: list[str] | None = None) -> int:
    sys.path.insert(0, str(ROOT / 'src'))
    from patchtrace.jobs import run_process
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--records', type=int, default=2_000_000)
    parser.add_argument('--caps', default='128,192,256,512')
    parser.add_argument('--alloc', action='store_true')
    args = parser.parse_args(argv)
    env = {k: v for k, v in os.environ.items() if k.upper() in {'PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'HOME'}}
    env.update(PYTHONPATH=str(ROOT / 'src'), PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION='upb')
    with tempfile.TemporaryDirectory(prefix='pt-memcap-') as tmp:
        work = Path(tmp)
        src = work / 'synthetic.BinExport'
        if not args.alloc:
            src.write_bytes(synthetic(args.records))
        for cap_mib in (int(c) for c in args.caps.split(',')):
            cap = cap_mib * 1024 * 1024
            snap = work / f'snap-{cap_mib}'
            code = ALLOC_CHILD if args.alloc else PIPELINE_CHILD
            extra = [str(cap)] if args.alloc else [str(src), str(snap), str(cap)]
            started = time.perf_counter()
            res = run_process([sys.executable, '-c', code, *extra], cwd=work, env=env, cancel=threading.Event(),
                              timeout_seconds=300, memory_limit_bytes=cap, separate_streams=True,
                              log_limit=4096, stderr_limit=4096)
            try:
                child = json.loads(res.log_tail.strip().splitlines()[-1])
            except (ValueError, IndexError):
                child = None
            print(json.dumps({'platform': sys.platform, 'mode': 'alloc' if args.alloc else 'pipeline',
                              'records': None if args.alloc else args.records,
                              'file_mib': None if args.alloc else round(src.stat().st_size / 2**20, 2),
                              'cap_mib': cap_mib, 'returncode': res.returncode, 'reason': res.reason,
                              'job_peak': res.peak_memory_bytes, 'child': child,
                              'stderr_tail': res.stderr_tail[-200:], 'wall': round(time.perf_counter() - started, 2)}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
