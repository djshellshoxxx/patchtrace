"""G-U5 performance harness (08-evaluation s6, L-35). Dev-only, never shipped, never imported by `src/`.

Every measurement runs in a FRESH process (`measure` spawns `python -P -m tools.unified.bench --child ...`), so the
peak RSS it reports belongs to that one workload. The child writes stdout and stderr to files in a private directory;
only a bounded tail of each is read back, and a child that writes more than `OUTPUT_CAP` bytes is a failed row (U7-13).
The workloads are SYNTHETIC: tests/unified_ir_builder.py for the ladder, tests/unified_extract_builder.py for ingest,
two images hand-assembled by tests/unified_facts_builder.py and placed through the REAL ingest for facts (the newer
side changes one immediate in every function; `compute.compute_stage` runs sources, ladder, fusion, facts and write,
and the row times the span between its `facts` and `write` events), and the in-memory row views of
tests/unified_read_support.py for the read model (filter, sort and first paint: filter, sort, then `cell_text` of the
first 50 rows over every column). They measure the cost of the algorithms, not Ghidra or real binaries. The extractor
is measured by the live workflow (`tools/live_unified_check.py`); `--live-result` turns its result file into
informational `extract` rows.

Gates are L-35 with 5x wall-clock slack on CI (08 s6) and no slack on memory, applied only at the sizes L-35 defines:
ladder 10k and 60k, ingest and worker memory at 60k, facts for 5,000 changed pairs, read-model filter, sort and first
paint at 10k and 100k rows. `--sizes` governs the ladder and ingest; facts and read_model always run at their L-35
sizes (`L35_SIZES`). Other sizes are informational. Exact operation-count checks (budget ticks per function, linear
growth, every changed pair judged, filter and sort consistent) hold at every size. What waits for another slice
(`data()` call counts, which need the Qt table model) is listed as `pending` with its limit, never left out, and so is
a built stage this report did not measure at its L-35 sizes ('not measured in this report'): a ladder-only report
never lets G-U5 pass. Windows numbers come from the Windows runner and the frozen EXE; the Windows RSS branch has not
been run by the author. The report carries `counts_sha256`, a digest of the deterministic counts only, so two runs on
equal code can be compared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from patchtrace.unified.limits import DEFAULT_LIMITS
from tools.calibration.common import canonical_json, strict_json
from tools.calibration.tier_r.contracts import ContractError

CONTRACT = 'bench-report/1'
SLACK = 5                       # 08 s6: CI wall-clock slack
TICKS_PER_FUNCTION = 12         # tests/test_unified_ladder_perf.py: budget ticks stay linear
MAX_LINEAR_RATIO = 7.0          # 6x the functions must cost about 6x the work, never 36x
INSNS = 50                      # 60k functions x 50 instructions = the 3 M instructions of L-35
TIMEOUT_S = 3600
OUTPUT_CAP = 4 * 2**20          # U7-13: bytes a child may write to stdout or to stderr before it is a failed row
TAIL_BYTES = 64 * 2**10         # bytes read back from the end of each of the two files
POLL_S = 0.25                   # how often the parent looks at the output files while the child runs
FACTS_FILLER = 30               # unchanged instructions per facts function (42 instructions in all)
FIRST_PAINT_ROWS = 50           # first paint: filter, sort, then `cell_text` of this many rows over every column
REPEATS = 5                     # a read-model time is the median of this many runs
HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
STAGES = ('ladder', 'ingest', 'facts', 'read_model')
# stages that run at their own L-35 sizes whatever `--sizes` says (it governs the ladder and ingest)
L35_SIZES = {'facts': (5_000,), 'read_model': (10_000, 100_000)}
NOT_MEASURED = 'not measured in this report'
# built stage -> (limit name, limit value, what); pending with NOT_MEASURED until a report measures all its L-35 sizes
BUILT = (
    ('facts', 'l35_facts_5000_s', DEFAULT_LIMITS.l35_facts_5000_s, 'change facts for 5,000 changed pairs'),
    ('read_model', 'l35_first_paint_ms|l35_sort_ms|l35_filter_ms', DEFAULT_LIMITS.l35_first_paint_ms,
     'read-model filter, sort and first paint at 10k and 100k rows'))
# stage -> (needs, limit name, limit value, what); listed, not measured, until the slice exists
PENDING = (
    ('ui_calls', 'S4b', 'l35_first_paint_ms|l35_sort_ms|l35_filter_ms', DEFAULT_LIMITS.l35_first_paint_ms,
     'exact data() call counts for first paint, sort and filter (C6 method; needs the Qt table model)'),)
_READ_GATES = (('l35_filter_ms', 'ms', 'filter'), ('l35_sort_ms', 'ms', 'sort'), ('l35_first_paint_ms', 'ms', 'first_paint'))
# (stage, n) -> ((limit name, unit, observed seconds key), ...): the sizes L-35 defines; memory has no key
GATES = {('ladder', 10_000): (('l35_ladder_10k_s', 's', 'total'),),
         ('ladder', 60_000): (('l35_ladder_60k_s', 's', 'total'), ('l35_worker_rss_bytes', 'bytes', None)),
         ('ingest', 60_000): (('l35_ingest_60k_s', 's', 'ingest'), ('l08_ingest_rss_bytes', 'bytes', None)),
         ('facts', 5_000): (('l35_facts_5000_s', 's', 'facts'),),
         **{('read_model', n): _READ_GATES for n in L35_SIZES['read_model']}}


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class Gate(_Strict):
    name: str
    unit: Literal['s', 'ms', 'bytes']
    limit: int
    slack: int
    allowed: float
    observed: float | None
    verdict: Literal['pass', 'fail', 'not-measured']


class Check(_Strict):
    name: str
    ok: bool
    detail: str


class Row(_Strict):
    stage: Literal['ladder', 'ingest', 'extract', 'facts', 'read_model']
    n: int
    status: Literal['measured', 'failed']
    seconds: dict[str, float]
    peak_rss_bytes: int | None
    counts: dict[str, int | str]
    derived: dict[str, float]
    error: str | None
    gates: tuple[Gate, ...]
    checks: tuple[Check, ...]


class PendingStage(_Strict):
    stage: str
    needs: str
    limit: str
    limit_value: int
    what: str


class BenchReport(_Strict):
    contract: Literal['bench-report/1']
    environment: dict[str, str | int]
    slack: int
    rows: tuple[Row, ...]
    pending: tuple[PendingStage, ...]
    verdict: Literal['pass', 'fail', 'insufficient-data']
    counts_sha256: str


# ---- process facts -----------------------------------------------------------------------------------------------------------

def peak_rss_bytes() -> int | None:
    """Peak resident set of this process: ru_maxrss (KiB on Linux, bytes on macOS) or the Windows peak working set."""
    try:
        if sys.platform == 'win32':
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                            ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                            ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaNonPagedPoolUsage', ctypes.c_size_t), ('PagefileUsage', ctypes.c_size_t),
                            ('PeakPagefileUsage', ctypes.c_size_t)]
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            kernel.GetCurrentProcess.restype = wintypes.HANDLE
            kernel.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            ok = kernel.K32GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
            return int(counters.PeakWorkingSetSize) if ok else None
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(peak) * (1 if sys.platform == 'darwin' else 1024)
    except (ImportError, OSError, AttributeError):
        return None


def environment() -> dict[str, str | int]:
    return {'platform': platform.platform(), 'python': platform.python_version(), 'machine': platform.machine(),
            'cpu_count': os.cpu_count() or 0}


# ---- workloads (run in the child) ----------------------------------------------------------------------------------------------

def _need_builders() -> None:
    for extra in (ROOT / 'src', ROOT / 'tests'):
        if str(extra) not in sys.path:
            sys.path.insert(0, str(extra))


def _ladder(n: int, seed: int) -> dict:
    _need_builders()
    from unified_ir_builder import generate_pair

    from patchtrace.unified.ladder.engine import run_ladder_data
    from patchtrace.unified.ladder.side import SideData
    from patchtrace.unified.limits import Budget
    t0 = time.perf_counter()
    pair = generate_pair(n, seed=seed)
    t1 = time.perf_counter()
    older, newer = SideData.from_ir(pair.older), SideData.from_ir(pair.newer)
    t2 = time.perf_counter()
    budget = Budget()
    corr = run_ladder_data(older, newer, budget=budget)
    t3 = time.perf_counter()
    got = {corr.older_rva[p.older_fid]: corr.newer_rva[p.newer_fid] for p in corr.pairs}
    stats = dict(corr.stats)
    return {'seconds': {'generate': t1 - t0, 'sides': t2 - t1, 'ladder': t3 - t2, 'total': t3 - t1},
            'counts': {'ticks': budget.used, 'pairs': len(corr.pairs), 'truth': len(pair.truth),
                       'right': sum(1 for k, v in got.items() if pair.truth.get(k) == v),
                       'wrong': sum(1 for k, v in got.items() if k in pair.truth and pair.truth[k] != v),
                       'spurious': sum(1 for k in got if k not in pair.truth), 'waves': int(stats.get('waves', 0)),
                       'status': corr.status, 'limits_hit': ','.join(sorted(dict(corr.limits_hit)))}}


def _ingest(n: int, seed: int, insns: int) -> dict:
    _need_builders()
    import random
    from array import array

    from unified_extract_builder import BASE, SHA, footer, header
    from unified_extract_builder import function as extract_function

    from patchtrace.unified.ir.ingest import ExpectedSide, ingest
    from patchtrace.unified.ir.pe_tables import PeTables, Section
    rng = random.Random(f'bench-ingest:{seed}')
    stride = 0x100 * ((insns * 5 + 1 + 0xFF) // 0x100)
    text_end = 0x1000 + n * stride
    size = (text_end + 0x2FFF) // 0x1000 * 0x1000
    tables = PeTables(image_base=BASE, size_of_image=size, relocs=array('I'), warnings=[], sections=(
        Section('.text', 0x1000, text_end, True), Section('.rdata', text_end, text_end + 0x1000, False)))
    with tempfile.TemporaryDirectory(prefix='pt-bench-ingest-') as private:
        path, out_dir = Path(private) / 'ir.jsonl', Path(private) / 'ir'
        out_dir.mkdir()
        t0 = time.perf_counter()
        total = 0
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(header(size=size), separators=(',', ':')) + '\n')
            for i in range(n):
                specs = [('movimm', rng.randrange(1, 2**31)) if k % 4 != 1 else ('mov',) for k in range(insns)]
                record = extract_function(0x1000 + i * stride, [*specs, ('ret',)], name=f'f{i}')
                total += len(record['insns'])
                handle.write(json.dumps(record, separators=(',', ':')) + '\n')
            handle.write(json.dumps(footer(n, total), separators=(',', ':')) + '\n')
        t1 = time.perf_counter()
        built = ingest(path, ExpectedSide(side='older', artifact_sha256=SHA, pe=tables), out_dir=out_dir,
                       created_utc='2026-01-01T00:00:00+00:00')
        t2 = time.perf_counter()
        counts = built.manifest.counts
        return {'seconds': {'generate': t1 - t0, 'ingest': t2 - t1},
                'counts': {'generated_functions': n, 'generated_instructions': total, 'functions': counts.functions,
                           'instructions': counts.instructions, 'blocks': counts.blocks,
                           'jsonl_bytes': path.stat().st_size, 'ir_bytes': (out_dir / 'ir.sqlite3').stat().st_size,
                           'content_digest': built.manifest.content_digest}}


def _filler(rng, k: int) -> tuple:
    reg = ('EBX', 'ESI', 'EDI')[k % 3]
    return (('mov_ri', reg, rng.randrange(1, 2**31)), ('add_ri', reg, rng.randrange(1, 100)), ('xor_rr', reg, 'EDX'),
            ('mov_rr', 'EDX', reg))[k % 4]


def _facts_body(filler: list, a: int, b: int, c: int, d: int, callee: str) -> list:
    return [('sub_rsp', 0x28), *filler, ('mov_ri', 'EAX', a), ('mov_ri', 'ECX', b), ('cmp_ri', 'ECX', c),
            ('jcc', 'Z', 'skip'), ('call', callee), ('add_ri', 'EAX', d), ('label', 'skip'), ('xor_rr', 'EDX', 'EDX'),
            ('test_rr', 'EAX', 'EAX'), ('mov_rr', 'EDX', 'EAX'), ('add_rsp', 0x28), ('ret',)]


def _facts(n: int, seed: int) -> dict:
    """`n` functions per side, each calling another one; the newer side changes ONE immediate in every function (a MOV,
    a CMP or an ADD operand in turn), so all `n` pairs are changed pairs. Both images go through the real ingest;
    `compute_stage` runs the whole step and the `facts` second is the span between its `facts` and `write` events."""
    _need_builders()
    import random

    from unified_facts_builder import BASE, NEW_SHA, OLD_SHA, build_reader, function

    from patchtrace.unified import store
    from patchtrace.unified.addressing import AddressMap, PeLayout
    from patchtrace.unified.compute import IrInputs, compute_stage
    from patchtrace.unified.sources import GhidriffRun, RawGhidriff, SourceInputs
    rng = random.Random(f'bench-facts:{seed}')
    first, stride = 0x4000, 0x100               # unified_facts_builder.big_pe: code from 0x4000 up, data below it
    size = (first + n * stride + 0x1FFF) // 0x1000 * 0x1000
    sym = {f'fn_{i}': first + i * stride for i in range(n)}
    older_fns, newer_fns = [], []
    for i in range(n):
        filler = [_filler(rng, k) for k in range(FACTS_FILLER)]
        a, b, c, d = rng.randrange(1, 2**31), rng.randrange(1, 2**31), rng.randrange(1, 100), rng.randrange(1, 100)
        which, callee, rva = i % 3, f'fn_{(i * 7 + 1) % n}', first + i * stride
        older_fns.append(function(rva, _facts_body(filler, a, b, c, d, callee), name=f'fn_{i}', sym=sym))
        changed = (a ^ 0x5A5A if which == 0 else a, b, c % 99 + 1 if which == 1 else c, d % 99 + 1 if which == 2 else d)
        newer_fns.append(function(rva, _facts_body(filler, *changed, callee), name=f'fn_{i}', sym=sym))
        if len(older_fns[-1]['raw']) // 2 > stride or len(newer_fns[-1]['raw']) // 2 > stride:
            raise ValueError('a facts function outgrew its slot')
    sections = ((0x1000, 0x2000), (0x2000, first), (first, size))
    inputs = SourceInputs(older_sha256=OLD_SHA, newer_sha256=NEW_SHA, matches=(),
                          run=GhidriffRun('bench', '1', RawGhidriff(status='ok', address_matches={}, sha256='0' * 64)))
    marks: dict[str, float] = {}

    def emit(event) -> None:
        marks[event.stage] = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix='pt-bench-facts-', ignore_cleanup_errors=True) as private:
        work, readers = Path(private), []
        try:
            t0 = time.perf_counter()
            readers.append(build_reader(work, 'older', older_fns, sha=OLD_SHA, size=size))
            readers.append(build_reader(work, 'newer', newer_fns, sha=NEW_SHA, size=size))
            out = work / 'result'
            out.mkdir()
            layout = PeLayout(BASE, size)
            t1 = time.perf_counter()
            manifest = compute_stage(inputs, AddressMap(layout, layout), result_dir=out, emit=emit,
                                     ir=IrInputs(readers[0], readers[1], sections, sections),
                                     created_utc='2026-01-01T00:00:00+00:00').manifest
            t2 = time.perf_counter()
            rows = list(store.read_rows(out, manifest))
            judged = {f.row_id for f in store.read_facts(out, manifest)}
            instructions = readers[0].manifest.counts.instructions
        finally:
            for reader in readers:
                reader.close()
    entries = set(sym.values())
    changed_judged = sum(1 for r in rows if len(r.older) == len(r.newer) == 1 and r.older[0].rva in entries
                         and r.newer[0].rva == r.older[0].rva and r.row_id in judged and r.materiality != 'unchanged')
    steps = ('sources', 'ladder', 'fusion', 'facts', 'write')      # the StageEvents of an IR run, in order
    ends = [*(marks[s] for s in steps[1:]), t2]
    spans = {s: end - marks[s] for s, end in zip(steps, ends, strict=True)}
    return {'seconds': {'build': t1 - t0, **spans, 'compute': t2 - t1},
            'counts': {'functions': n, 'changed': n, 'instructions': instructions, 'rows': len(rows),
                       'matched': manifest.counts.decisions.matched, 'judged': len(judged),
                       'changed_judged': changed_judged, 'status': manifest.status,
                       'limitations': ','.join(manifest.limitations), 'result_id': manifest.result_id,
                       **{f'materiality/{k}': v for k, v in manifest.counts.materiality.model_dump().items()}}}


def _median_seconds(fn) -> float:
    times = []
    for _ in range(REPEATS):
        start = time.perf_counter()
        fn()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def _read_model(n: int) -> dict:
    """`n` in-memory row views; `filter` and `sort` are the slowest of three filters and three sorts over every row,
    `first_paint` is the default filter, the default order and the cells of the first rows. Medians of REPEATS runs."""
    _need_builders()
    from unified_read_support import synthetic_rows, synthetic_view

    from patchtrace.unified import read_model as rm
    t0 = time.perf_counter()
    rows = synthetic_rows(n)
    vm = synthetic_view(rows)
    t1 = time.perf_counter()
    width, everything = len(rm.columns(vm)), list(range(len(rows)))

    def first_paint() -> list[str]:
        order = rm.sort_rows(rows, rm.filter_rows(rows))
        return [rm.cell_text(rows[i], column) for i in order[:FIRST_PAINT_ROWS] for column in range(width)]
    filters = {'default': lambda: rm.filter_rows(rows),
               'search': lambda: rm.filter_rows(rows, search=f'function_{n - 1}', show_collapsed=True),
               'combined': lambda: rm.filter_rows(rows, decisions={'matched', 'contested'}, classes={'callee'},
                                                  sources={'bindiff'})}
    sorts = {'default': lambda: rm.sort_rows(rows, everything),
             'source': lambda: rm.sort_rows(rows, everything, rm.column_sort_key(vm, 'source:bindiff')),
             'function': lambda: rm.sort_rows(rows, everything, rm.column_sort_key(vm, 'function'), descending=True)}
    seconds = {'generate': t1 - t0, **{f'filter_{k}': _median_seconds(f) for k, f in filters.items()},
               **{f'sort_{k}': _median_seconds(f) for k, f in sorts.items()}}
    seconds['filter'] = max(seconds[f'filter_{k}'] for k in filters)
    seconds['sort'] = max(seconds[f'sort_{k}'] for k in sorts)
    seconds['first_paint'] = _median_seconds(first_paint)
    shown, painted = filters['default'](), first_paint()
    order = rm.sort_rows(rows, shown)
    return {'seconds': seconds,
            'counts': {'rows': len(rows), 'columns': width, 'shown': len(shown),
                       'collapsed': sum(1 for r in rows if r.collapsed), 'searched': len(filters['search']()),
                       'combined': len(filters['combined']()), 'sorted': len(order) if sorted(order) == shown else 0,
                       'painted_cells': len(painted),
                       'paint_sha256': hashlib.sha256('\n'.join(painted).encode('utf-8')).hexdigest()}}


def _child(stage: str, n: int, seed: int, insns: int) -> int:
    if n < 1:
        raise ValueError('n must be positive')
    workloads = {'ladder': lambda: _ladder(n, seed), 'ingest': lambda: _ingest(n, seed, insns),
                 'facts': lambda: _facts(n, seed), 'read_model': lambda: _read_model(n)}
    work = workloads[stage]()
    print(json.dumps({**work, 'peak_rss_bytes': peak_rss_bytes()}, separators=(',', ':')))
    return 0


# ---- parent: fresh processes, gates, report --------------------------------------------------------------------------------------------

def _row(stage: str, n: int, *, status: str = 'measured', work: dict | None = None, error: str | None = None) -> dict:
    work = work or {}
    return {'stage': stage, 'n': n, 'status': status, 'seconds': work.get('seconds', {}),
            'peak_rss_bytes': work.get('peak_rss_bytes'), 'counts': work.get('counts', {}), 'derived': {},
            'error': error}


def _tail(handle) -> str:
    """At most TAIL_BYTES from the end of an output file, as printable text (the child is ours, its text is not)."""
    size = os.fstat(handle.fileno()).st_size
    handle.seek(max(0, size - TAIL_BYTES))
    text = handle.read(TAIL_BYTES).decode('utf-8', errors='replace')
    return ''.join(ch if ch.isprintable() or ch in '\n\t' else '�' for ch in text)


def run_child(argv: Sequence[str], *, timeout: float, env: dict[str, str] | None = None
              ) -> tuple[int | None, str, str, str | None]:
    """Run `argv` in an empty private directory with stdout and stderr going to files there (U7-13): nothing is
    buffered in memory, a child that writes more than OUTPUT_CAP bytes to either file or outlives `timeout` is
    killed, and only the last TAIL_BYTES of each file are read back. Returns (exit code, stdout tail, stderr tail,
    problem); `problem` is None for a child that ended by itself within both bounds."""
    with tempfile.TemporaryDirectory(prefix='pt-bench-', ignore_cleanup_errors=True) as private:
        with open(Path(private) / 'stdout.bin', 'w+b') as out, open(Path(private) / 'stderr.bin', 'w+b') as err:
            def written() -> int:
                return max(os.fstat(out.fileno()).st_size, os.fstat(err.fileno()).st_size)
            problem = None
            deadline = time.monotonic() + timeout
            child = subprocess.Popen(list(argv), cwd=private, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            try:
                while problem is None:
                    try:
                        child.wait(timeout=max(0.0, min(POLL_S, deadline - time.monotonic())))
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    if written() > OUTPUT_CAP:
                        problem = f'the child wrote more than {OUTPUT_CAP} bytes of output; it exceeds the cap'
                    elif time.monotonic() >= deadline:
                        problem = f'timeout after {timeout:g} s'
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
            if problem is None and written() > OUTPUT_CAP:
                problem = f'the child wrote more than {OUTPUT_CAP} bytes of output; it exceeds the cap'
            return child.returncode, _tail(out), _tail(err), problem


def measure(stage: str, n: int, *, seed: int = 1, insns: int = INSNS, timeout: float = TIMEOUT_S) -> dict:
    """One workload in a fresh interpreter. A child that fails, times out or writes too much is a `failed` row, never
    an exception."""
    argv = [sys.executable, '-P', '-m', 'tools.unified.bench', '--child', stage, str(n), str(seed), str(insns)]
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(str(p) for p in (ROOT, ROOT / 'src', ROOT / 'tests'))}
    code, stdout, stderr, problem = run_child(argv, timeout=timeout, env=env)
    if problem is not None:
        return _row(stage, n, status='failed', error=problem)
    if code != 0:
        return _row(stage, n, status='failed', error=(stderr.strip() or f'exit {code}')[-400:])
    try:
        return _row(stage, n, work=json.loads(stdout.strip().splitlines()[-1]))
    except (ValueError, IndexError):
        return _row(stage, n, status='failed', error='the child printed no result')


def extract_rows(live: dict) -> list[dict]:
    """Informational rows from a `tools/live_unified_check.py` result: the extractor's cost per instruction."""
    sides = live.get('sides') if isinstance(live, dict) else None
    if not sides:
        raise ContractError('a live result needs its per-side records')
    rows = []
    for side, data in sorted(sides.items()):
        try:
            counts, seconds = data['counts'], data['seconds']
            instructions, functions = int(counts['instructions']), int(counts['functions'])
            extract = float(seconds['extract'])
        except (KeyError, TypeError, ValueError):
            raise ContractError(f'live result side {side} lacks counts or seconds') from None
        row = _row('extract', functions, work={'seconds': {'extract': extract, 'ingest': float(seconds.get('ingest', 0))},
                                               'counts': {'side': side, 'functions': functions,
                                                          'instructions': instructions,
                                                          'content_digest': str(data.get('content_digest', ''))}})
        row['derived'] = {'us_per_instruction': round(extract * 1e6 / instructions, 3)} if instructions else {}
        rows.append(row)
    return rows


def _gate(row: dict, name: str, unit: str, key: str | None) -> dict:
    """Time (s or ms) has the 5x CI slack, memory none; a missing observation is `not-measured`, never a pass."""
    limit = getattr(DEFAULT_LIMITS, name)
    slack = 1 if unit == 'bytes' else SLACK
    if unit == 'bytes':
        observed = row['peak_rss_bytes']
    else:
        value = row['seconds'].get(key)
        observed = None if value is None else (round(value * 1000, 3) if unit == 'ms' else value)
    allowed = limit * slack
    verdict = 'not-measured' if observed is None else ('pass' if observed <= allowed else 'fail')
    return {'name': name, 'unit': unit, 'limit': limit, 'slack': slack, 'allowed': allowed, 'observed': observed,
            'verdict': verdict}


def _check(name: str, ok: bool, detail: str) -> dict:
    return {'name': name, 'ok': bool(ok), 'detail': detail}


def _row_checks(row: dict) -> list[dict]:
    counts, n = row['counts'], row['n']
    if row['stage'] == 'ladder':
        hit = counts.get('limits_hit', '')
        return [_check('complete', counts.get('status') == 'complete' and hit in ('', 'neighbour-cap'),
                       f'status {counts.get("status")}, limits hit {hit or "none"}'),
                _check('consistent', counts.get('wrong') == 0 and counts.get('spurious') == 0
                       and counts.get('right', 0) >= 0.99 * counts.get('truth', 0),
                       f'right {counts.get("right")} of {counts.get("truth")}, wrong {counts.get("wrong")}, '
                       f'spurious {counts.get("spurious")} (a property of the generator, not an accuracy claim)'),
                _check('ticks-per-function', counts.get('ticks', 0) <= TICKS_PER_FUNCTION * n,
                       f'{counts.get("ticks")} ticks for {n} functions')]
    if row['stage'] == 'ingest':
        ok = all(k in counts for k in ('generated_functions', 'generated_instructions')) \
            and counts.get('functions') == counts.get('generated_functions') \
            and counts.get('instructions') == counts.get('generated_instructions')
        return [_check('ingest-complete', ok, f'{counts.get("functions")} of {counts.get("generated_functions")} '
                       f'functions, {counts.get("instructions")} of {counts.get("generated_instructions")} instructions')]
    if row['stage'] == 'facts':
        changed = counts.get('changed', 0)
        ok = counts.get('status') == 'complete' and changed > 0 and counts.get('changed_judged') == changed \
            and counts.get('judged', 0) >= changed
        return [_check('facts-judged', ok, f'{counts.get("changed_judged")} of {changed} changed functions judged with '
                       f'their counterpart and not unchanged, {counts.get("judged")} pairs judged, status '
                       f'{counts.get("status")}')]
    if row['stage'] == 'read_model':
        shown, collapsed, width = counts.get('shown', -1), counts.get('collapsed', -1), counts.get('columns', 0)
        ok = counts.get('rows') == n and shown + collapsed == n and counts.get('sorted') == shown \
            and counts.get('searched') == 1 and width > 0 \
            and counts.get('painted_cells') == min(FIRST_PAINT_ROWS, shown) * width
        return [_check('read-model-consistent', ok, f'{shown} shown and {collapsed} collapsed of {counts.get("rows")} '
                       f'rows, {counts.get("sorted")} in order, search found {counts.get("searched")}, '
                       f'{counts.get("painted_cells")} cells painted over {width} columns')]
    return []


def evaluate(rows: Sequence[dict]) -> list[dict]:
    """Rows with their gates (L-35 sizes only) and checks; failed rows carry neither."""
    out = [dict(r, gates=[], checks=[]) for r in rows]
    for row in out:
        if row['status'] != 'measured':
            continue
        row['gates'] = [_gate(row, name, unit, key) for name, unit, key in GATES.get((row['stage'], row['n']), ())]
        row['checks'] = _row_checks(row)
    ladder = {r['n']: r for r in out if r['stage'] == 'ladder' and r['status'] == 'measured'}
    if 10_000 in ladder and 60_000 in ladder:
        small, large = ladder[10_000]['counts'].get('ticks', 0), ladder[60_000]['counts'].get('ticks', 0)
        ratio = large / small if small else float('inf')
        ladder[60_000]['checks'].append(_check('work-linear', ratio < MAX_LINEAR_RATIO,
                                               f'60k costs {ratio:.2f}x the budget ticks of 10k (limit {MAX_LINEAR_RATIO}x)'))
    return out


def counts_sha256(rows: Sequence[dict]) -> str:
    """Digest of the deterministic counts only (stage, size, counts): equal code gives an equal digest."""
    keyed = sorted(([r['stage'], r['n'], sorted(r['counts'].items())] for r in rows), key=lambda x: (x[0], x[1], str(x[2])))
    return hashlib.sha256(canonical_json(keyed)).hexdigest()


def _verdict(rows: Sequence[dict]) -> str:
    if any(r['status'] != 'measured' for r in rows):
        return 'fail'
    gates = [g for r in rows for g in r['gates']]
    if any(g['verdict'] == 'fail' for g in gates) or any(not c['ok'] for r in rows for c in r['checks']):
        return 'fail'
    return 'pass' if gates and all(g['verdict'] == 'pass' for g in gates) else 'insufficient-data'


def pending_stages(rows: Sequence[dict]) -> list[dict]:
    """PENDING, plus every built stage without a measured row at each of its L-35 sizes: such a report cannot show
    that the stage fits its limit, so G-U5 keeps waiting for it."""
    out = []
    for stage, name, value, what in BUILT:
        measured = {r['n'] for r in rows if r['stage'] == stage and r['status'] == 'measured'}
        missing = [str(n) for n in L35_SIZES[stage] if n not in measured]
        if missing:
            out.append({'stage': stage, 'needs': 'a bench run', 'limit': name, 'limit_value': value,
                        'what': f'{what}: {NOT_MEASURED} (n = {", ".join(missing)})'})
    return out + [{'stage': s, 'needs': needs, 'limit': name, 'limit_value': value, 'what': what}
                  for s, needs, name, value, what in PENDING]


def report(rows: Sequence[dict], env: dict) -> BenchReport:
    pending = pending_stages(rows)
    body = {'contract': CONTRACT, 'environment': env, 'slack': SLACK, 'rows': list(rows), 'pending': pending,
            'verdict': _verdict(rows), 'counts_sha256': counts_sha256(rows)}
    return BenchReport.model_validate_json(json.dumps(body))


def dump(built: BenchReport) -> bytes:
    return (json.dumps(built.model_dump(mode='json'), sort_keys=True, indent=1, ensure_ascii=False) + '\n').encode('utf-8')


def load(data: bytes) -> BenchReport:
    try:
        strict_json(data)
        built = BenchReport.model_validate_json(data)
    except (ValueError, ValidationError) as exc:
        raise ContractError(f'bench report invalid: {exc}') from None
    if counts_sha256([r.model_dump(mode='json') for r in built.rows]) != built.counts_sha256:
        raise ContractError('bench counts digest mismatch (edited after generation)')
    return built


# ---- command line --------------------------------------------------------------------------------------------------------------------

def plan(stages: Sequence[str], sizes: Sequence[int]) -> list[tuple[str, int]]:
    """(stage, n) to measure: `sizes` for the ladder and ingest, the L-35 sizes for facts and read_model."""
    return [(stage, n) for stage in stages for n in L35_SIZES.get(stage, sizes)]


def _seconds(value: float) -> str:
    return f'{value:.2f}s' if value >= 1 else f'{value * 1000:.1f}ms'


def _print(built: BenchReport) -> None:
    for row in built.rows:
        seconds = ' '.join(f'{k} {_seconds(v)}' for k, v in row.seconds.items())
        rss = f'{row.peak_rss_bytes / 2**20:.0f} MiB' if row.peak_rss_bytes else 'rss n/a'
        gates = ' '.join(f'{g.name}:{g.verdict}' for g in row.gates) or 'informational'
        bad = ' '.join(c.name for c in row.checks if not c.ok)
        print(f'{row.stage:10s} n={row.n:<8d} {row.status:8s} {seconds} | {rss} | {gates}'
              f'{" | FAILED CHECKS " + bad if bad else ""}{" | " + row.error if row.error else ""}')
    for p in built.pending:
        print(f'pending    {p.stage}: needs {p.needs}, limit {p.limit} = {p.limit_value} ({p.what})')
    print(f'verdict {built.verdict}, counts_sha256 {built.counts_sha256}')


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m tools.unified.bench', description=__doc__.split('\n\n')[0])
    parser.add_argument('--sizes', default='10000,60000',
                        help='comma-separated function counts for ladder and ingest (facts and read_model always run '
                             'at their L-35 sizes)')
    parser.add_argument('--stages', default=','.join(STAGES), help=f'comma-separated: {", ".join(STAGES)}')
    parser.add_argument('--insns', type=int, default=INSNS, help='instructions per generated function (ingest)')
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--live-result', action='append', default=[], help='live-unified result JSON (extract rows)')
    parser.add_argument('--out', help='write bench-report/1 here')
    parser.add_argument('--child', nargs=4, metavar=('STAGE', 'N', 'SEED', 'INSNS'), help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child:
        stage, n, seed, insns = args.child
        if stage not in STAGES:
            parser.error(f'unknown stage {stage}')
        return _child(stage, int(n), int(seed), int(insns))
    try:
        sizes = [int(s) for s in args.sizes.split(',') if s]
        stages = [s for s in args.stages.split(',') if s]
        if not sizes or any(s not in STAGES for s in stages) or args.insns < 1:
            raise ValueError
    except ValueError:
        print(f'error: --sizes needs integers, --stages names from {",".join(STAGES)} and --insns a positive number',
              file=sys.stderr)
        return 2
    rows = [measure(stage, n, seed=args.seed, insns=args.insns) for stage, n in plan(stages, sizes)]
    try:
        for path in args.live_result:
            rows += extract_rows(json.loads(Path(path).read_text(encoding='utf-8')))
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    built = report(evaluate(rows), environment())
    _print(built)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_bytes(dump(built))
    return 1 if built.verdict == 'fail' else 0


if __name__ == '__main__':
    raise SystemExit(main())
