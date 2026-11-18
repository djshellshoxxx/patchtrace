"""G-U5 performance harness (08-evaluation s6, L-35). Dev-only, never shipped, never imported by `src/`.

Every measurement runs in a FRESH process (`measure` spawns `python -P -m tools.unified.bench --child ...`), so the
peak RSS it reports belongs to that one workload. The workloads are SYNTHETIC (the generators of
tests/unified_ir_builder.py for the ladder and tests/unified_extract_builder.py for ingest): they measure the cost of
the algorithms, not Ghidra or real binaries. The extractor is measured by the live workflow
(`tools/live_unified_check.py`); `--live-result` turns its result file into informational `extract` rows.

Gates are L-35 with 5x wall-clock slack on CI (08 s6) and no slack on memory, applied only at the sizes L-35 defines:
ladder 10k and 60k, ingest and worker memory at 60k. Other sizes are informational. Exact operation-count checks
(budget ticks per function, linear growth) hold at every size. The `facts` stage (5,000 changed pairs through the real IR
channels and verdict rules), the `read_model` stage (build, first paint, sort and filter over 10k and 100k rows; L-35 gates
at 100k) and the `ui_calls` stage (exact `data()` call counts of an offscreen QTableView over the real Unified table model,
counts not times) replace the former `pending` list. What still waits for something else is listed as `pending` with its
limit, never left out. Child processes run through `patchtrace.jobs.run_process`: bounded output, the whole process tree
killed on timeout. Windows numbers come from the
Windows runner and the frozen EXE; the Windows RSS branch has not been run by the author. The report carries
`counts_sha256`, a digest of the deterministic counts only, so two runs on equal code can be compared.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import threading
import time
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from patchtrace.jobs import run_process
from patchtrace.unified.limits import DEFAULT_LIMITS
from tools.calibration.common import canonical_json, strict_json
from tools.calibration.tier_r.contracts import ContractError

CONTRACT = 'bench-report/1'
SLACK = 5                       # 08 s6: CI wall-clock slack
TICKS_PER_FUNCTION = 12         # tests/test_unified_ladder_perf.py: budget ticks stay linear
MAX_LINEAR_RATIO = 7.0          # 6x the functions must cost about 6x the work, never 36x
INSNS = 50                      # 60k functions x 50 instructions = the 3 M instructions of L-35
TIMEOUT_S = 3600
HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
STAGES = ('ladder', 'ingest', 'facts', 'read_model', 'ui_calls')
DEFAULT_STAGES = STAGES
FACTS_PAIRS = 5_000             # L-35: facts for 5,000 changed pairs
ROW_SIZES = (10_000, 100_000)   # 08 s6: read model and data() calls at 10k and 100k rows; L-35 gates 100k
DEFAULT_SIZES = {'ladder': (10_000, 60_000), 'ingest': (10_000, 60_000), 'facts': (FACTS_PAIRS,),
                 'read_model': ROW_SIZES, 'ui_calls': ROW_SIZES}
MAX_CALLS_PER_CELL = 24         # Qt asks a handful of roles per visible cell (display, tooltip, font, ...); never per row
MAX_CHILD_OUTPUT = 4 * 2**20    # the child prints one JSON line; a flood is a failure, not a memory problem
CHILD_LOG_TAIL = 64 * 1024
# stages that wait for something else: (stage, needs, limit name, limit value, what). Empty since UE-R4.
PENDING: tuple[tuple[str, str, str, int, str], ...] = ()
# stages that G-U5 needs measured at a size L-35 defines: stage -> sizes of which at least one must have a gate
REQUIRED_STAGES = {'ladder': (10_000, 60_000), 'ingest': (60_000,), 'facts': (FACTS_PAIRS,),
                   'read_model': (100_000,), 'ui_calls': ROW_SIZES}
# (stage, n) -> ((limit name, unit), ...): the sizes L-35 defines
GATES = {('ladder', 10_000): (('l35_ladder_10k_s', 's'),),
         ('ladder', 60_000): (('l35_ladder_60k_s', 's'), ('l35_worker_rss_bytes', 'bytes')),
         ('ingest', 60_000): (('l35_ingest_60k_s', 's'), ('l08_ingest_rss_bytes', 'bytes')),
         ('facts', FACTS_PAIRS): (('l35_facts_5000_s', 's'),),
         ('read_model', 100_000): (('l35_first_paint_ms', 'ms'), ('l35_sort_ms', 'ms'), ('l35_filter_ms', 'ms'))}
# gate limit name -> key of `Row.seconds` that is compared with it (default: `total`, else `ingest`)
OBSERVED = {'l35_facts_5000_s': 'facts', 'l35_first_paint_ms': 'first_paint', 'l35_sort_ms': 'sort',
            'l35_filter_ms': 'filter'}


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
    stage: Literal['ladder', 'ingest', 'extract', 'facts', 'read_model', 'ui_calls']
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


def _facts(n: int, seed: int) -> dict:
    """Facts for `n` changed pairs: the real ingest builds two images (excluded from the gate), then the real
    `FactsContext` and verdict rules judge every pair. Each newer function differs from its older one by one compare
    constant, so every pair is a changed pair."""
    _need_builders()
    import random
    from collections import Counter

    import unified_facts_builder as fb

    from patchtrace.unified import keys
    from patchtrace.unified.addressing import AddressMap, PeLayout
    from patchtrace.unified.facts import verdict
    from patchtrace.unified.facts.channels import FactsContext
    from patchtrace.unified.facts.irchannels import IrSides
    rng = random.Random(f'bench-facts:{seed}')
    stride, first = 0x40, 0x4000
    size = (first + n * stride + 0xFFF) // 0x1000 * 0x1000
    constants = [rng.randrange(1, 50) for _ in range(n)]

    def image(shift: int) -> list[dict]:
        return [fb.function(first + i * stride, [('mov_ri', 'EAX', i + 1), ('cmp_ri', 'EAX', constants[i] + shift),
                                                 ('jcc', 'Z', 'out'), ('mov_ri', 'ECX', 7), ('label', 'out'), ('ret',)],
                            name=f'f{i}') for i in range(n)]
    with tempfile.TemporaryDirectory(prefix='pt-bench-facts-') as private, ExitStack() as readers:
        t0 = time.perf_counter()
        old, new = image(0), image(1)
        older = fb.build_reader(Path(private), 'old', old, sha=fb.OLD_SHA, size=size)
        readers.callback(older.close)
        newer = fb.build_reader(Path(private), 'new', new, sha=fb.NEW_SHA, size=size)
        readers.callback(newer.close)
        t1 = time.perf_counter()
        rows = [fb.decided(a['rva'], b['rva']) for a, b in zip(old, new, strict=True)]
        layout = PeLayout(image_base=fb.BASE, size_of_image=size)
        sides = IrSides(older, newer, older_sections=fb.DATA_SECTIONS, newer_sections=fb.DATA_SECTIONS, identical=False)
        context = FactsContext.build(older_sha256=fb.OLD_SHA, newer_sha256=fb.NEW_SHA, addr=AddressMap(layout, layout),
                                     matches=[], rows=rows, bindiff_flags={}, ir_sides=sides)
        t2 = time.perf_counter()
        verdicts: Counter = Counter()
        for row in rows:
            judged = verdict.judge(keys.row_id(fb.OLD_SHA, fb.NEW_SHA, row.older, row.newer), row.decision,
                                   context.collect(row))
            verdicts[judged.facts.verdict] += 1
        t3 = time.perf_counter()
        return {'seconds': {'build_images': t1 - t0, 'context': t2 - t1, 'judge': t3 - t2, 'facts': t3 - t1},
                'counts': {'pairs': len(rows), 'changed': verdicts['material'] + verdicts['review'],
                           **{f'verdict/{k}': v for k, v in sorted(verdicts.items())}}}


def _synthetic_vm(n: int, seed: int):
    """A real stored result of `n` rows (a mix of decisions and verdicts) read back by the real `load_unified`."""
    _need_builders()
    import unified_read_support as support

    from patchtrace.unified import read_model
    rows, facts = [], []
    for i in range(n):
        older, newer = 0x1000 + i * 0x20, 0x2000000 + i * 0x20
        name, pick = f'fn_{i}', ((i + seed) * 37 % 100) / 100      # every kind from 100 rows on, so the columns do not depend on n
        if pick < 0.04:
            row, fact = support.material({'older': [(older, name)], 'newer': [(newer, name)]})
            rows.append(row)
            facts.append(fact)
        elif pick < 0.06:
            rows.append(support.contested_row(older, newer, name))
        elif pick < 0.08:
            rows.append(support.make_row([(older, name)], [], decision='older-only',
                                         atoms=[support.atom(older=older, newer=None)]))
        elif pick < 0.10:
            rows.append(support.make_row([], [(newer, name)], decision='newer-only',
                                         atoms=[support.atom(older=None, newer=newer)]))
        elif pick < 0.60:
            row = support.make_row([(older, name)], [(newer, name)], materiality='unchanged',
                                   atoms=[support.atom(older=older, newer=newer)])
            rows.append(row)
            facts.append(support.make_facts(row, 'unchanged', proof='UNCH/1'))
        else:
            rows.append(support.make_row([(older, name)], [(newer, name)],
                                         atoms=[support.atom(older=older, newer=newer)]))
    private = tempfile.TemporaryDirectory(prefix='pt-bench-rows-')
    loaded = support.publish(Path(private.name) / 'result', rows, facts)
    t0 = time.perf_counter()
    vm = read_model.load_unified(support.request(loaded))
    return vm, time.perf_counter() - t0, private


def _best(fn, repeats: int = 3) -> tuple[float, object]:
    best, out = float('inf'), None
    for _ in range(repeats):
        t = time.perf_counter()
        out = fn()
        best = min(best, time.perf_counter() - t)
    return best, out


def _read_model(n: int, seed: int) -> dict:
    """Qt-free read-model costs at `n` rows. first_paint is the default view (filter, collapsed rows left out, default
    order) the table model computes on reset; sort is a column sort of that view; filter is a decision filter plus a
    search. `build` (load_unified, a worker-thread job) is informational."""
    from patchtrace.unified import read_model
    t0 = time.perf_counter()
    vm, build, private = _synthetic_vm(n, seed)
    generate = time.perf_counter() - t0 - build
    with private:
        first, shown = _best(lambda: read_model.filter_rows(vm.rows))
        key = read_model.column_sort_key(vm, 'function')
        sort, ordered = _best(lambda: read_model.sort_rows(vm.rows, shown, key))
        narrow, found = _best(lambda: read_model.filter_rows(vm.rows, decisions={'matched', 'tentative'}, search='fn_1'))
        return {'seconds': {'generate': generate, 'build': build, 'first_paint': first, 'sort': sort, 'filter': narrow},
                'counts': {'rows': len(vm.rows), 'state': vm.state, 'shown_default': len(shown), 'sorted': len(ordered),
                           'shown_filtered': len(found), 'collapsed': sum(1 for r in vm.rows if r.collapsed),
                           'columns': len(read_model.columns(vm))}}


def _ui_calls(n: int, seed: int) -> dict:
    """Exact `data()` call counts (not times) of the real `UnifiedTableModel` under an offscreen QTableView of fixed
    geometry: model reset (first paint), column sort and filter, each followed by a synchronous viewport repaint."""
    os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication, QTableView

    from patchtrace.ui_unified import UnifiedTableModel
    vm, _build, private = _synthetic_vm(n, seed)
    with private:
        app = QApplication.instance() or QApplication([])
        model, view = UnifiedTableModel(), QTableView()
        view.setModel(model)
        view.verticalHeader().setDefaultSectionSize(24)
        view.horizontalHeader().setDefaultSectionSize(120)
        view.setWordWrap(False)
        view.resize(1200, 480)
        view.show()
        app.processEvents()

        def settle() -> None:
            app.processEvents()
            view.viewport().repaint()
        calls = {}
        for name, act in (('first_paint', lambda: model.set_view_model(vm)), ('sort', lambda: model.sort(0)),
                          ('filter', lambda: model.set_filter(decisions={'matched', 'tentative'}, search='fn_1'))):
            model.data_calls = 0
            act()
            settle()
            calls[name] = model.data_calls
        last = view.rowAt(view.viewport().height() - 1)
        counts = {'rows': len(vm.rows), 'columns': model.columnCount(),
                  'visible_rows': len(model.view) if last < 0 else last + 1, 'shown': model.shown,
                  **{f'{k}_calls': v for k, v in calls.items()}}
        view.close()
        return {'seconds': {}, 'counts': counts}


def _child(stage: str, n: int, seed: int, insns: int) -> int:
    if n < 1:
        raise ValueError('n must be positive')
    work = {'ladder': lambda: _ladder(n, seed), 'ingest': lambda: _ingest(n, seed, insns),
            'facts': lambda: _facts(n, seed), 'read_model': lambda: _read_model(n, seed),
            'ui_calls': lambda: _ui_calls(n, seed)}[stage]()
    print(json.dumps({**work, 'peak_rss_bytes': peak_rss_bytes()}, separators=(',', ':')))
    return 0


# ---- parent: fresh processes, gates, report --------------------------------------------------------------------------------------------

def _row(stage: str, n: int, *, status: str = 'measured', work: dict | None = None, error: str | None = None) -> dict:
    work = work or {}
    return {'stage': stage, 'n': n, 'status': status, 'seconds': work.get('seconds', {}),
            'peak_rss_bytes': work.get('peak_rss_bytes'), 'counts': work.get('counts', {}), 'derived': {},
            'error': error}


def run_child(argv: Sequence[str], *, cwd: str, env: dict, timeout: float, max_output: int = MAX_CHILD_OUTPUT):
    """`patchtrace.jobs.run_process`: output bounded (the tail is kept, a flood stops the child), the whole process tree
    killed on timeout or flood (a Windows Job Object, a POSIX process group). Returns the `ProcessResult`."""
    return run_process([os.path.abspath(argv[0]), *argv[1:]], cwd=Path(cwd), env=env, cancel=threading.Event(),
                       timeout_seconds=timeout, log_limit=CHILD_LOG_TAIL, stderr_limit=CHILD_LOG_TAIL,
                       separate_streams=True, max_output_bytes=max_output)


def measure(stage: str, n: int, *, seed: int = 1, insns: int = INSNS, timeout: float = TIMEOUT_S) -> dict:
    """One workload in a fresh interpreter. A child that fails, floods its output or times out is a `failed` row, never
    an exception, and never leaves a process behind."""
    argv = [sys.executable, '-P', '-m', 'tools.unified.bench', '--child', stage, str(n), str(seed), str(insns)]
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join(str(p) for p in (ROOT, ROOT / 'src', ROOT / 'tests'))}
    with tempfile.TemporaryDirectory(prefix='pt-bench-') as private:
        try:
            done = run_child(argv, cwd=private, env=env, timeout=timeout)
        except (OSError, RuntimeError, ValueError) as exc:
            return _row(stage, n, status='failed', error=f'the child could not run: {exc}'[-400:])
    if done.reason == 'timeout':
        return _row(stage, n, status='failed', error=f'timeout after {timeout:g} s')
    if done.reason:
        return _row(stage, n, status='failed', error=f'child stopped: {done.reason}')
    if done.returncode != 0:
        return _row(stage, n, status='failed', error=(done.stderr_tail.strip() or f'exit {done.returncode}')[-400:])
    try:
        return _row(stage, n, work=json.loads(done.log_tail.strip().splitlines()[-1]))
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


def _gate(row: dict, name: str, unit: str) -> dict:
    limit = getattr(DEFAULT_LIMITS, name)
    slack = 1 if unit == 'bytes' else SLACK
    seconds = row['seconds']
    if unit == 'bytes':
        observed = row['peak_rss_bytes']
    elif name in OBSERVED:
        observed = seconds.get(OBSERVED[name])
    else:
        observed = seconds.get('total', seconds.get('ingest'))
    if observed is not None and unit == 'ms':
        observed = observed * 1000
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
                _check('ticks-per-function',
                       isinstance(counts.get('ticks'), int) and counts['ticks'] <= TICKS_PER_FUNCTION * n,
                       f'{counts.get("ticks", "missing")} ticks for {n} functions')]
    if row['stage'] == 'ingest':
        ok = all(k in counts for k in ('generated_functions', 'generated_instructions')) \
            and counts.get('functions') == counts.get('generated_functions') \
            and counts.get('instructions') == counts.get('generated_instructions')
        return [_check('ingest-complete', ok, f'{counts.get("functions")} of {counts.get("generated_functions")} '
                       f'functions, {counts.get("instructions")} of {counts.get("generated_instructions")} instructions')]
    if row['stage'] == 'facts':
        return [_check('facts-complete', counts.get('pairs') == n and counts.get('changed') == n,
                       f'{counts.get("changed")} of {counts.get("pairs")} pairs judged material or review, {n} asked')]
    if row['stage'] == 'read_model':
        return [_check('rows-built', counts.get('rows') == n and counts.get('state') == 'U3'
                       and counts.get('sorted') == counts.get('shown_default'),
                       f'{counts.get("rows")} of {n} rows, state {counts.get("state")}, '
                       f'{counts.get("sorted")} sorted of {counts.get("shown_default")} shown')]
    if row['stage'] == 'ui_calls':
        cells = (counts.get('visible_rows', 0) + 1) * counts.get('columns', 0)
        got = {k: counts.get(f'{k}_calls') for k in ('first_paint', 'sort', 'filter')}
        ok = cells > 0 and all(isinstance(v, int) and 0 < v <= MAX_CALLS_PER_CELL * cells for v in got.values())
        return [_check('calls-bounded-by-visible-cells', ok,
                       f'data() calls {got} for {counts.get("visible_rows")} visible rows x {counts.get("columns")} '
                       f'columns (at most {MAX_CALLS_PER_CELL} per visible cell, never per row)')]
    return []


def evaluate(rows: Sequence[dict]) -> list[dict]:
    """Rows with their gates (L-35 sizes only) and checks; failed rows carry neither."""
    out = [dict(r, gates=[], checks=[]) for r in rows]
    for row in out:
        if row['status'] != 'measured':
            continue
        row['gates'] = [_gate(row, name, unit) for name, unit in GATES.get((row['stage'], row['n']), ())]
        row['checks'] = _row_checks(row)
    ladder = {r['n']: r for r in out if r['stage'] == 'ladder' and r['status'] == 'measured'}
    if 10_000 in ladder and 60_000 in ladder:
        small, large = ladder[10_000]['counts'].get('ticks'), ladder[60_000]['counts'].get('ticks')
        present = isinstance(small, int) and isinstance(large, int)  # a missing count must fail, never read as 0
        ratio = large / small if present and small else float('inf')
        detail = (f'60k costs {ratio:.2f}x the budget ticks of 10k (limit {MAX_LINEAR_RATIO}x)' if present
                  else 'ticks missing from a ladder row')
        ladder[60_000]['checks'].append(_check('work-linear', present and ratio < MAX_LINEAR_RATIO, detail))
    calls = sorted((r for r in out if r['stage'] == 'ui_calls' and r['status'] == 'measured'), key=lambda r: r['n'])
    shape = ('visible_rows', 'columns', 'first_paint_calls', 'sort_calls', 'filter_calls')
    for big in calls[1:]:
        base = calls[0]
        same = all(big['counts'].get(k) == base['counts'].get(k) for k in shape)
        big['checks'].append(_check('calls-independent-of-n', same,
                                    f'{big["n"]} rows: {[big["counts"].get(k) for k in shape]}, {base["n"]} rows: '
                                    f'{[base["counts"].get(k) for k in shape]} (visible rows, columns, first paint, '
                                    'sort, filter)'))
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


def report(rows: Sequence[dict], env: dict) -> BenchReport:
    pending = [{'stage': s, 'needs': needs, 'limit': name, 'limit_value': value, 'what': what}
               for s, needs, name, value, what in PENDING]
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
    raw = [r.model_dump(mode='json') for r in built.rows]
    fresh = evaluate(raw)                   # the digest covers counts only: gates, checks and verdict must still follow
    if [(r['gates'], r['checks']) for r in fresh] != [(r['gates'], r['checks']) for r in raw] \
            or _verdict(fresh) != built.verdict or built.slack != SLACK:
        raise ContractError('bench report gates, checks or verdict no longer follow from its measurements '
                            '(edited after generation, or L-35 limits changed: run the bench again)')
    return built


# ---- command line --------------------------------------------------------------------------------------------------------------------

def _print(built: BenchReport) -> None:
    for row in built.rows:
        seconds = ' '.join(f'{k} {v:.2f}s' for k, v in row.seconds.items())
        rss = f'{row.peak_rss_bytes / 2**20:.0f} MiB' if row.peak_rss_bytes else 'rss n/a'
        gates = ' '.join(f'{g.name}:{g.verdict}' for g in row.gates) or 'informational'
        bad = ' '.join(c.name for c in row.checks if not c.ok)
        print(f'{row.stage:8s} n={row.n:<8d} {row.status:8s} {seconds} | {rss} | {gates}'
              f'{" | FAILED CHECKS " + bad if bad else ""}{" | " + row.error if row.error else ""}')
    for p in built.pending:
        print(f'pending  {p.stage}: needs {p.needs}, limit {p.limit} = {p.limit_value} ({p.what})')
    print(f'verdict {built.verdict}, counts_sha256 {built.counts_sha256}')


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m tools.unified.bench', description=__doc__.split('\n\n')[0])
    parser.add_argument('--sizes', default=None, help='comma-separated sizes for every stage (functions, changed pairs '
                        'or rows); default: the L-35 sizes of each stage')
    parser.add_argument('--stages', default=','.join(DEFAULT_STAGES), help='comma-separated: ' + ', '.join(STAGES))
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
        given = None if args.sizes is None else [int(s) for s in args.sizes.split(',') if s]
        stages = [s for s in args.stages.split(',') if s]
        if given == [] or not stages or any(s not in STAGES for s in stages) or args.insns < 1:
            raise ValueError
    except ValueError:
        print('error: --sizes needs integers, --stages names from ' + ','.join(STAGES) + ' and --insns a positive number',
              file=sys.stderr)
        return 2
    rows = [measure(stage, n, seed=args.seed, insns=args.insns) for stage in stages
            for n in (given or DEFAULT_SIZES[stage])]
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
