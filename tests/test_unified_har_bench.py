"""SPEC-31 harness audit (card har): UE-R4 bench stages `facts`, `read_model`, `ui_calls`, G-U5 wiring and U7-13 (bounded,
tree-killing child runs). Sizes are tiny here; the real sizes (5,000 pairs, 10k and 100k rows) are the CLI defaults and are
recorded in docs/qa.md, never asserted."""
from __future__ import annotations

import copy
import os
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS), str(TESTS.parent / 'src')]
from unified_s6_helpers import evaluated, row  # noqa: E402

from patchtrace.unified.limits import DEFAULT_LIMITS  # noqa: E402
from tools.unified import bench, gates_u  # noqa: E402


def stage_row(stage, n, *, seconds=None, counts=None):
    return {'stage': stage, 'n': n, 'status': 'measured', 'seconds': seconds or {}, 'peak_rss_bytes': 100 * 2**20,
            'counts': counts or {}, 'derived': {}, 'error': None}


def facts_row(n=5000, seconds=1.0):
    return stage_row('facts', n, seconds={'facts': seconds}, counts={'pairs': n, 'changed': n, 'verdict/review': n})


def read_row(n=100_000, **seconds):
    base = {'first_paint': 0.01, 'sort': 0.01, 'filter': 0.01, 'build': 1.0}
    return stage_row('read_model', n, seconds={**base, **seconds},
                     counts={'rows': n, 'state': 'U3', 'shown_default': n // 2, 'sorted': n // 2, 'shown_filtered': 10,
                             'collapsed': n // 2, 'columns': 5})


def ui_row(n, **over):
    counts = {'rows': n, 'columns': 5, 'visible_rows': 19, 'shown': 10, 'first_paint_calls': 1330, 'sort_calls': 665,
              'filter_calls': 1330}
    return stage_row('ui_calls', n, counts={**counts, **over})


def verdicts(rows):
    return {(r['stage'], r['n'], g['name']): g['verdict'] for r in rows for g in r['gates']}


# ---- facts -------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('fail_newer', [False, True])
def test_facts_readers_close_before_temporary_files_are_removed(monkeypatch, fail_newer):
    import unified_facts_builder as fb

    opened = []
    build = fb.build_reader

    def reader(*args, **kwargs):
        if fail_newer and opened:
            raise RuntimeError('newer ingest failed')
        result = build(*args, **kwargs)
        opened.append(result)
        return result

    monkeypatch.setattr(fb, 'build_reader', reader)
    if fail_newer:
        with pytest.raises(RuntimeError, match='newer ingest failed'):
            bench._facts(2, 1)
    else:
        assert bench._facts(2, 1)['counts']['pairs'] == 2
    assert len(opened) == (1 if fail_newer else 2)
    assert all(r._db is None for r in opened)


def test_bench_facts_stage_reports_counts_and_gate():
    measured = bench.measure('facts', 40, seed=1)
    assert measured['status'] == 'measured', measured['error']
    assert measured['counts']['pairs'] == measured['counts']['changed'] == 40
    assert {'build_images', 'context', 'judge', 'facts'} <= set(measured['seconds'])
    assert bench.measure('facts', 40, seed=1)['counts'] == measured['counts']             # deterministic
    done = bench.evaluate([measured])[0]
    assert done['gates'] == [] and [c['ok'] for c in done['checks']] == [True]            # 40 pairs is not an L-35 size
    limit = DEFAULT_LIMITS.l35_facts_5000_s * bench.SLACK
    assert verdicts(bench.evaluate([facts_row(seconds=limit)]))[('facts', 5000, 'l35_facts_5000_s')] == 'pass'
    assert verdicts(bench.evaluate([facts_row(seconds=limit + 0.5)]))[('facts', 5000, 'l35_facts_5000_s')] == 'fail'
    short = facts_row()
    short['counts']['changed'] = 4999                                                      # a pair that was not judged
    assert not bench.evaluate([short])[0]['checks'][0]['ok']


# ---- read model --------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('n', [200, 700])
def test_bench_read_model_stage_at_10k_and_100k(n):
    """The stage at two small stand-ins for 10k and 100k rows: real stored result, real `load_unified`."""
    measured = bench.measure('read_model', n, seed=1)
    assert measured['status'] == 'measured', measured['error']
    counts = measured['counts']
    assert counts['rows'] == n and counts['state'] == 'U3' and counts['sorted'] == counts['shown_default'] > 0
    assert {'build', 'first_paint', 'sort', 'filter'} <= set(measured['seconds'])
    assert bench.evaluate([measured])[0]['checks'][0]['ok']
    assert bench.measure('read_model', n, seed=1)['counts'] == counts


def test_read_model_limits_are_gated_at_100k_only_in_milliseconds_with_five_x_slack():
    assert bench.evaluate([read_row(10_000)])[0]['gates'] == []                            # 10k is informational
    edge = verdicts(bench.evaluate([read_row(first_paint=0.2 * 5, sort=0.15 * 5, filter=0.1 * 5)]))
    assert set(edge.values()) == {'pass'} and len(edge) == 3
    slow = verdicts(bench.evaluate([read_row(first_paint=1.01, sort=0.76, filter=0.51)]))
    assert set(slow.values()) == {'fail'}
    gate = {g['name']: g for g in bench.evaluate([read_row(sort=0.3)])[0]['gates']}['l35_sort_ms']
    assert (gate['unit'], gate['limit'], gate['allowed'], round(gate['observed'])) == ('ms', 150, 750, 300)
    broken = read_row()
    broken['counts']['rows'] = 99_999
    assert not bench.evaluate([broken])[0]['checks'][0]['ok']


# ---- ui calls ----------------------------------------------------------------------------------------------------------------------

def test_bench_ui_calls_exact_data_call_counts():
    small, large = bench.measure('ui_calls', 150, seed=1), bench.measure('ui_calls', 1500, seed=1)
    for measured in (small, large):
        assert measured['status'] == 'measured', measured['error']
        assert measured['seconds'] == {}                                                   # counts, never times
    keys = ('visible_rows', 'columns', 'first_paint_calls', 'sort_calls', 'filter_calls')
    assert [small['counts'][k] for k in keys] == [large['counts'][k] for k in keys]        # independent of the row count
    assert small['counts']['first_paint_calls'] > 0
    assert bench.measure('ui_calls', 150, seed=1)['counts'] == small['counts']             # exact, repeatable
    done = bench.evaluate([small, large])
    assert all(c['ok'] for r in done for c in r['checks'])
    assert {c['name'] for c in done[1]['checks']} == {'calls-bounded-by-visible-cells', 'calls-independent-of-n'}


def test_ui_calls_that_grow_with_the_row_count_or_exceed_the_visible_cells_fail():
    assert all(c['ok'] for r in bench.evaluate([ui_row(10_000), ui_row(100_000)]) for c in r['checks'])
    growing = bench.evaluate([ui_row(10_000), ui_row(100_000, first_paint_calls=1330 + 5)])
    assert [c['name'] for c in growing[1]['checks'] if not c['ok']] == ['calls-independent-of-n']
    per_row = bench.evaluate([ui_row(10_000, sort_calls=10_000 * 5)])[0]
    assert [c['name'] for c in per_row['checks'] if not c['ok']] == ['calls-bounded-by-visible-cells']
    nothing = bench.evaluate([ui_row(10_000, first_paint_calls=0)])[0]
    assert not nothing['checks'][0]['ok']                                                   # no call at all = nothing measured


# ---- G-U5 --------------------------------------------------------------------------------------------------------------------------

def report(platform, *, extra=()):
    env = {**bench.environment(), 'platform': platform}
    rows = evaluated(row(n=10_000, ticks=60_000), row(n=60_000, ticks=360_000), row('ingest', 60_000))
    return bench.report(rows + bench.evaluate(list(extra)), env)


FULL = (facts_row(), read_row(10_000), read_row(), ui_row(10_000), ui_row(100_000))


def g5(*benches):
    inputs = gates_u.Inputs(benches=list(benches))
    return {g.id: g for g in gates_u.build_report(inputs).gates}['G-U5']


def test_pending_list_is_empty_and_every_stage_is_selectable():
    assert bench.PENDING == () and set(bench.STAGES) == {'ladder', 'ingest', 'facts', 'read_model', 'ui_calls'}
    assert bench.report([], bench.environment()).pending == ()
    assert bench.main(['--stages', 'nope', '--sizes', '10']) == 2 and bench.main(['--stages', '']) == 2


def test_g_u5_pending_clears_only_with_windows_report():
    linux = g5(report('Linux-6', extra=FULL))
    text = ' '.join(linux.reasons)
    assert linux.status == 'pending' and 'Windows' in text and 'not measured' not in text    # stages present
    both = g5(report('Linux-6', extra=FULL), report('Windows-11', extra=FULL))
    assert both.status == 'pending' and 'Windows' not in ' '.join(both.reasons)
    assert both.observed['windows_report'] is True
    assert any('largest Tier R pair' in r for r in both.reasons)                              # waits stay honest
    # a Windows report that measured no gated size is no Windows evidence
    empty = bench.report(bench.evaluate([row(n=250_000)]), {**bench.environment(), 'platform': 'Windows-11'})
    assert g5(report('Linux-6', extra=FULL), empty).observed['windows_report'] is False


def test_g_u5_names_every_stage_that_was_not_measured():
    reasons = ' '.join(g5(report('Linux-6'), report('Windows-11')).reasons)
    for stage in ('facts', 'read_model', 'ui_calls'):
        assert f'stage {stage} not measured' in reasons
    partial = ' '.join(g5(report('Linux-6', extra=(facts_row(), read_row(), ui_row(10_000)))).reasons)
    assert 'stage facts not measured' not in partial and 'stage read_model not measured' not in partial
    assert 'stage ui_calls not measured' in partial                                           # both sizes are needed
    wrong_size = ' '.join(g5(report('Linux-6', extra=(facts_row(4000), read_row(50_000), ui_row(10_000),
                                                     ui_row(100_000)))).reasons)
    assert 'stage facts not measured' in wrong_size and 'stage read_model not measured' in wrong_size


def test_g_u5_fails_on_a_slow_new_stage_or_a_failed_call_check():
    slow = g5(report('Linux-6', extra=(facts_row(seconds=10**4),)))
    assert slow.status == 'fail' and any('l35_facts_5000_s' in r for r in slow.reasons)
    bad = g5(report('Linux-6', extra=(ui_row(10_000, first_paint_calls=0),)))
    assert bad.status == 'fail' and any('calls-bounded' in r for r in bad.reasons)


# ---- U7-13: bounded output, process tree killed ----------------------------------------------------------------------------------------

def _run(code, *, timeout=30, max_output=bench.MAX_CHILD_OUTPUT):
    return bench.run_child([sys.executable, '-c', code], cwd=str(Path.cwd()), env=dict(os.environ), timeout=timeout,
                           max_output=max_output)


def test_a_child_that_floods_its_output_is_stopped_not_buffered():
    started = time.monotonic()
    done = _run('import sys\nwhile True:\n    sys.stdout.write("x" * 65536)\n    sys.stdout.flush()',
                max_output=1_000_000)
    assert done.reason == 'output-limit' and time.monotonic() - started < 25
    assert len(done.log_tail) <= bench.CHILD_LOG_TAIL                                        # only a tail is kept


@pytest.mark.skipif(os.name == 'nt', reason='the grandchild is observed with os.kill(pid, 0)')
def test_a_timeout_kills_the_grandchildren_too(tmp_path):
    pid_file = tmp_path / 'pid'
    code = ('import subprocess, sys, time\n'
            'p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])\n'
            f'open({str(pid_file)!r}, "w").write(str(p.pid))\n'
            'time.sleep(120)')
    done = _run(code, timeout=2)
    assert done.reason == 'timeout'
    pid = int(pid_file.read_text())
    deadline = time.monotonic() + 5
    alive = True
    while alive and time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
            os.waitpid(pid, os.WNOHANG)
            time.sleep(0.05)
        except (ProcessLookupError, ChildProcessError):
            alive = False
    assert not alive, 'the grandchild survived the timeout'


def test_measure_turns_flood_timeout_and_spawn_failure_into_failed_rows(monkeypatch):
    real = bench.run_child
    monkeypatch.setattr(bench, 'run_child', lambda argv, **kw: real([sys.executable, '-c', 'import time; time.sleep(60)'],
                                                                   **{**kw, 'timeout': 1}))
    failed = bench.measure('ladder', 10)
    assert failed['status'] == 'failed' and 'timeout' in failed['error']
    monkeypatch.setattr(bench, 'run_child', lambda argv, **kw: real(
        [sys.executable, '-c', 'import sys\nwhile True:\n    sys.stdout.write("y" * 65536)\n    sys.stdout.flush()'],
        **{**kw, 'max_output': 200_000}))
    assert 'output-limit' in bench.measure('ladder', 10)['error']

    def boom(argv, **kw):
        raise OSError('no such interpreter')
    monkeypatch.setattr(bench, 'run_child', boom)
    assert 'could not run' in bench.measure('ladder', 10)['error']


def test_the_cli_runs_the_new_stages_and_reports_them(tmp_path, capsys):
    out = tmp_path / 'b.json'
    code = bench.main(['--sizes', '150', '--stages', 'facts,read_model,ui_calls', '--out', str(out)])
    built = bench.load(out.read_bytes())
    assert {(r.stage, r.n) for r in built.rows} == {('facts', 150), ('read_model', 150), ('ui_calls', 150)}
    assert all(r.status == 'measured' for r in built.rows), [r.error for r in built.rows]
    assert code == 0 and built.verdict == 'insufficient-data' and built.pending == ()
    assert 'ui_calls' in capsys.readouterr().out
    clone = copy.deepcopy(built.model_dump(mode='json'))
    assert clone['rows'][0]['gates'] == []
