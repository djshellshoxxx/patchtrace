"""SPEC-31 S6a bench harness for gate G-U5 (tools/unified/bench.py; 08-evaluation s6, L-35).

SYNTHETIC workloads only (the generators of tests/unified_ir_builder.py, tests/unified_extract_builder.py,
tests/unified_facts_builder.py and tests/unified_read_support.py): they measure the cost of the algorithms, not Ghidra or real
binaries. Sizes here are tiny; the real sizes (10k, 60k, 250k) run in the
`unified-corpus.yml` workflow and their numbers are recorded in docs/qa.md, never asserted here."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS), str(TESTS.parent / 'src')]
from unified_s6_helpers import evaluated, row  # noqa: E402

from patchtrace.unified.limits import DEFAULT_LIMITS  # noqa: E402
from tools.calibration.tier_r.contracts import ContractError  # noqa: E402
from tools.unified import bench  # noqa: E402


def verdicts(rows):
    return {(r['stage'], r['n'], g['name']): g['verdict'] for r in rows for g in r['gates']}


def test_the_constants_are_the_ones_the_spec_and_the_s2_perf_tests_state():
    assert bench.SLACK == 5                                             # 08 s6: CI wall-clock slack
    assert 60_000 * bench.INSNS == 3_000_000                            # L-35: ingest of 60k functions / 3 M instructions
    assert (bench.TICKS_PER_FUNCTION, bench.MAX_LINEAR_RATIO) == (12, 7.0)   # tests/test_unified_ladder_perf.py


def test_peak_rss_is_a_positive_number_of_bytes_here():
    peak = bench.peak_rss_bytes()
    assert isinstance(peak, int) and peak > 1_000_000


def test_the_five_x_slack_is_inclusive_and_both_sides_plus_ladder_and_ladder_alone_are_gated():
    limit = DEFAULT_LIMITS.l35_ladder_10k_s * bench.SLACK
    ok = verdicts(evaluated(row(ladder=limit - 1, sides=1)))
    assert ok[('ladder', 10_000, 'l35_ladder_10k_s')] == 'pass'
    edge = verdicts(evaluated(row(ladder=limit, sides=0)))
    assert edge[('ladder', 10_000, 'l35_ladder_10k_s')] == 'pass'                     # >= timings, never ==
    slow_total = verdicts(evaluated(row(ladder=limit - 1, sides=2)))
    assert slow_total[('ladder', 10_000, 'l35_ladder_10k_s')] == 'fail'               # sides + ladder counts too
    assert verdicts(evaluated(row(ladder=limit + 0.5, sides=0)))[('ladder', 10_000, 'l35_ladder_10k_s')] == 'fail'


def test_l35_defines_10k_and_60k_for_the_ladder_and_60k_for_ingest_and_rss_nothing_else_is_gated():
    rows = evaluated(row(n=10_000), row(n=60_000), row(n=250_000), row('ingest', 60_000), row('ingest', 10_000))
    gated = {(r['stage'], r['n'], g['name']) for r in rows for g in r['gates']}
    assert gated == {('ladder', 10_000, 'l35_ladder_10k_s'), ('ladder', 60_000, 'l35_ladder_60k_s'),
                     ('ladder', 60_000, 'l35_worker_rss_bytes'), ('ingest', 60_000, 'l35_ingest_60k_s'),
                     ('ingest', 60_000, 'l08_ingest_rss_bytes')}


def test_rss_has_no_slack_and_a_missing_rss_is_not_measured_never_a_pass():
    cap = DEFAULT_LIMITS.l35_worker_rss_bytes
    assert verdicts(evaluated(row(n=60_000, rss=cap)))[('ladder', 60_000, 'l35_worker_rss_bytes')] == 'pass'
    assert verdicts(evaluated(row(n=60_000, rss=cap + 1)))[('ladder', 60_000, 'l35_worker_rss_bytes')] == 'fail'
    assert verdicts(evaluated(row(n=60_000, rss=None)))[('ladder', 60_000, 'l35_worker_rss_bytes')] == 'not-measured'


def checks(rows, name):
    return {(r['stage'], r['n']): c['ok'] for r in rows for c in r['checks'] if c['name'] == name}


def test_the_synthetic_consistency_checks_catch_wrong_spurious_and_missing_pairs():
    rows = evaluated(row(n=1000), row(n=1000, wrong=1), row(n=1000, spurious=2), row(n=1000, right=900),
                     row(n=1000, status='partial'), row(n=1000, limits_hit='budget'))
    by_row = [{c['name']: c['ok'] for c in r['checks']} for r in rows]
    assert [c['complete'] for c in by_row] == [True, True, True, True, False, False]
    assert [c['consistent'] for c in by_row] == [True, False, False, False, True, True]


def test_work_per_function_is_bounded_and_does_not_grow_with_n():
    good = evaluated(row(n=10_000, ticks=60_000), row(n=60_000, ticks=360_000))
    assert checks(good, 'ticks-per-function') == {('ladder', 10_000): True, ('ladder', 60_000): True}
    assert checks(good, 'work-linear') == {('ladder', 60_000): True}
    quadratic = evaluated(row(n=10_000, ticks=60_000), row(n=60_000, ticks=60_000 * 36))
    assert checks(quadratic, 'work-linear') == {('ladder', 60_000): False}
    heavy = evaluated(row(n=10_000, ticks=13 * 10_000))
    assert checks(heavy, 'ticks-per-function') == {('ladder', 10_000): False}
    assert checks(evaluated(row(n=60_000, ticks=360_000)), 'work-linear') == {}      # no 10k row to compare with


def test_the_ingest_row_must_have_read_back_every_generated_function_and_instruction():
    sound = evaluated(row('ingest', 500, functions=500, instructions=5000, generated_functions=500,
                          generated_instructions=5000))
    assert checks(sound, 'ingest-complete') == {('ingest', 500): True}
    short = evaluated(row('ingest', 500, functions=499, instructions=5000, generated_functions=500,
                          generated_instructions=5000))
    assert checks(short, 'ingest-complete') == {('ingest', 500): False}


def test_stages_that_wait_for_s3_and_s4_are_listed_with_their_limits_and_never_silently_absent():
    built = bench.report([], bench.environment())
    pending = {p.stage: p for p in built.pending}
    assert set(pending) == {'facts', 'read_model', 'ui_calls'}
    assert pending['facts'].limit_value == DEFAULT_LIMITS.l35_facts_5000_s                    # built, not measured here
    assert 'not measured in this report' in pending['facts'].what
    assert 'not measured in this report' in pending['read_model'].what and 'first_paint' in pending['read_model'].limit
    assert pending['ui_calls'].needs == 'S4b' and 'first_paint' in pending['ui_calls'].limit  # data() counts need Qt
    assert built.verdict == 'insufficient-data'                                      # nothing was measured


# ---- facts and read_model (UE-R4a): rows with the shape the children produce ----------------------------------------------------

MATERIALITY_KEYS = ('unchanged', 'cosmetic', 'material', 'review', 'unknown', 'not_applicable')


def facts_row(n=5_000, *, facts=1.0, rss=200 * 2**20, **counts):
    base = {'functions': n, 'changed': n, 'rows': n, 'matched': n, 'judged': n, 'changed_judged': n,
            'status': 'complete', 'limitations': '', 'result_id': 'r' * 64,
            **{f'materiality/{m}': (n if m == 'review' else 0) for m in MATERIALITY_KEYS}}
    return {'stage': 'facts', 'n': n, 'status': 'measured', 'peak_rss_bytes': rss,
            'seconds': {'build': 2.0, 'ladder': 0.5, 'fusion': 0.2, 'facts': facts, 'write': 0.5, 'compute': facts + 1.2},
            'counts': {**base, **counts}, 'derived': {}, 'error': None}


def read_row(n=10_000, *, filter=0.01, sort=0.02, first_paint=0.03, **counts):
    seconds = {'generate': 0.4, 'filter': filter, 'sort': sort, 'first_paint': first_paint}
    collapsed = (n + 2) // 20
    base = {'rows': n, 'columns': 5, 'shown': n - collapsed, 'collapsed': collapsed, 'searched': 1,
            'sorted': n - collapsed, 'painted_cells': 50 * 5, 'paint_sha256': 'p' * 64}
    return {'stage': 'read_model', 'n': n, 'status': 'measured', 'peak_rss_bytes': 300 * 2**20,
            'seconds': {k: v for k, v in seconds.items() if v is not None}, 'counts': {**base, **counts}, 'derived': {},
            'error': None}


def test_the_default_stage_list_has_the_new_stages_so_the_frozen_workflow_runs_them():
    assert bench.STAGES == ('ladder', 'ingest', 'facts', 'read_model')
    assert bench.L35_SIZES == {'facts': (5_000,), 'read_model': (10_000, 100_000)}


def test_l35_gates_only_at_facts_5000_and_read_model_10k_100k():
    rows = evaluated(facts_row(), facts_row(n=4_999), facts_row(n=50), read_row(), read_row(n=100_000),
                     read_row(n=50_000), read_row(n=2_000))
    gated = {(r['stage'], r['n'], g['name']) for r in rows for g in r['gates']}
    assert gated == {('facts', 5_000, 'l35_facts_5000_s'),
                     *(('read_model', n, name) for n in (10_000, 100_000)
                       for name in ('l35_filter_ms', 'l35_sort_ms', 'l35_first_paint_ms'))}
    assert all(g['verdict'] == 'pass' for r in rows for g in r['gates'])
    assert bench.report(rows, bench.environment()).verdict == 'pass'
    facts_gate = next(g for r in rows for g in r['gates'] if g['name'] == 'l35_facts_5000_s')
    assert (facts_gate['unit'], facts_gate['slack'], facts_gate['observed']) == ('s', 5, 1.0)   # the facts span only


def test_ms_gate_has_5x_slack_and_missing_is_not_measured():
    def gate(row, name):
        return next(g for g in evaluated(row)[0]['gates'] if g['name'] == name)
    for name, key in (('l35_filter_ms', 'filter'), ('l35_sort_ms', 'sort'), ('l35_first_paint_ms', 'first_paint')):
        limit = getattr(DEFAULT_LIMITS, name)
        edge = gate(read_row(**{key: limit * bench.SLACK / 1000}), name)
        assert (edge['unit'], edge['slack'], edge['allowed'], edge['verdict']) == ('ms', 5, limit * 5, 'pass')
        assert edge['observed'] == limit * 5                                       # milliseconds, >= never ==
        assert gate(read_row(**{key: (limit * bench.SLACK + 1) / 1000}), name)['verdict'] == 'fail'
        assert gate(read_row(**{key: None}), name)['verdict'] == 'not-measured'
    assert bench.report(evaluated(read_row(first_paint=None)), bench.environment()).verdict == 'insufficient-data'
    slow = bench.report(evaluated(read_row(n=100_000, sort=1.0)), bench.environment())
    assert slow.verdict == 'fail' and bench.load(bench.dump(slow)).rows[0].gates[1].unit == 'ms'


def test_the_new_stages_have_checks_on_their_counts():
    assert checks(evaluated(facts_row()), 'facts-judged') == {('facts', 5_000): True}
    assert checks(evaluated(facts_row(changed_judged=4_999)), 'facts-judged') == {('facts', 5_000): False}
    assert checks(evaluated(facts_row(status='partial')), 'facts-judged') == {('facts', 5_000): False}
    assert checks(evaluated(read_row()), 'read-model-consistent') == {('read_model', 10_000): True}
    assert checks(evaluated(read_row(sorted=3)), 'read-model-consistent') == {('read_model', 10_000): False}
    assert checks(evaluated(read_row(painted_cells=10)), 'read-model-consistent') == {('read_model', 10_000): False}


def test_sizes_flag_keeps_new_stages_at_their_l35_sizes(monkeypatch, capsys):
    assert bench.plan(['ladder', 'ingest', 'facts', 'read_model'], [150, 300]) == [
        ('ladder', 150), ('ladder', 300), ('ingest', 150), ('ingest', 300), ('facts', 5_000), ('read_model', 10_000),
        ('read_model', 100_000)]
    calls = []

    def fake(stage, n, **kwargs):
        calls.append((stage, n))
        return bench._row(stage, n, status='failed', error='not run in this test')
    monkeypatch.setattr(bench, 'measure', fake)
    assert bench.main(['--sizes', '150']) == 1                                       # the failed rows fail the report
    assert calls == [('ladder', 150), ('ingest', 150), ('facts', 5_000), ('read_model', 10_000), ('read_model', 100_000)]
    calls.clear()
    assert bench.main(['--sizes', '7', '--stages', 'facts,read_model']) == 1
    assert calls == [('facts', 5_000), ('read_model', 10_000), ('read_model', 100_000)]
    capsys.readouterr()


def test_built_stage_absent_from_report_stays_pending():
    from tools.unified import gates_u
    ladder_only = bench.report(evaluated(row(n=10_000), row(n=60_000, ticks=360_000), row('ingest', 60_000)),
                               {**bench.environment(), 'platform': 'Windows-11'})
    pending = {p.stage: p for p in ladder_only.pending}
    assert set(pending) == {'facts', 'read_model', 'ui_calls'} and ladder_only.verdict == 'pass'
    for stage in ('facts', 'read_model'):
        assert 'not measured in this report' in pending[stage].what
    g5 = gates_u._g_u5(gates_u.Inputs(benches=[ladder_only]))
    assert g5[0] == 'pending' and any('facts' in r and 'not measured' in r for r in g5[1])     # never a pass
    half = bench.report(evaluated(facts_row(), read_row()), bench.environment())             # 100k missing
    assert {p.stage for p in half.pending} == {'read_model', 'ui_calls'}
    failed = dict(facts_row(), status='failed', error='boom')
    assert 'facts' in {p.stage for p in bench.report(bench.evaluate([failed]), bench.environment()).pending}
    full = bench.report(evaluated(facts_row(), read_row(), read_row(n=100_000)), bench.environment())
    assert [p.stage for p in full.pending] == ['ui_calls'] and full.verdict == 'pass'


def test_the_counts_digest_ignores_timings_and_memory_and_sees_every_count():
    a, b = evaluated(row(ladder=1.0, rss=1)), evaluated(row(ladder=9.0, rss=999))
    assert bench.counts_sha256(a) == bench.counts_sha256(b)
    assert bench.counts_sha256(a) != bench.counts_sha256(evaluated(row(wrong=1)))


def test_the_overall_verdict_is_fail_pass_or_insufficient_data():
    env = bench.environment()
    assert bench.report(evaluated(row()), env).verdict == 'pass'
    assert bench.report(evaluated(row(ladder=10**6)), env).verdict == 'fail'
    assert bench.report(evaluated(row(wrong=1)), env).verdict == 'fail'
    assert bench.report(evaluated(row(n=250_000)), env).verdict == 'insufficient-data'     # informational size only
    failed = dict(row(), status='failed', error='boom')
    assert bench.report(bench.evaluate([failed]), env).verdict == 'fail'


def test_the_report_round_trips_strictly_and_a_changed_number_is_noticed():
    built = bench.report(evaluated(row(), row(n=60_000)), bench.environment())
    data = bench.dump(built)
    assert bench.load(data).counts_sha256 == built.counts_sha256
    assert data.endswith(b'\n') and b'\r' not in data
    tampered = json.loads(data)
    tampered['rows'][0]['counts']['wrong'] = 5
    with pytest.raises(ContractError, match='counts digest'):
        bench.load(json.dumps(tampered).encode('utf-8'))


def test_a_live_result_becomes_informational_extract_rows_with_the_cost_per_instruction():
    live = {'machine': 'x86_64', 'os': 'Linux', 'python': '3.13', 'script_sha256': 'a' * 64, 'sides': {
        side: {'artifact_sha256': 'b' * 64, 'content_digest': 'c' * 64, 'ir_key': 'd' * 64, 'hashers': None,
               'probe': {'ghidra': '12.0.4'}, 'warnings': [], 'seconds': {'extract': 40.0, 'ingest': 1.0},
               'counts': {'functions': 250, 'instructions': 20_000, 'blocks': 4000}} for side in ('older', 'newer')}}
    rows = bench.extract_rows(live)
    assert [r['stage'] for r in rows] == ['extract', 'extract'] and rows[0]['n'] == 250
    assert rows[0]['derived'] == {'us_per_instruction': 2000.0}
    assert bench.evaluate(rows)[0]['gates'] == []                                   # a data point, not a limit
    with pytest.raises(ContractError):
        bench.extract_rows({'sides': {}})


# ---- real, tiny measurements in fresh processes ------------------------------------------------------------------------------------

def test_the_ladder_stage_runs_in_a_fresh_process_and_the_synthetic_pairs_are_consistent():
    measured = bench.measure('ladder', 300, seed=1)
    assert measured['status'] == 'measured' and measured['peak_rss_bytes'] > 1_000_000
    counts = measured['counts']
    assert counts['wrong'] == 0 and counts['spurious'] == 0 and counts['status'] == 'complete'
    assert counts['right'] >= 0.99 * counts['truth'] and counts['ticks'] > 0
    assert set(measured['seconds']) == {'generate', 'sides', 'ladder', 'total'}
    again = bench.measure('ladder', 300, seed=1)
    assert again['counts'] == counts                                                # deterministic apart from timings


def test_the_ingest_stage_reads_back_what_it_generated_and_is_deterministic():
    measured = bench.measure('ingest', 120, seed=1, insns=8)
    counts = measured['counts']
    assert (counts['functions'], counts['instructions']) == (120, 120 * 9) == (
        counts['generated_functions'], counts['generated_instructions'])
    assert len(counts['content_digest']) == 64 and counts['jsonl_bytes'] > 0
    assert bench.measure('ingest', 120, seed=1, insns=8)['counts'] == counts
    assert bench.measure('ingest', 120, seed=2, insns=8)['counts']['content_digest'] != counts['content_digest']


def test_a_child_that_fails_is_a_failed_row_with_its_error_not_a_crash():
    failed = bench.measure('ladder', 0, seed=1)                                     # generate_pair refuses n = 0
    assert failed['status'] == 'failed' and failed['error'] and failed['peak_rss_bytes'] is None
    assert bench.evaluate([failed])[0]['gates'] == []
    assert bench.measure('nope', 10, seed=1)['status'] == 'failed'


def test_facts_stage_judges_every_changed_pair_in_a_fresh_process():
    measured = bench.measure('facts', 40, seed=1)
    assert measured['status'] == 'measured', measured['error']
    assert measured['peak_rss_bytes'] > 1_000_000
    counts = measured['counts']
    assert counts['functions'] == counts['changed'] == counts['judged'] == counts['changed_judged'] == 40
    assert counts['matched'] == counts['rows'] == 40 and counts['status'] == 'complete'
    assert counts['materiality/unchanged'] == 0
    assert sum(counts[f'materiality/{m}'] for m in MATERIALITY_KEYS) == 40
    assert {'build', 'facts', 'compute'} <= set(measured['seconds']) and measured['seconds']['facts'] > 0
    assert measured['seconds']['facts'] < measured['seconds']['compute']               # the span, not the whole step
    assert checks(bench.evaluate([measured]), 'facts-judged') == {('facts', 40): True}
    assert bench.measure('facts', 40, seed=1)['counts'] == counts                        # deterministic apart from timings


def test_read_model_stage_times_filter_sort_and_first_paint():
    measured = bench.measure('read_model', 2_000, seed=1)
    assert measured['status'] == 'measured', measured['error']
    seconds, counts = measured['seconds'], measured['counts']
    assert all(seconds[k] > 0 for k in ('filter', 'sort', 'first_paint'))
    assert counts['rows'] == 2_000 and counts['columns'] == 5 and counts['searched'] == 1
    assert counts['shown'] + counts['collapsed'] == 2_000 and counts['sorted'] == counts['shown']
    assert counts['painted_cells'] == 50 * counts['columns'] and len(counts['paint_sha256']) == 64
    assert checks(bench.evaluate([measured]), 'read-model-consistent') == {('read_model', 2_000): True}
    assert bench.measure('read_model', 2_000, seed=1)['counts'] == counts


def test_child_output_is_bounded(monkeypatch):
    loud = [sys.executable, '-c', "import sys; sys.stdout.write('x' * 300_000); sys.stdout.flush()"]
    monkeypatch.setattr(bench, 'OUTPUT_CAP', 100_000)
    code, out, err, problem = bench.run_child(loud, timeout=120)
    assert problem and 'exceeds' in problem and len(out) <= bench.TAIL_BYTES
    monkeypatch.setattr(bench, 'TAIL_BYTES', 1_000)
    noisy = [sys.executable, '-c', "import sys; sys.stderr.write('e' * 50_000 + 'END'); sys.exit(3)"]
    code, out, err, problem = bench.run_child(noisy, timeout=120)
    assert (code, problem, out) == (3, None, '') and len(err) <= 1_000 and err.endswith('END')
    monkeypatch.setattr(bench, 'OUTPUT_CAP', 64)                                     # a result line is larger than this
    failed = bench.measure('ladder', 5, seed=1)
    assert failed['status'] == 'failed' and 'exceeds' in failed['error'] and failed['counts'] == {}


def test_the_command_line_writes_a_report_and_exits_by_the_verdict(tmp_path, capsys):
    out = tmp_path / 'bench.json'
    code = bench.main(['--sizes', '150', '--stages', 'ladder,ingest', '--insns', '6', '--out', str(out)])
    built = bench.load(out.read_bytes())
    assert {(r.stage, r.n) for r in built.rows} == {('ladder', 150), ('ingest', 150)}
    assert code == 0 and built.verdict == 'insufficient-data'                         # 150 is not an L-35 size
    assert 'pending' in capsys.readouterr().out
    assert bench.main(['--sizes', 'abc']) == 2 and bench.main(['--stages', 'nope', '--sizes', '10']) == 2
