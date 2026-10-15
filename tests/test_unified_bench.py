"""SPEC-31 S6a bench harness for gate G-U5 (tools/unified/bench.py; 08-evaluation s6, L-35).

SYNTHETIC workloads only (the generators of tests/unified_ir_builder.py and tests/unified_extract_builder.py): they measure the
cost of the algorithms, not Ghidra or real binaries. Sizes here are tiny; the real sizes (10k, 60k, 250k) run in the
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
    assert pending['facts'].needs == 'S3' and pending['facts'].limit_value == DEFAULT_LIMITS.l35_facts_5000_s
    assert pending['ui_calls'].needs == 'S4' and 'first_paint' in pending['ui_calls'].limit
    assert built.verdict == 'insufficient-data'                                      # nothing was measured


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


def test_the_command_line_writes_a_report_and_exits_by_the_verdict(tmp_path, capsys):
    out = tmp_path / 'bench.json'
    code = bench.main(['--sizes', '150', '--stages', 'ladder,ingest', '--insns', '6', '--out', str(out)])
    built = bench.load(out.read_bytes())
    assert {(r.stage, r.n) for r in built.rows} == {('ladder', 150), ('ingest', 150)}
    assert code == 0 and built.verdict == 'insufficient-data'                         # 150 is not an L-35 size
    assert 'pending' in capsys.readouterr().out
    assert bench.main(['--sizes', 'abc']) == 2 and bench.main(['--stages', 'nope', '--sizes', '10']) == 2
