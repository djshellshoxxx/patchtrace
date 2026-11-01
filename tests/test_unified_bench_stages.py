"""Tiny real-path GT12 smoke and independent budget/call-count failure oracles; no acceptance-size runs here."""
from __future__ import annotations

import copy

import pytest

from tools.unified import bench


@pytest.fixture(scope='module')
def measured():
    return {stage: bench.measure(stage, 25, seed=7, insns=20)
            for stage in ('facts', 'read_model', 'ui_calls')}


def test_changed_pairs_really_ingest_ir_and_run_complete_nonbenign_facts(measured):
    row = measured['facts']
    assert row['status'] == 'measured', row['error']
    counts = row['counts']
    assert counts['generated_pairs'] == counts['pairs'] == counts['machine_changed'] == counts['with_deltas'] == 25
    assert counts['nonbenign'] == 25 and counts['limited'] == 0 and counts['mutation_families'] == 5
    assert counts['older_instructions'] > 25 * 10
    assert counts['older_ir_digest'] != counts['newer_ir_digest']
    assert all(v >= 0 for v in row['seconds'].values())
    assert row['seconds']['total'] >= row['seconds']['facts']


def test_persisted_read_model_uses_distinct_mixed_records_and_three_source_cells(measured):
    row = measured['read_model']
    assert row['status'] == 'measured', row['error']
    counts = row['counts']
    assert counts['state'] == 'U3' and counts['unique_rows'] == counts['rows'] == 25
    assert counts['sources'] == 3 and counts['materiality_kinds'] == 5
    assert len(counts['rows_sha256']) == len(counts['facts_sha256']) == 64
    assert bench.evaluate([row])[0]['gates'] == []  # L-35 sets no read-model build-time limit.


def test_real_offscreen_table_paints_sorts_and_selectively_filters(measured):
    row = measured['ui_calls']
    assert row['status'] == 'measured', row['error']
    counts = row['counts']
    assert counts['qt_platform'] == 'offscreen'
    assert counts['shown_rows'] == 25 and counts['filtered_rows'] == 3
    assert counts['sort_correct'] == counts['filter_correct'] == 1
    for operation in ('first_paint', 'sort', 'filter'):
        assert counts[f'{operation}_paints'] > 0 and counts[f'{operation}_data_calls'] > 0
    assert all(c['ok'] for c in bench.evaluate([row])[0]['checks'])


def test_equal_seed_has_equal_fixtures_and_changed_seed_is_not_a_cached_workload(measured):
    for stage, digest in (('facts', 'older_ir_digest'), ('read_model', 'rows_sha256')):
        same = bench.measure(stage, 25, seed=7, insns=20)
        changed = bench.measure(stage, 25, seed=8, insns=20)
        assert same['counts'] == measured[stage]['counts']
        assert changed['counts'][digest] != same['counts'][digest]


def test_replay_parameters_survive_success_and_child_failure(measured):
    for row in measured.values():
        assert (row['counts']['seed'], row['counts']['requested_insns']) == (7, 20)
    failed = bench.measure('facts', 0, seed=23, insns=17)
    assert failed['status'] == 'failed'
    assert (failed['counts']['seed'], failed['counts']['requested_insns']) == (23, 17)


def test_wrong_or_vacuous_work_never_passes_even_when_fast(measured):
    for stage, key, value in (('facts', 'nonbenign', 24), ('facts', 'limited', 1),
                              ('read_model', 'rows', 24), ('ui_calls', 'filtered_rows', 0),
                              ('ui_calls', 'sort_correct', 0), ('ui_calls', 'first_paint_paints', 0),
                              ('ui_calls', 'sort_data_calls', 0), ('ui_calls', 'filter_data_calls', 1_000_000)):
        row = copy.deepcopy(measured[stage])
        row['counts'][key] = value
        assert bench.report(bench.evaluate([row]), {}).verdict == 'fail', (stage, key)


def test_l35_units_sizes_and_inclusive_boundaries_remain_unchanged(measured):
    facts = copy.deepcopy(measured['facts'])
    facts['n'] = 5000
    facts['seconds']['total'] = 300.0  # 60 seconds * existing CI slack 5
    gate = bench.evaluate([facts])[0]['gates'][0]
    assert (gate['name'], gate['unit'], gate['limit'], gate['slack'], gate['verdict']) == (
        'l35_facts_5000_s', 's', 60, 5, 'pass')
    facts['seconds']['total'] += 0.001
    assert bench.evaluate([facts])[0]['gates'][0]['verdict'] == 'fail'
    ui = copy.deepcopy(measured['ui_calls'])
    ui['n'] = 100_000
    ui['seconds'].update(first_paint=1.0, sort=0.75, filter=0.5)
    gates = bench.evaluate([ui])[0]['gates']
    assert [(g['limit'], g['slack'], g['unit'], g['verdict']) for g in gates] == [
        (200, 5, 'ms', 'pass'), (150, 5, 'ms', 'pass'), (100, 5, 'ms', 'pass')]
    for metric in ('first_paint', 'sort', 'filter'):
        slower = copy.deepcopy(ui)
        slower['seconds'][metric] += 0.001
        assert [g['name'] for g in bench.evaluate([slower])[0]['gates'] if g['verdict'] == 'fail'] == [f'l35_{metric}_ms']
    ui['n'] = 10_000
    assert bench.evaluate([ui])[0]['gates'] == []


def test_visible_cell_ceiling_is_exact_and_has_no_time_slack(measured):
    row = copy.deepcopy(measured['ui_calls'])
    row['counts']['sort_visible_cells'] = 100
    row['counts']['sort_data_calls'] = 860  # floor(7 * 100 * 1.2) + 20
    assert next(c['ok'] for c in bench.evaluate([row])[0]['checks'] if c['name'] == 'sort-calls')
    row['counts']['sort_data_calls'] = 861
    assert not next(c['ok'] for c in bench.evaluate([row])[0]['checks'] if c['name'] == 'sort-calls')


def test_unrun_acceptance_sizes_stay_pending_and_failed_measurements_do_not_disappear(measured):
    rows = bench.evaluate(list(measured.values()))
    built = bench.report(rows, {})
    assert built.verdict == 'insufficient-data' and {p.stage for p in built.pending} == set(measured)
    assert bench.load(bench.dump(built)).counts_sha256 == built.counts_sha256
    failed = bench._row('facts', 5000, status='failed', error='original failure')
    built = bench.report(bench.evaluate([failed]), {})
    assert built.verdict == 'fail' and built.rows[0].error == 'original failure'
    assert '5000' in next(p.what for p in built.pending if p.stage == 'facts')


def test_pending_coverage_requires_every_named_size(measured):
    rows = []
    for stage, sizes in bench.SIZES.items():
        if stage not in measured:
            continue
        for size in sizes:
            rows.append(dict(measured[stage], n=size))
    assert bench.report(bench.evaluate(rows), {}).pending == ()
    partial = bench.report(bench.evaluate(rows[:-1]), {})
    assert [p.stage for p in partial.pending] == ['ui_calls']
    assert 'missing sizes 100000' in partial.pending[0].what


def test_cross_size_qt_call_growth_cannot_hide_under_a_large_visible_cell_ceiling(measured):
    small = copy.deepcopy(measured['ui_calls'])
    large = copy.deepcopy(small)
    small['n'], large['n'] = 10_000, 100_000
    small['counts']['sort_data_calls'] = 100
    large['counts']['sort_data_calls'] = 141
    checks = bench.evaluate([small, large])[1]['checks']
    assert next(c['ok'] for c in checks if c['name'] == 'sort-calls')
    assert not next(c['ok'] for c in checks if c['name'] == 'sort-calls-independent-of-n')


def test_default_sizes_are_stage_specific_without_running_large_jobs(monkeypatch):
    requests = []

    def record(stage, n, **kwargs):
        requests.append((stage, n))
        return bench._row(stage, n, status='failed', error='measurement deliberately not run by CLI routing test')

    monkeypatch.setattr(bench, 'measure', record)
    assert bench.main(['--stages', 'facts,read_model,ui_calls']) == 1
    assert requests == [('facts', 5000), ('read_model', 10_000), ('read_model', 100_000),
                        ('ui_calls', 10_000), ('ui_calls', 100_000)]
    assert bench.main(['--stages', '', '--sizes', '10']) == 2
