"""Additional independent controls written during source review, not real accuracy evidence."""
from __future__ import annotations

import json

import pytest
from test_accuracy_peer_controls import case, manifest, results, write_l3

from tools.research_qualification import parity, scorerun, scoring


@pytest.mark.parametrize(('field', 'value'), [
    ('layer', []), ('layer', {}), ('stratum', []), ('stratum', None), ('holdout', 1), ('holdout', 'false'),
])
def test_generic_cohort_invalid_types_refuse_cleanly(field, value):
    record = case('one', **{field: value})
    for api in (
        lambda: scoring.score_run(manifest(record), results([record])),
        lambda: parity.compare_runs(manifest(record), results([record]), results([record])),
    ):
        with pytest.raises(ValueError):
            api()


@pytest.mark.parametrize(('field', 'value'), [
    ('layer', []), ('stratum', []), ('stratum', None), ('holdout', 1),
])
def test_l3_invalid_cohort_metadata_refuses_before_grouping(tmp_path, field, value):
    record = case('one', layer='L3')
    record[field] = value
    with pytest.raises(scorerun.ScoreRunError):
        scorerun.score_all({}, manifest(record), tmp_path, 5, 'ghidriff')


def test_l3_missing_project_reports_withheld_bound_instead_of_keyerror(tmp_path):
    record = case('one', layer='L3')
    del record['project']
    reports = tmp_path / 'reports'
    pair = write_l3(reports, record)
    report = scorerun.score_all({'one': pair}, manifest(record), reports, 5, 'ghidriff')
    assert report['rows'][0]['project'] is None
    assert report['development']['scored'] == 1
    assert report['development']['lower_bound'] is None
    assert report['development']['bound_reason'] == 'missing_project'


def test_l3_mixed_strata_summary_and_saved_result_keep_all_bound_reasons(tmp_path):
    records = [case('one', layer='L3', stratum='same|\nstratum', project='shared'),
               case('two', layer='L3', stratum='same|\nstratum', project='shared'),
               case('three', layer='L3', stratum='other')]
    reports = tmp_path / 'reports'
    pairs = {c['id']: write_l3(reports, c) for c in records}
    report = scorerun.score_all(pairs, manifest(*records), reports, 5, 'ghidriff')
    development = report['development']
    assert development['lower_bound'] is None
    assert development['by_stratum']['same|\nstratum']['bound_reason'] == 'repeated_projects'
    assert development['by_stratum']['other']['lower_bound'] == 0.05
    assert development['by_stratum']['other']['bound_reason'] == 'conditional_on_independence'
    markdown = scorerun.summary_markdown(report)
    assert 'same\\| stratum' in markdown
    assert 'same|\nstratum' not in markdown
    assert 'repeated_projects' in markdown and 'conditional_on_independence' in markdown
    result_path, receipt_path = scorerun.write_outputs(report, tmp_path / 'out', '2026-11-19T00:00:00Z')
    saved = json.loads(result_path.read_text(encoding='utf-8'))
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    assert saved == report
    assert receipt['result']['status'] == 'PASS'  # correct authored case outcomes, not an accuracy claim.
    assert saved['development']['lower_bound'] is None
    assert receipt['result']['counters']['scored'] == 3


def test_missing_project_does_not_modify_the_frozen_manifest():
    record = case('one')
    del record['project']
    data = manifest(record)
    original = json.dumps(data, sort_keys=True)
    report = scoring.score_run(data, results([record]))
    assert report['bound_reason'] == 'missing_project'
    assert json.dumps(data, sort_keys=True) == original
