"""Authored report-boundary controls; these are not live accuracy evidence."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import parity, scorerun, scoring  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402


def case(cid, **changes):
    return {
        'id': cid, 'layer': 'L2', 'stratum': 'authored', 'project': f'project-{cid}',
        'source_url': 'https://example.invalid/authored-control', 'licence': 'MIT',
        'older': {'ref': 'old', 'sha256': 'a' * 64},
        'newer': {'ref': 'new', 'sha256': 'b' * 64},
        'expected': {'function': 'Target'}, 'facts': 'verified', 'holdout': False, **changes,
    }


def manifest(*cases):
    return {'schema': 'rq-case-manifest/1', 'cases': list(cases)}


def generic(verb, doc, results):
    return scoring.score_run(doc, results) if verb == 'score' else parity.compare_runs(doc, results, results)


@pytest.mark.parametrize('verb', ['score', 'parity'])
@pytest.mark.parametrize(('key', 'value'), [('layer', 'L3'), ('stratum', 'another'), ('holdout', True)])
def test_generic_report_refuses_mixed_cohorts(verb, key, value):
    doc = manifest(case('a'), case('b', **{key: value}))
    with pytest.raises(ValueError, match='cohort'):
        generic(verb, doc, {'a': ['Target'], 'b': ['Target']})


@pytest.mark.parametrize('verb', ['score', 'parity'])
@pytest.mark.parametrize(('key', 'value'), [('layer', 'L3'), ('stratum', 'another'), ('holdout', True)])
def test_cli_refuses_mixed_cohorts_without_printing_a_result(tmp_path, monkeypatch, capsys, verb, key, value):
    monkeypatch.setenv('RQ_ALLOWED_DIRS', str(tmp_path))
    m, r = tmp_path / 'manifest.json', tmp_path / 'results.json'
    m.write_text(json.dumps(manifest(case('a'), case('b', **{key: value}))), encoding='utf-8')
    r.write_text(json.dumps({'a': ['Target'], 'b': ['Target']}), encoding='utf-8')
    args = [verb, str(m), str(r)] + ([str(r)] if verb == 'parity' else [])
    assert main(args) == 2
    captured = capsys.readouterr()
    assert not captured.out and 'cohort' in captured.err


@pytest.mark.parametrize('verb', ['score', 'parity'])
def test_successful_generic_result_names_its_cohort(verb):
    result = generic(verb, manifest(case('a', layer='L3', holdout=True)), {'a': ['Target']})
    assert {key: result[key] for key in ('layer', 'stratum', 'holdout')} == {
        'layer': 'L3', 'stratum': 'authored', 'holdout': True,
    }


@pytest.mark.parametrize('verb', ['score', 'parity'])
def test_incomplete_cohort_metadata_cannot_hide_a_mixed_claim(verb):
    incomplete = case('a')
    del incomplete['layer']
    with pytest.raises(ValueError, match='cohort'):
        generic(verb, manifest(incomplete), {'a': ['Target']})


def test_repeated_project_withholds_bound_without_dropping_case_results():
    doc = manifest(*(case(str(i), project='same-project') for i in range(29)))
    result = scoring.score_run(doc, {str(i): ['Target'] for i in range(29)})
    assert result['lower_bound'] is None
    assert result['bound_reason'] == 'repeated_projects'
    assert result['scored_projects'] == 1
    assert result['scored'] == result['hits'] == len(result['rows']) == 29


def test_blocked_and_unverified_duplicates_do_not_invalidate_an_admitted_bound():
    doc = manifest(case('a'), case('missing', project='project-a'),
                   case('unverified', project='project-a', facts='unverified'))
    result = scoring.score_run(doc, {'a': ['Target'], 'unverified': ['Target']})
    assert result['lower_bound'] == 0.05
    assert result['scored_projects'] == 1 and result['blocked'] == 2
    assert result['bound_reason'] == 'conditional_on_independence'


def test_missing_project_identity_withholds_bound():
    incomplete = case('a')
    del incomplete['project']
    result = scoring.score_run(manifest(incomplete), {'a': ['Target']})
    assert result['lower_bound'] is None and result['bound_reason'] == 'missing_project'


def l3_run(tmp_path, cases):
    pairs = {}
    for c in cases:
        cid = c['id']
        path = tmp_path / cid
        path.mkdir()
        report = {'functions': {'modified': [{'old': {'name': 'Target', 'fullname': 'Target'},
                                              'new': {'name': 'Target'}, 'diff_type': ['code'], 'ratio': 0.1}],
                                'added': [], 'deleted': []}}
        (path / 'x.ghidriff.json').write_text(json.dumps(report), encoding='utf-8')
        pairs[cid] = {'id': cid, 'status': 'found',
                      'older': {'path': f'{cid}/older/a.sys', 'sha256': 'a' * 64},
                      'newer': {'path': f'{cid}/newer/a.sys', 'sha256': 'b' * 64}}
    return scorerun.score_all(pairs, manifest(*cases), tmp_path, 5, 'ghidriff')


@pytest.mark.parametrize('holdout', [False, True])
def test_l3_repeated_project_bound_is_withheld_in_json_and_markdown(tmp_path, holdout):
    result = l3_run(tmp_path, [case('a', layer='L3', project='same', holdout=holdout),
                               case('b', layer='L3', project='same', holdout=holdout)])
    part = result['holdout' if holdout else 'development']
    assert part['lower_bound'] is None and part['bound_reason'] == 'repeated_projects'
    assert part['scored_projects'] == 1 and part['pass'] == part['scored'] == 2
    assert scorerun.exit_for(result) == 0  # case correctness is independent of claiming a bound
    assert 'repeated_projects' in scorerun.summary_markdown(result)


def test_l3_mixed_strata_have_separate_counts_and_no_pooled_bound(tmp_path):
    result = l3_run(tmp_path, [case('a', layer='L3'), case('b', layer='L3', stratum='other')])
    part = result['development']
    assert part['lower_bound'] is None and part['bound_reason'] == 'mixed_strata'
    assert part['pass'] == 2
    assert set(part['by_stratum']) == {'authored', 'other'}
    assert all(s['lower_bound'] == 0.05 and s['scored'] == 1 for s in part['by_stratum'].values())
    summary = scorerun.summary_markdown(result)
    assert 'mixed_strata' in summary and 'authored' in summary and 'other' in summary


@pytest.mark.parametrize(('key', 'value'), [('layer', []), ('stratum', None), ('stratum', []), ('holdout', 1)])
def test_l3_direct_api_refuses_invalid_cohort_metadata_before_grouping(tmp_path, key, value):
    invalid = case('a', layer='L3')
    invalid[key] = value
    with pytest.raises(scorerun.ScoreRunError, match='cohort'):
        l3_run(tmp_path, [invalid])


def test_l3_missing_project_preserves_case_result_and_withholds_bound(tmp_path):
    incomplete = case('a', layer='L3')
    del incomplete['project']
    result = l3_run(tmp_path, [incomplete])
    assert result['rows'][0]['project'] is None
    assert result['rows'][0]['verdict'] == 'PASS'
    assert result['development']['lower_bound'] is None
    assert result['development']['bound_reason'] == 'missing_project'
