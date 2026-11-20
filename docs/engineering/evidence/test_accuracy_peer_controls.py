"""Independent authored report-boundary controls; no empirical accuracy evidence."""
from __future__ import annotations

import copy
import hashlib
import json

import pytest

from tools.research_qualification import parity, scorerun, scoring
from tools.research_qualification.__main__ import main


def case(cid, **updates):
    record = {
        'id': cid, 'layer': 'L2', 'stratum': 'authored-msvc', 'project': 'project-' + cid,
        'source_url': 'https://example.org/authored-control', 'licence': 'CC0',
        'older': {'ref': 'authored-old', 'sha256': hashlib.sha256(b'peer older fixture').hexdigest()},
        'newer': {'ref': 'authored-new', 'sha256': hashlib.sha256(b'peer newer fixture').hexdigest()},
        'expected': {'function': 'PatchedFunction'}, 'facts': 'verified', 'holdout': False,
    }
    record.update(updates)
    return record


def manifest(*records):
    return {'schema': 'rq-case-manifest/1', 'cases': list(records)}


def results(records):
    return {c['id']: ['PatchedFunction'] for c in records}


@pytest.mark.parametrize('api', ['score', 'parity'])
@pytest.mark.parametrize(('field', 'value'), [('layer', 'L3'), ('stratum', 'authored-mingw'), ('holdout', True)])
def test_generic_boundaries_refuse_mixed_cohort(api, field, value):
    records = [case('one'), case('two', **{field: value})]
    data, candidates = manifest(*records), results(records)
    with pytest.raises(ValueError):
        if api == 'score':
            scoring.score_run(data, candidates)
        else:
            parity.compare_runs(data, candidates, candidates)


@pytest.mark.parametrize('api', ['score', 'parity'])
@pytest.mark.parametrize('field', ['layer', 'stratum', 'holdout'])
def test_generic_boundary_requires_explicit_cohort_metadata(api, field):
    record = case('one')
    del record[field]
    data, candidates = manifest(record), results([record])
    with pytest.raises(ValueError):
        if api == 'score':
            scoring.score_run(data, candidates)
        else:
            parity.compare_runs(data, candidates, candidates)


@pytest.mark.parametrize('count', [2, 29])
def test_repeated_project_hits_do_not_receive_case_binomial_bound(count):
    records = [case(f'case-{i}', project='one-authored-project') for i in range(count)]
    report = scoring.score_run(manifest(*records), results(records))
    assert report['scored'] == report['hits'] == count
    assert report['lower_bound'] is None


def test_repeated_project_preserves_miss_and_false_positive_counts():
    records = [case('hit', project='same'), case('miss', project='same'),
               case('nochange', project='same', expected={'no_change': True})]
    report = scoring.score_run(manifest(*records),
                               {'hit': ['PatchedFunction'], 'miss': ['Other'], 'nochange': ['Unexpected']})
    assert (report['scored'], report['hits'], report['misses'], report['false_positives']) == (3, 1, 1, 1)
    assert report['lower_bound'] is None


@pytest.mark.parametrize('project', [None, '', '   ', 17])
def test_missing_or_invalid_project_identity_never_receives_bound(project):
    record = case('one', project=project)
    try:
        report = scoring.score_run(manifest(record), results([record]))
    except ValueError:
        return  # An explicit typed refusal also satisfies the boundary.
    assert report['lower_bound'] is None


def test_absent_project_identity_never_receives_bound():
    record = case('one')
    del record['project']
    try:
        report = scoring.score_run(manifest(record), results([record]))
    except ValueError:
        return
    assert report['lower_bound'] is None


@pytest.mark.parametrize('count', [1, 2, 29])
def test_one_case_per_distinct_project_keeps_conditional_all_hit_bound(count):
    records = [case(f'case-{i}') for i in range(count)]
    report = scoring.score_run(manifest(*records), results(records))
    # Closed-form all-success one-sided exact bound, independent of the implementation helper.
    assert report['lower_bound'] == round(0.05 ** (1 / count), 3)


def test_blocked_cases_do_not_inflate_or_suppress_scored_project_bound():
    records = [case('only-hit', project='same'), case('missing-report', project='same')]
    records += [case(f'unverified-{i}', project='same', facts='unverified') for i in range(29)]
    candidates = results(records)
    del candidates['missing-report']
    report = scoring.score_run(manifest(*records), candidates)
    assert (report['scored'], report['hits'], report['blocked']) == (1, 1, 30)
    assert report['lower_bound'] == 0.05
    compare = parity.compare_runs(manifest(*records), candidates, candidates)
    assert (compare['compared'], compare['blocked']) == (1, 30)
    assert compare['mean_jaccard_at_k'] == 1.0


def test_empty_runs_make_no_accuracy_or_parity_claim():
    score = scoring.score_run(manifest(), {})
    compare = parity.compare_runs(manifest(), {}, {})
    assert score['scored'] == 0 and score['lower_bound'] is None
    assert compare['compared'] == 0 and compare['identical'] is False
    assert compare['mean_jaccard_at_k'] is None


def write_l3(reports, record):
    folder = reports / record['id']
    folder.mkdir(parents=True)
    # Authored JSON report, not a native engine invocation.
    report = {'functions': {'modified': [
        {'old': {'name': 'PatchedFunction', 'fullname': 'PatchedFunction'},
         'new': {'name': 'PatchedFunction'}, 'diff_type': ['code'], 'ratio': 0.1}],
        'added': [], 'deleted': []}}
    (folder / 'authored.ghidriff.json').write_text(json.dumps(report), encoding='utf-8')
    return {'id': record['id'], 'status': 'found',
            'older': {'path': record['id'] + '/older/a.sys', 'sha256': record['older']['sha256']},
            'newer': {'path': record['id'] + '/newer/a.sys', 'sha256': record['newer']['sha256']}}


def test_l3_mixed_strata_never_receive_pooled_bound(tmp_path):
    records = [case('one', layer='L3'), case('two', layer='L3', stratum='authored-mingw')]
    reports = tmp_path / 'reports'
    pairs = {c['id']: write_l3(reports, c) for c in records}
    report = scorerun.score_all(pairs, manifest(*records), reports, 5, 'ghidriff')
    assert report['development']['scored'] == 2
    assert report['development']['lower_bound'] is None
    assert report['holdout']['lower_bound'] is None


def test_l3_repeated_projects_withhold_each_set_bound(tmp_path):
    records = [case(f'case-{i}', layer='L3', project='same', holdout=i >= 2) for i in range(4)]
    reports = tmp_path / 'reports'
    pairs = {c['id']: write_l3(reports, c) for c in records}
    report = scorerun.score_all(pairs, manifest(*records), reports, 5, 'ghidriff')
    assert report['development']['scored'] == report['holdout']['scored'] == 2
    assert report['development']['lower_bound'] is report['holdout']['lower_bound'] is None
    assert scorerun.exit_for(report) == 0  # case mechanics passed; an accuracy bound is withheld.


def test_l3_blocked_other_layer_and_stratum_do_not_enter_bound(tmp_path):
    records = [case('one', layer='L3'), case('unverified', layer='L3', facts='unverified', stratum='blocked'),
               case('l2', layer='L2', stratum='blocked')]
    reports = tmp_path / 'reports'
    pairs = {c['id']: write_l3(reports, c) for c in records}
    report = scorerun.score_all(pairs, manifest(*records), reports, 5, 'ghidriff')
    assert (report['development']['scored'], report['development']['blocked']) == (1, 2)
    assert report['development']['lower_bound'] == 0.05


@pytest.mark.parametrize('command', ['score', 'parity'])
@pytest.mark.parametrize(('field', 'value'), [('layer', 'L3'), ('stratum', 'other'), ('holdout', True)])
def test_cli_mixed_cohort_is_usage_refusal(tmp_path, capsys, monkeypatch, command, field, value):
    monkeypatch.delenv('RQ_ALLOWED_DIRS', raising=False)
    records = [case('one'), case('two', **{field: value})]
    mpath, rpath = tmp_path / 'manifest.json', tmp_path / 'results.json'
    mpath.write_text(json.dumps(manifest(*records)), encoding='utf-8')
    rpath.write_text(json.dumps(results(records)), encoding='utf-8')
    args = [command, str(mpath), str(rpath)]
    if command == 'parity':
        args.append(str(rpath))
    assert main(args) == 2
    output = capsys.readouterr()
    assert not output.out.strip()
    assert output.err.strip()


def test_review_controls_leave_inputs_unchanged():
    record = case('one')
    data, candidates = manifest(record), results([record])
    original = copy.deepcopy((data, candidates))
    scoring.score_run(data, candidates)
    parity.compare_runs(data, candidates, candidates)
    assert (data, candidates) == original
