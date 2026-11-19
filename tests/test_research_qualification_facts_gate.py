"""Unverified manifest facts cannot produce accuracy or engine-parity credit."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import parity, scoring  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402


def _case(cid, *, facts='verified', expected=None):
    # The verified branch is an authored scoring control, not a real CVE claim.
    return {
        'id': cid, 'layer': 'L2', 'stratum': 'authored', 'project': f'fixture-{cid}',
        'source_url': 'https://example.invalid/authored-fixture', 'licence': 'MIT',
        'older': {'ref': 'authored-older', 'sha256': hashlib.sha256(b'older fixture').hexdigest()},
        'newer': {'ref': 'authored-newer', 'sha256': hashlib.sha256(b'newer fixture').hexdigest()},
        'expected': expected or {'function': 'target'}, 'facts': facts, 'holdout': False,
    }


@pytest.mark.parametrize(('expected', 'candidates'), [
    ({'function': 'target'}, ['target']),
    ({'function': 'target', 'accept': ['renamed']}, ['renamed']),
    ({'no_change': True}, []),
])
def test_unverified_results_never_score_even_when_the_expected_answer_matches(expected, candidates):
    case = _case('unverified', facts='unverified', expected=expected)
    result = scoring.score_case(case, candidates)
    assert result == {'id': 'unverified', 'outcome': 'BLOCKED', 'rank': None,
                      'reason': 'facts_not_verified'}


@pytest.mark.parametrize('facts', [None, '', 'Verified', 'verified '])
def test_missing_or_unknown_facts_fail_closed(facts):
    case = _case('unknown', facts=facts)
    if facts is None:
        del case['facts']
    assert scoring.score_case(case, ['target'])['outcome'] == 'BLOCKED'


def test_unverified_cases_cannot_inflate_counts_or_the_confidence_denominator():
    verified = [_case('hit'), _case('miss')]
    unverified = [_case('unverified-hit', facts='unverified'),
                  _case('unverified-empty', facts='unverified', expected={'no_change': True})]
    results = {'hit': ['target'], 'miss': ['other'], 'unverified-hit': ['target'], 'unverified-empty': []}
    full = scoring.score_run({'cases': verified + unverified}, results)
    admitted = scoring.score_run({'cases': verified}, {'hit': ['target'], 'miss': ['other']})
    assert (full['cases'], full['scored'], full['blocked'], full['hits'], full['misses']) == (4, 2, 2, 1, 1)
    assert full['top1'] == 1 and full['false_positives'] == 0
    assert full['lower_bound'] == admitted['lower_bound']
    assert [row['rank'] for row in full['rows'][2:]] == [None, None]


def test_unverified_cases_cannot_produce_parity_or_disagreement_credit():
    cases = [_case('verified'), _case('unverified-hit', facts='unverified'),
             _case('unverified-diff', facts='unverified'),
             _case('unverified-empty', facts='unverified', expected={'no_change': True})]
    a = {'verified': ['target', 'a'], 'unverified-hit': ['target'],
         'unverified-diff': ['target'], 'unverified-empty': []}
    b = {'verified': ['target', 'b'], 'unverified-hit': ['target'],
         'unverified-diff': ['other'], 'unverified-empty': []}
    result = parity.compare_runs({'cases': cases}, a, b)
    assert result['compared'] == 1 and result['blocked'] == 3
    assert result['outcomes']['both-hit'] == 1 and result['disagreements'] == []
    assert result['mean_overlap_at_k'] == 1 and result['mean_jaccard_at_k'] == round(1 / 3, 3)
    assert all(row['a']['rank'] is None and row['b']['rank'] is None
               for row in result['rows'] if row['outcome'] == 'blocked')


@pytest.mark.parametrize('verb', ['score', 'parity'])
def test_public_cli_does_not_succeed_on_only_unverified_facts(tmp_path, monkeypatch, capsys, verb):
    monkeypatch.setenv('RQ_ALLOWED_DIRS', str(tmp_path))
    manifest = {'schema': 'rq-case-manifest/1', 'cases': [
        _case('match', facts='unverified'),
        _case('empty', facts='unverified', expected={'no_change': True}),
    ]}
    m, r = tmp_path / 'manifest.json', tmp_path / 'results.json'
    m.write_text(json.dumps(manifest), encoding='utf-8')
    r.write_text(json.dumps({'match': ['target'], 'empty': []}), encoding='utf-8')
    args = [verb, str(m), str(r)] + ([str(r)] if verb == 'parity' else [])
    assert main(args) == (2 if verb == 'parity' else 1)
    result = json.loads(capsys.readouterr().out)
    assert result['blocked'] == 2
    if verb == 'score':
        assert result['scored'] == result['hits'] == result['top1'] == 0
        assert result['lower_bound'] is None
        assert all(row['outcome'] == 'BLOCKED' for row in result['rows'])
    else:
        assert result['compared'] == 0 and result['identical'] is False
        assert result['mean_overlap_at_k'] is result['mean_jaccard_at_k'] is None
        assert result['outcomes']['both-hit'] == 0
