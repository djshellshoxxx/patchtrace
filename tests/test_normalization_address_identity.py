"""Synthetic address spelling boundary tests, not live Ghidriff compatibility evidence."""
from __future__ import annotations

import copy

import pytest

from patchtrace.models import AnalysisRun, Artifact, ComparisonProject
from patchtrace.normalization import normalize_ghidriff
from patchtrace.sample import sample_diff


@pytest.fixture
def inputs():
    run = AnalysisRun(status='completed')
    project = ComparisonProject(name='p', runs=[run], artifacts=[
        Artifact(side='older', name='o.dll', sha256='a' * 64, size=1, relative_path='artifacts/o.bin'),
        Artifact(side='newer', name='n.dll', sha256='b' * 64, size=1, relative_path='artifacts/n.bin')])
    return sample_diff(project), project, run.id


@pytest.mark.parametrize(('first', 'second'), [
    ('180001000', '0x180001000'), ('180001abc', '180001ABC'),
    ('180001000', ' 180001000 '), ('0', '0x0'),
    (None, ''), ('', 'not-an-address'), (None, '10000000000000000'),
])
@pytest.mark.parametrize('placement', ['modified', 'one-sided'])
def test_same_function_under_equivalent_addresses_rejected(inputs, first, second, placement):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    pair['old']['address'] = first
    if placement == 'modified':
        repeated = copy.deepcopy(pair)
        repeated['old']['address'] = second
        repeated['new']['name'] = repeated['new']['fullname'] = 'another_counterpart'
        repeated['new']['address'] = '180009000'
        raw['functions']['modified'].append(repeated)
    else:
        repeated = copy.deepcopy(pair['old'])
        repeated['address'] = second
        raw['functions']['deleted'].append(repeated)
    with pytest.raises(ValueError, match='PT-SCHEMA: upstream function is repeated'):
        normalize_ghidriff(raw, project, run_id)


def test_distinct_parsed_addresses_keep_original_text(inputs):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    pair['old']['address'] = '0x180001000'
    repeated = copy.deepcopy(pair)
    repeated['old']['address'] = '180001001'
    repeated['new']['name'] = repeated['new']['fullname'] = 'another_counterpart'
    repeated['new']['address'] = '180009000'
    raw['functions']['modified'].append(repeated)
    result = normalize_ghidriff(raw, project, run_id)
    assert {match.older[0].address for match in result if match.category == 'modified'} >= {
        '0x180001000', '180001001'}


def test_same_address_with_different_function_names_remains_distinct(inputs):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    repeated = copy.deepcopy(pair)
    repeated['old']['name'] = repeated['old']['fullname'] = 'another_old'
    repeated['new']['name'] = repeated['new']['fullname'] = 'another_new'
    raw['functions']['modified'].append(repeated)
    result = normalize_ghidriff(raw, project, run_id)
    assert sum(match.category == 'modified' for match in result) == len(raw['functions']['modified'])


@pytest.mark.parametrize('fullname', [None, 'qualified::same'])
def test_identity_uses_qualified_name_or_fallback(inputs, fullname):
    raw, project, run_id = inputs
    pair = raw['functions']['modified'][0]
    pair['old']['fullname'] = fullname
    repeated = copy.deepcopy(pair)
    repeated['old']['address'] = '0x' + pair['old']['address']
    if fullname:
        # Different short names still refer to the same qualified identity.
        repeated['old']['name'] = 'different_short_name'
    repeated['new']['name'] = repeated['new']['fullname'] = 'another_new'
    repeated['new']['address'] = '180009000'
    raw['functions']['modified'].append(repeated)
    with pytest.raises(ValueError, match='PT-SCHEMA: upstream function is repeated'):
        normalize_ghidriff(raw, project, run_id)
