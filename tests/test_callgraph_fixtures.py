"""WB2 G0: synthetic call-graph fixtures are strict JSON, normalize, and carry the shapes the plan names."""
from __future__ import annotations

import json
from collections import Counter

import pytest
from callgraph_fixtures import FIXTURE_DIR, FIXTURE_NAMES, build_fixture, dump_fixture, project_for_fixtures

from patchtrace.models import FunctionMatch
from patchtrace.normalization import normalize_ghidriff


def strict_load(text: str) -> dict:
    def reject_duplicate_keys(items):
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError('duplicate key')
        return dict(items)

    def reject_constant(name):
        raise ValueError(f'non-standard constant {name}')

    return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)


def committed(name: str) -> str:
    return (FIXTURE_DIR / f'{name}.json').read_bytes().decode('utf-8')


def side_records(raw: dict, side: str) -> list[dict]:
    functions = raw['functions']
    if side == 'newer':
        return list(functions['added']) + [item['new'] for item in functions['modified']]
    return list(functions['deleted']) + [item['old'] for item in functions['modified']]


@pytest.mark.parametrize('name', FIXTURE_NAMES, ids=FIXTURE_NAMES)
def test_committed_fixture_matches_builder_output_byte_for_byte(name):
    text = committed(name)
    assert '\r' not in text and text.endswith('\n')
    assert text == dump_fixture(build_fixture(name))


@pytest.mark.parametrize('name', FIXTURE_NAMES, ids=FIXTURE_NAMES)
def test_fixture_is_strict_json_and_round_trips(name):
    assert strict_load(committed(name)) == build_fixture(name)


@pytest.mark.parametrize('name', FIXTURE_NAMES, ids=FIXTURE_NAMES)
def test_fixture_passes_normalize_ghidriff(name):
    project, run_id = project_for_fixtures()
    matches = normalize_ghidriff(strict_load(committed(name)), project, run_id)
    assert matches and all(isinstance(match, FunctionMatch) for match in matches)


def test_svc_pair_has_the_known_answer_shape():
    raw = strict_load(committed('svc_pair'))
    modified_older = {item['old']['name'] for item in raw['functions']['modified']}
    assert modified_older == {'DriverEntry', 'FUN_140001500', 'FUN_140001600', 'FUN_140001800', 'FUN_140001c00'}
    added = {record['name'] for record in raw['functions']['added']}
    assert added == {'FUN_140001f00', 'ntoskrnl.exe::ProbeForRead', 'ntoskrnl.exe::EtwWriteTransfer'}
    externals = [record for record in raw['functions']['added'] if record['external']]
    assert len(externals) == 2 and all(record['address'].startswith('EXTERNAL:') for record in externals)
    assert raw['matches']['name_matches']['FUN_140001200'] == [['FUN_140001340', ['ExactBytesFunctionHasher']]]
    assert 'FUN_140001200' not in {record['name'] for record in side_records(raw, 'older')}


def test_hostile_names_are_carried_as_data_and_exceed_the_label_limit():
    raw = strict_load(committed('hostile_names'))
    names = [record['name'] for side in ('older', 'newer') for record in side_records(raw, side)]
    assert any('‮' in name for name in names)
    assert any(' ' in name for name in names)
    assert any('\n' in name for name in names)
    assert any('"' in name and '\\' in name for name in names)
    assert any(len(name) > 512 for name in names)


def test_ambiguous_pair_has_one_qualified_name_on_two_newer_functions():
    raw = strict_load(committed('ambiguous_pair'))
    newer = Counter(record['name'] for record in side_records(raw, 'newer'))
    assert newer['parser.dll::Parse'] >= 2


def test_no_matches_fixture_has_no_matches_section_and_the_sample_call_change():
    raw = strict_load(committed('no_matches'))
    assert 'matches' not in raw
    read_item = next(record for record in side_records(raw, 'newer') if record['name'] == 'read_item')
    assert read_item['called'] == ['report_invalid_index']


def test_count_suffix_fixture_has_one_inferable_stem_and_one_ambiguous_stem():
    raw = strict_load(committed('count_suffix'))
    newer = side_records(raw, 'newer')
    counts = Counter(record['name'] for record in newer)
    dispatch = next(record for record in newer if record['name'] == 'Dispatch')
    unresolved = [label for label in dispatch['called'] if label not in counts]
    assert 'ReadBuffer-3' in unresolved and counts['ReadBuffer'] == 1
    assert 'Write-2' in unresolved and counts['Write'] == 2


def test_cycle_hub_fixture_has_a_cycle_and_a_fan_in_of_at_least_64():
    raw = strict_load(committed('cycle_hub'))
    newer = {record['name']: record for record in side_records(raw, 'newer')}
    assert 'CycleB' in newer['CycleA']['called'] and 'CycleA' in newer['CycleB']['called']
    assert len(newer['TraceMessageHub']['calling']) >= 64
