"""PIL-A1 contract freeze: `pilot/1` records, schemas and examples, limits, errors and the additive-only guarantees
(docs/specs/program-e/PIL-integration-plan.md s7, s9). Synthetic data only; nothing here is live evidence.

Mandatory gates of PIL-A1: regenerate-and-compare, invalid examples rejected for their reason,
`test_strong_is_unreachable`, `test_assessment_has_no_floats`, `test_old_reader_ignores_patch_intent`.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import get_args

import pytest
from pydantic import TypeAdapter, ValidationError

import patchtrace.pilot as pilot_package
from patchtrace.enrichment import storage
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence import contracts as intel
from patchtrace.pilot import contracts, keys
from patchtrace.pilot.limits import (
    DEFAULT_LIMITS,
    ERROR_CODES,
    EXIT_CODES,
    GIB,
    KIB,
    MIB,
    TARGETS,
    Budget,
    BudgetExhausted,
    PilotError,
    PilotLimits,
)
from patchtrace.sample import create_sample
from patchtrace.secondary import load_secondary
from patchtrace.secondary.evidence_view import sanitize_text
from patchtrace.secondary.store import current_sets

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(pilot_package.__file__).parent  # the package under test, wherever it is imported from
SCHEMAS = ROOT / 'docs' / 'schemas' / 'pilot'
EXAMPLES = SCHEMAS / 'examples'
INDEX = json.loads((EXAMPLES / 'index.json').read_text(encoding='utf-8'))
NAMES = sorted(INDEX)
VALID = [n for n in NAMES if INDEX[n]['valid']]
INVALID = [n for n in NAMES if not INDEX[n]['valid']]
FUTURE = '9999-01-01T00:00:00+00:00'
X = 'f' * 64


def generator():
    spec = importlib.util.spec_from_file_location('generate_pilot_schemas', ROOT / 'tools' / 'generate_pilot_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def doc(name: str):
    return json.loads((EXAMPLES / name).read_text(encoding='utf-8'))


def model_of(name: str):
    return getattr(contracts, INDEX[name]['model'])


def rejection(model, document) -> str | None:
    """None when the document validates, else the validation error text (JSON mode, as stored rows are read)."""
    try:
        model.model_validate_json(json.dumps(document))
    except ValidationError as exc:
        return str(exc)
    return None


def assert_rejected(model, document, text: str) -> None:
    message = rejection(model, document)
    assert message is not None, f'{model.__name__} accepted a document that must be rejected ({text})'
    assert text in message, message[:600]


ASSESSMENT = doc('valid-PilotAssessment.json')
LEAD_FIT, LEAD_REVIEW, LEAD_QUEUE = ASSESSMENT['leads'][:3]
LEAD_CODE = doc('valid-Lead-code-only.json')
OBS = ASSESSMENT['observations'][0]
CONTEXT = ASSESSMENT['cves'][0]


def lead(base: dict, **over) -> dict:
    return {**base, **over}


# --- vocabulary and field freeze (additive only: extending any of these means editing this test) -----------------

def test_vocabularies_match_the_plan_s7():
    assert get_args(contracts.Role) == ('shape', 'local', 'counter', 'conflict', 'context')
    assert get_args(contracts.Verification) == ('verified-bytes', 'tool-reported', 'label-only', 'advisory-claim',
                                                'rule-hypothesis', 'analyst-assertion')
    assert contracts.MECHANISMS == ('strong', 'moderate', 'tentative', 'unexplained', 'contested', 'not-assessed')
    assert get_args(contracts.LeadClass) == ('fit', 'review', 'partial', 'code', 'queue')
    assert get_args(contracts.Identity) == ('corroborated', 'contested', 'unassessed')
    assert get_args(contracts.CveGate) == ('applies', 'asserted', 'unverified', 'conflict', 'not-applicable', 'none')
    assert get_args(contracts.ChannelState) == ('available', 'partial', 'not-run', 'unsupported', 'failed', 'stale')
    assert get_args(contracts.Depth) == ('typed', 'lexical', 'none')
    assert get_args(contracts.ChangeState) == ('met', 'not-observed', 'unknown', 'contradicted')
    assert get_args(contracts.Channel) == ('advisory', 'code', 'calls', 'strings', 'capa', 'build', 'pairing')
    assert get_args(contracts.ReviewAction) == ('pin', 'unpin', 'dismiss', 'restore', 'note')
    assert get_args(contracts.Cap) == ('confounded-window-needs-locality', 'toolchain-changed-lexical-only',
                                       'cve-unverified', 'cve-conflict')
    assert get_args(contracts.KevState) == ('listed', 'not-in-snapshot', 'unknown')
    assert get_args(contracts.WindowState) == ('yes', 'no', 'unknown')
    assert get_args(contracts.RunStatus) == ('complete', 'partial', 'abstained')
    assert contracts.CONTRACT == 'pilot/1'


FROZEN_FIELDS = {
    'Observation': ('obs_id', 'channel', 'kind', 'role', 'verification', 'origins', 'evidence_class', 'obligations',
                    'anchor_ids', 'ref', 'nav', 'detail'),
    'ObsRef': ('kind', 'id', 'pointer', 'sha256'),
    'Nav': ('side', 'rva', 'start_line', 'end_line'),
    'ExpectedChange': ('id', 'state', 'required', 'observation_ids', 'teach_id'),
    'HypothesisFit': ('hypothesis_id', 'rule_id', 'rule_revision', 'cwe_id', 'basis', 'expected_changes', 'met',
                      'total'),
    'LeadComponents': ('count', 'tags'),
    'Tie': ('size', 'first', 'last'),
    'FunctionRef': ('rva', 'name'),
    'Lead': ('candidate_key', 'cve', 'lead_class', 'mechanism', 'identity', 'gate', 'depth', 'fits', 'components',
             'local_hits', 'caps', 'support_ids', 'counter_ids', 'unknown_ids', 'alternative_ids', 'rank', 'tie',
             'assessment', 'older', 'newer'),
    'LeadCounts': ('fit', 'review', 'partial', 'code', 'queue'),
    'ApplicabilitySummary': ('older', 'newer', 'older_mapping', 'newer_mapping', 'contradictions'),
    'CweSummary': ('status', 'ids'),
    'Kev': ('state', 'date_added', 'snapshot_id'),
    'Confounding': ('state', 'cves'),
    'CveContext': ('cve', 'source_ids', 'gate', 'applicability', 'cwe', 'kev', 'confounding', 'counts',
                   'limitations'),
    'ChannelStatus': ('channel', 'state', 'reason'),
    'ToolKey': ('engine', 'side', 'cache_key'),
    'PilotConfig': ('locality_min_tokens', 'confounded_min_cves', 'lexical_moderate', 'limits_digest'),
    'PilotInputs': ('older_sha256', 'newer_sha256', 'orientation', 'ghidriff_run_id', 'raw_sha256',
                    'unified_result_id', 'secondary_set_ids', 'tool_keys', 'advisory_facts_ids', 'kev_snapshot_id',
                    'kb_link_digest', 'asserted_gates', 'lexicon_digest', 'rules_digest', 'pilot_rules_digest',
                    'origins_digest', 'tiers_version', 'config_digest'),
    'PilotAssessment': ('contract', 'result_id', 'project_id', 'revision', 'older_sha256', 'newer_sha256',
                        'orientation', 'inputs', 'channels', 'cves', 'leads', 'queue_count', 'observations',
                        'status', 'limitations', 'limits_hit', 'created_utc'),
    'ReviewEvent': ('contract', 'candidate_key', 'cve', 'action', 'text', 'created_utc'),
    'PilotPart': ('name', 'sha256', 'bytes'),
    'PilotResultPointer': ('contract', 'result_id', 'relative_dir', 'manifest_sha256', 'status', 'counts',
                           'config_digest'),
    'PilotManifest': ('contract', 'result_id', 'inputs', 'config', 'status', 'limitations', 'counts', 'queue_count',
                      'parts', 'created_utc'),
}


@pytest.mark.parametrize('name', sorted(FROZEN_FIELDS), ids=[f'm{i}' for i in range(len(FROZEN_FIELDS))])
def test_persisted_fields_are_frozen_in_order(name):
    """Persisted contracts are additive only: a field may be appended (with a default) by editing this table."""
    model = getattr(contracts, name)
    assert tuple(model.model_fields) == FROZEN_FIELDS[name]
    assert model.model_config['extra'] == 'forbid' and model.model_config['strict'] is True
    assert model.model_config['frozen'] is True


def test_strong_is_unreachable():
    """`strong` is a reserved word of the vocabulary; no lead can carry it until a typed channel exists (s1, s7)."""
    assert 'strong' in contracts.MECHANISMS
    assert 'strong' not in contracts.ASSIGNABLE_MECHANISMS and contracts.STRONG_REACHABLE is False
    schema = contracts.Lead.model_json_schema()
    assert 'strong' not in schema['properties']['mechanism']['enum']
    for model, _ident in contracts.SCHEMA_MODELS:  # no pilot schema enumerates it anywhere
        assert '"strong"' not in json.dumps(model.model_json_schema())
    assert_rejected(contracts.Lead, lead(LEAD_FIT, mechanism='strong'), 'reserved')
    for base in (LEAD_FIT, LEAD_REVIEW, LEAD_QUEUE):
        assert_rejected(contracts.Lead, lead(base, mechanism='strong'), 'reserved')
    strong = json.loads(json.dumps(ASSESSMENT))
    strong['leads'][0]['mechanism'] = 'strong'
    assert_rejected(contracts.PilotAssessment, strong, 'reserved')
    assert not any('strong' in m for classes in contracts.CLASS_MECHANISMS.values() for m in classes)
    for mechanism in ('strong', 'STRONG', ' strong'):
        assert rejection(contracts.Lead, lead(LEAD_FIT, mechanism=mechanism)) is not None


def _numbers(node, path=''):
    """Every integer leaf (bools excluded) of a JSON document with its path."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _numbers(value, f'{path}/{key}')
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _numbers(value, f'{path}/{index}')
    elif isinstance(node, int) and not isinstance(node, bool):
        yield path


def _replace(document, path: str, value):
    out = json.loads(json.dumps(document))
    target = out
    parts = path.strip('/').split('/')
    for part in parts[:-1]:
        target = target[int(part)] if isinstance(target, list) else target[part]
    last = parts[-1]
    if isinstance(target, list):
        target[int(last)] = value
    else:
        target[last] = value
    return out


def test_assessment_has_no_floats():
    """Ordering comes from integer counts and classes (s6): no float in a schema, a document or an input."""
    for model, _ident in contracts.SCHEMA_MODELS:
        text = json.dumps(model.model_json_schema())
        assert '"number"' not in text and '"float"' not in text, model.__name__

    def refuse(token):
        raise AssertionError(f'float literal {token} in a pilot document')

    raw = (EXAMPLES / 'valid-PilotAssessment.json').read_text(encoding='utf-8')
    json.loads(raw, parse_float=refuse)
    assessment = contracts.PilotAssessment.model_validate_json(raw)
    json.loads(keys.canonical_bytes(assessment), parse_float=refuse)
    json.loads(assessment.model_dump_json(), parse_float=refuse)
    paths = list(_numbers(ASSESSMENT))
    assert len(paths) > 40  # rank, tie, counts, rva, lines, revision, versions: every one must refuse a float
    for path in paths:
        for bad in (1.0, 1.5):
            assert rejection(contracts.PilotAssessment, _replace(ASSESSMENT, path, bad)) is not None, path
    for bad in (True, '1', None):  # booleans and strings never stand in for integers either
        assert rejection(contracts.PilotAssessment, _replace(ASSESSMENT, '/leads/0/rank', bad)) is not None


# --- records: strict, frozen, exact examples -----------------------------------------------------------------------

def test_index_lists_every_example_file():
    on_disk = {p.name for p in EXAMPLES.iterdir()} - {'index.json'}
    assert on_disk == set(NAMES)
    assert {INDEX[n]['valid'] for n in NAMES} == {True, False}
    assert len(INVALID) >= 30


@pytest.mark.parametrize('name', VALID, ids=[f'v{i}' for i in range(len(VALID))])
def test_valid_examples_round_trip(name):
    text = (EXAMPLES / name).read_text(encoding='utf-8')  # universal newlines: CRLF checkouts parse the same
    record = model_of(name).model_validate_json(text)
    assert record.model_dump(mode='json') == json.loads(text)
    assert model_of(name).model_validate_json(record.model_dump_json()) == record


@pytest.mark.parametrize('name', INVALID, ids=[f'i{i}' for i in range(len(INVALID))])
def test_invalid_examples_rejected_for_their_reason(name):
    message = rejection(model_of(name), doc(name))
    assert message is not None, f'{name} must be rejected'
    assert INDEX[name]['expect'] in message


def test_records_are_strict_and_frozen():
    obs = contracts.Observation.model_validate_json(json.dumps(OBS))
    with pytest.raises(ValidationError):
        contracts.Observation.model_validate({**obs.model_dump(), 'origins': ['D_ghidra']})  # list is not a tuple
    with pytest.raises(ValidationError):
        obs.__setattr__('role', 'context')
    assert_rejected(contracts.Observation, {**OBS, 'surprise': 1}, 'Extra inputs')
    assert_rejected(contracts.Lead, lead(LEAD_FIT, rank='1'), 'rank')
    assert_rejected(contracts.Lead, lead(LEAD_FIT, local_hits=True), 'local_hits')
    assert_rejected(contracts.ReviewEvent, {**doc('valid-ReviewEvent-pin.json'), 'surprise': 1}, 'Extra inputs')


# --- Observation ------------------------------------------------------------------------------------------------

OBS_CASES = {
    'die-shape': (dict(kind='die:toolchain-changed', channel='build', role='shape'), 'context only'),
    'die-local': (dict(kind='die:packed', channel='build', role='local'), 'context only'),
    'str-shape': (dict(kind='str:added', channel='strings', role='shape'), 'context only'),
    'chan-kind': (dict(kind='b1:BND', channel='calls'), 'belongs to channel'),
    'chan-adv': (dict(kind='adv:cwe-stated', channel='code'), 'belongs to channel'),
    'bad-kind': (dict(kind='BND'), 'kind'),
    'kind-case': (dict(kind='B1:bnd'), 'kind'),
    'no-origin': (dict(origins=[]), 'origins'),
    'dup-origin': (dict(origins=['D_ghidra', 'D_ghidra']), 'sorted and unique'),
    'unsorted': (dict(origins=['D_ghidra', 'D_bytes']), 'sorted and unique'),
    'bad-origin': (dict(origins=['ghidra']), 'origins'),
    'bad-class': (dict(evidence_class='BODY'), 'evidence_class'),
    'bad-role': (dict(role='support'), 'role'),
    'bad-verif': (dict(verification='verified'), 'verification'),
    'no-detail': (dict(detail=''), 'detail'),
    'long': (dict(detail='x' * 301), 'detail'),
    'newline': (dict(detail='two\nlines'), 'plain text'),
    'bidi': (dict(detail='fix‮evil'), 'plain text'),
    'nul': (dict(detail='nul\x00'), 'plain text'),
    'nav-order': (dict(nav={'side': 'newer', 'rva': 4096, 'start_line': 9, 'end_line': 3}), 'end_line'),
    'nav-end-only': (dict(nav={'side': 'newer', 'rva': 4096, 'start_line': None, 'end_line': 3}), 'start_line'),
    'nav-rva': (dict(nav={'side': 'newer', 'rva': -1, 'start_line': None, 'end_line': None}), 'rva'),
    'nav-side': (dict(nav={'side': 'both', 'rva': 1, 'start_line': None, 'end_line': None}), 'side'),
    'anchor': (dict(anchor_ids=['no space allowed:x y']), 'anchor_ids'),
    'anchor-order': (dict(anchor_ids=['fn:b', 'fn:a']), 'sorted and unique'),
    'obligation': (dict(obligations=['Bad Slug']), 'obligations'),
    'ref-ptr': (dict(ref={'kind': 'csaf-fact', 'id': 'x', 'pointer': 'no-slash', 'sha256': None}), 'pointer'),
    'ref-sha': (dict(ref={'kind': 'csaf-fact', 'id': 'x', 'pointer': None, 'sha256': 'abc'}), 'sha256'),
    'ref-id': (dict(ref={'kind': 'csaf-fact', 'id': 'bad\nid', 'pointer': None, 'sha256': None}), 'id'),
}


@pytest.mark.parametrize('name', sorted(OBS_CASES), ids=[f'o{i}' for i in range(len(OBS_CASES))])
def test_observation_invariants(name):
    over, text = OBS_CASES[name]
    assert_rejected(contracts.Observation, {**OBS, **over}, text)


def test_observation_with_optional_parts_omitted_is_valid():
    minimal = {k: v for k, v in OBS.items() if k not in ('nav', 'obligations', 'anchor_ids')}
    record = contracts.Observation.model_validate_json(json.dumps(minimal))
    assert record.nav is None and record.obligations == () and record.anchor_ids == ()


# --- Lead -------------------------------------------------------------------------------------------------------

def _tie(first: int, last: int) -> dict:
    return {'size': last - first + 1, 'first': first, 'last': last}


LEAD_CASES = {
    'fit-tentative': (LEAD_FIT, dict(mechanism='tentative'), 'requires mechanism'),
    'fit-contested': (LEAD_FIT, dict(mechanism='contested'), 'requires mechanism'),
    'review-moderate': (LEAD_REVIEW, dict(mechanism='moderate'), 'requires mechanism'),
    'queue-moderate': (LEAD_QUEUE, dict(mechanism='moderate'), 'requires mechanism'),
    'code-unexplained': (LEAD_CODE, dict(mechanism='unexplained'), 'requires mechanism'),
    'partial-moderate': (LEAD_FIT, dict(lead_class='partial'), 'requires mechanism'),
    'strong': (LEAD_FIT, dict(mechanism='strong'), 'reserved'),
    'bad-class': (LEAD_FIT, dict(lead_class='maybe'), 'lead_class'),
    'cve-no-gate': (LEAD_FIT, dict(gate='none'), 'no CVE'),
    'gate-no-cve': (LEAD_FIT, dict(cve=None), 'no CVE'),
    'gate-na': (LEAD_FIT, dict(gate='not-applicable'), 'gate'),
    'code-with-cve': (LEAD_CODE, dict(cve='CVE-2099-20001', gate='applies'), 'code-only'),
    'fit-no-cve': (LEAD_CODE, dict(lead_class='fit', mechanism='moderate'), 'advisory'),
    'unverified-fit': (LEAD_FIT, dict(gate='unverified'), 'unverified'),
    'unverified-review': (LEAD_REVIEW, dict(gate='unverified'), 'unverified'),
    'conflict-fit': (LEAD_FIT, dict(gate='conflict'), 'conflicting'),
    'contested-fit': (LEAD_FIT, dict(identity='contested'), 'contested pairing'),
    'one-component': (LEAD_FIT, dict(components={'count': 1, 'tags': ['D_ghidra']}), 'independent components'),
    'count-tags': (LEAD_FIT, dict(components={'count': 3, 'tags': ['D_ghidra', 'D_vendor_text']}), 'number of tags'),
    'tags-unsorted': (LEAD_FIT, dict(components={'count': 2, 'tags': ['D_vendor_text', 'D_ghidra']}),
                      'sorted and unique'),
    'depth-none': (LEAD_FIT, dict(depth='none'), 'depth'),
    'tie-size': (LEAD_FIT, dict(tie={'size': 3, 'first': 1, 'last': 1}), 'tie'),
    'tie-range': (LEAD_FIT, dict(tie={'size': 1, 'first': 2, 'last': 2}), 'tie group'),
    'rank-zero': (LEAD_FIT, dict(rank=0, tie=_tie(0, 0)), 'rank'),
    'rank-outside': (LEAD_FIT, dict(rank=5), 'tie group'),
    'cap-fit': (LEAD_FIT, dict(caps=['toolchain-changed-lexical-only']), 'capped lead'),
    'cap-window-review': (LEAD_REVIEW, dict(caps=['confounded-window-needs-locality']), 'capped lead'),
    'cap-gate': (LEAD_FIT, dict(caps=['cve-conflict']), 'needs gate'),
    'cap-unsorted': (LEAD_QUEUE, dict(caps=['toolchain-changed-lexical-only', 'confounded-window-needs-locality']),
                     'sorted and unique'),
    'cap-unknown': (LEAD_QUEUE, dict(caps=['whatever']), 'caps'),
    'dup-ids': (LEAD_FIT, dict(support_ids=[X, X]), 'sorted and unique'),
    'unsorted-ids': (LEAD_FIT, dict(counter_ids=['f' * 64, 'e' * 64]), 'sorted and unique'),
    'obs-budget': (LEAD_FIT, dict(alternative_ids=[f'{i:064x}' for i in range(257)]), '256'),
    'no-fits': (LEAD_FIT, dict(fits=[]), 'every required change'),
    'assess-unknown': (LEAD_FIT, dict(assessment='unknown'), 'rule hypothesis'),
    'not-assessed-hyp': (LEAD_CODE, dict(assessment='rule-hypothesis'), 'unknown'),
    'dup-fit': (LEAD_FIT, dict(fits=[LEAD_FIT['fits'][0], LEAD_FIT['fits'][0]]), 'unique'),
    'older-order': (LEAD_FIT, dict(older=[{'rva': 9, 'name': 'b'}, {'rva': 3, 'name': 'a'}]), 'sorted and unique'),
    'name-bidi': (LEAD_FIT, dict(older=[{'rva': 9, 'name': 'evil‮'}]), 'plain text'),
    'extra': (LEAD_FIT, dict(surprise=1), 'Extra inputs'),
}


@pytest.mark.parametrize('name', sorted(LEAD_CASES), ids=[f'l{i}' for i in range(len(LEAD_CASES))])
def test_lead_invariants(name):
    base, over, text = LEAD_CASES[name]
    assert_rejected(contracts.Lead, lead(base, **over), text)


ALLOWED_LEADS = [
    (LEAD_FIT, {}), (LEAD_REVIEW, {}), (LEAD_QUEUE, {}), (LEAD_CODE, {}),
    (LEAD_FIT, dict(lead_class='partial', mechanism='tentative')),
    (LEAD_FIT, dict(lead_class='partial', mechanism='tentative', gate='unverified', caps=['cve-unverified'])),
    (LEAD_REVIEW, dict(gate='conflict', caps=['cve-conflict'])),
    (LEAD_FIT, dict(gate='asserted')),
    (LEAD_FIT, dict(lead_class='partial', mechanism='tentative', caps=['confounded-window-needs-locality'])),
    (LEAD_QUEUE, dict(gate='unverified')),
]


@pytest.mark.parametrize('base, over', ALLOWED_LEADS, ids=[f'ok{i}' for i in range(len(ALLOWED_LEADS))])
def test_every_class_and_gate_combination_the_plan_allows_is_valid(base, over):
    assert rejection(contracts.Lead, lead(base, **over)) is None


def test_class_mechanism_table_follows_the_plan():
    assert contracts.CLASS_MECHANISMS == {'fit': ('moderate',), 'review': ('contested',), 'partial': ('tentative',),
                                          'code': ('not-assessed',), 'queue': ('unexplained', 'not-assessed')}
    assert contracts.LEAD_CLASSES == ('fit', 'review', 'partial', 'code', 'queue')


def test_the_budget_of_256_observations_counts_distinct_ids():
    ids = [f'{i:064x}' for i in range(128)]
    same_twice = lead(LEAD_QUEUE, support_ids=ids, counter_ids=ids)  # 128 distinct ids listed in two roles
    assert rejection(contracts.Lead, same_twice) is None
    exactly = lead(LEAD_QUEUE, support_ids=ids, counter_ids=[f'{i:064x}' for i in range(128, 256)])
    assert rejection(contracts.Lead, exactly) is None
    too_many = lead(LEAD_QUEUE, support_ids=ids, counter_ids=[f'{i:064x}' for i in range(128, 257)])
    assert_rejected(contracts.Lead, too_many, '256')


# --- ExpectedChange / HypothesisFit ---------------------------------------------------------------------------------

FIT = LEAD_FIT['fits'][0]
CHANGE = FIT['expected_changes'][0]
FIT_CASES = {
    'met-no-obs': (contracts.ExpectedChange, {**CHANGE, 'state': 'met', 'observation_ids': []}, 'needs observations'),
    'contra-no-obs': (contracts.ExpectedChange, {**CHANGE, 'state': 'contradicted', 'observation_ids': []},
                      'needs observations'),
    'state': (contracts.ExpectedChange, {**CHANGE, 'state': 'maybe'}, 'state'),
    'required-str': (contracts.ExpectedChange, {**CHANGE, 'required': 'yes'}, 'required'),
    'teach': (contracts.ExpectedChange, {**CHANGE, 'teach_id': 'Pilot.Change'}, 'teach_id'),
    'obs-order': (contracts.ExpectedChange, {**CHANGE, 'observation_ids': [X, 'e' * 64]}, 'sorted and unique'),
    'met-count': (contracts.HypothesisFit, {**FIT, 'met': 3}, 'met'),
    'total-count': (contracts.HypothesisFit, {**FIT, 'total': 9}, 'total'),
    'dup-change': (contracts.HypothesisFit, {**FIT, 'expected_changes': [CHANGE, CHANGE], 'met': 2, 'total': 2},
                   'unique'),
    'too-many': (contracts.HypothesisFit, {**FIT, 'expected_changes': [
        {**CHANGE, 'id': f'change-{i}', 'state': 'unknown', 'observation_ids': []} for i in range(17)],
        'met': 0, 'total': 17}, '16'),
    'rule-id': (contracts.HypothesisFit, {**FIT, 'rule_id': 'memory-write'}, 'rule_id'),
    'revision': (contracts.HypothesisFit, {**FIT, 'rule_revision': 0}, 'rule_revision'),
    'cwe': (contracts.HypothesisFit, {**FIT, 'cwe_id': 'CWE-0'}, 'cwe_id'),
    'basis': (contracts.HypothesisFit, {**FIT, 'basis': 'guess'}, 'basis'),
}


@pytest.mark.parametrize('name', sorted(FIT_CASES), ids=[f'e{i}' for i in range(len(FIT_CASES))])
def test_expected_change_and_fit_invariants(name):
    model, document, text = FIT_CASES[name]
    assert_rejected(model, document, text)


# --- CveContext -------------------------------------------------------------------------------------------------

CONTEXT_CASES = {
    'gate-none': (dict(gate='none'), 'gate'),
    'na-counts': (dict(gate='not-applicable'), 'produces no leads'),
    'kev-listed': (dict(kev={'state': 'listed', 'date_added': None, 'snapshot_id': X}), 'needs its date'),
    'kev-listed-snap': (dict(kev={'state': 'listed', 'date_added': '2099-02-10', 'snapshot_id': None}),
                        'needs its date'),
    'kev-absent': (dict(kev={'state': 'not-in-snapshot', 'date_added': None, 'snapshot_id': None}),
                   'needs its snapshot'),
    'kev-absent-date': (dict(kev={'state': 'not-in-snapshot', 'date_added': '2099-02-10', 'snapshot_id': X}),
                        'no date'),
    'kev-unknown-date': (dict(kev={'state': 'unknown', 'date_added': '2099-02-10', 'snapshot_id': None}), 'no date'),
    'kev-bad-date': (dict(kev={'state': 'listed', 'date_added': '2099-13-40', 'snapshot_id': X}), 'date_added'),
    'kev-state': (dict(kev={'state': 'exploited', 'date_added': None, 'snapshot_id': None}), 'state'),
    'window-one': (dict(confounding={'state': 'yes', 'cves': ['CVE-2099-20001']}), 'at least two'),
    'window-unknown': (dict(confounding={'state': 'unknown', 'cves': ['CVE-2099-20001']}), 'no CVEs'),
    'window-order': (dict(confounding={'state': 'yes', 'cves': ['CVE-2099-20002', 'CVE-2099-20001']}),
                     'sorted and unique'),
    'cwe-order': (dict(cwe={'status': 'explicit', 'ids': ['CWE-787', 'CWE-125']}), 'sorted and unique'),
    'cwe-status': (dict(cwe={'status': 'sure', 'ids': []}), 'status'),
    'cve': (dict(cve='CVE-99-1'), 'cve'),
    'sources': (dict(source_ids=[X, 'e' * 64]), 'sorted and unique'),
    'counts-neg': (dict(counts={'fit': -1, 'review': 0, 'partial': 0, 'code': 0, 'queue': 0}), 'fit'),
    'resolution': (dict(applicability={**CONTEXT['applicability'], 'older': 'vulnerable'}), 'older'),
    'limits-long': (dict(limitations=['x' * 301]), 'limitations'),
}


@pytest.mark.parametrize('name', sorted(CONTEXT_CASES), ids=[f'c{i}' for i in range(len(CONTEXT_CASES))])
def test_cve_context_invariants(name):
    over, text = CONTEXT_CASES[name]
    assert_rejected(contracts.CveContext, {**CONTEXT, **over}, text)


def test_a_not_applicable_context_with_zero_counts_is_valid():
    record = doc('valid-CveContext-not-applicable.json')
    assert record['gate'] == 'not-applicable' and set(record['counts'].values()) == {0}
    assert rejection(contracts.CveContext, record) is None


# --- PilotAssessment --------------------------------------------------------------------------------------------

def _mutate(path_value_pairs) -> dict:
    out = json.loads(json.dumps(ASSESSMENT))
    for path, value in path_value_pairs:
        out = _replace(out, path, value) if not callable(value) else value(out)
    return out


def _reorder_classes(document):
    document['leads'] = [document['leads'][0], {**document['leads'][2], 'rank': 2, 'tie': _tie(2, 2)},
                         {**document['leads'][1], 'rank': 3, 'tie': _tie(3, 3)}]
    return document


def _many_leads(document, count: int, cls: str, *, start: int = 0):
    """Replace the leads of the first context by `count` copies of the fit (or queue) lead, ranked from 1."""
    base = document['leads'][0] if cls != 'queue' else document['leads'][2]
    document['cves'][0]['counts'] = {'fit': 0, 'review': 0, 'partial': 0, 'code': 0, 'queue': 0}
    document['cves'][0]['counts'][cls] = count
    document['leads'] = [{**base, 'candidate_key': f'{start + i:064x}', 'rank': i + 1, 'tie': _tie(i + 1, i + 1)}
                         for i in range(count)]
    return document


def _swap_leads(document):
    document['leads'][0], document['leads'][1] = document['leads'][1], document['leads'][0]
    return document


ASSESSMENT_CASES = {
    'dangling-support': ([('/leads/0/support_ids', [X])], 'unknown observation'),
    'dangling-change': ([('/leads/0/fits/0/expected_changes/0/observation_ids', [X])], 'unknown observation'),
    'unknown-cve': ([('/leads/0/cve', 'CVE-2099-99999')], 'unknown CVE context'),
    'gate-mismatch': ([('/leads/0/gate', 'asserted')], 'gate must equal'),
    'unsorted-leads': ([('', _swap_leads)], 'sorted by'),
    'dup-rank': ([('/leads/1/rank', 1), ('/leads/1/tie', _tie(1, 1))], 'ranks must be unique'),
    'class-order': ([('', _reorder_classes)], 'class order'),
    'counts-low': ([('/cves/0/counts/fit', 0)], 'exceed'),
    'na-with-leads': ([('/cves/0/gate', 'not-applicable'),
                       ('/cves/0/counts', {'fit': 0, 'review': 0, 'partial': 0, 'code': 0, 'queue': 0})], 'no leads'),
    'dup-candidate': ([('/leads/1/candidate_key', ASSESSMENT['leads'][0]['candidate_key'])], 'one lead per'),
    'abstained-leads': ([('/status', 'abstained')], 'abstained'),
    'partial-no-limits': ([('/status', 'partial'), ('/limitations', [])], 'limitations'),
    'orientation': ([('/orientation', 'newer->older')], 'orientation'),
    'inputs-older': ([('/inputs/older_sha256', X)], 'inputs'),
    'inputs-newer': ([('/inputs/newer_sha256', X)], 'inputs'),
    'chan-dup': ([('/channels/1', ASSESSMENT['channels'][0])], 'channels'),
    'chan-order': ([('', lambda d: {**d, 'channels': list(reversed(d['channels']))})], 'channels'),
    'chan-state': ([('/channels/0/state', 'ok')], 'state'),
    'contract': ([('/contract', 'pilot/2')], 'contract'),
    'pool-order': ([('', lambda d: {**d, 'observations': list(reversed(d['observations']))})], 'sorted by obs_id'),
    'pool-dup': ([('', lambda d: {**d, 'observations': sorted([*d['observations'], d['observations'][0]],
                                                              key=lambda o: o['obs_id'])})], 'sorted by obs_id'),
    'ctx-dup': ([('', lambda d: {**d, 'cves': [d['cves'][0], d['cves'][0]]})], 'sorted by CVE'),
    'queue-neg': ([('/queue_count', -1)], 'queue_count'),
    'limits-hit': ([('/limits_hit', ['Not A Slug'])], 'limits_hit'),
    'project': ([('/project_id', '../escape')], 'project_id'),
    'created': ([('/created_utc', 'yesterday')], 'created_utc'),
    'extra': ([('/surprise', 1)], 'Extra inputs'),
    'p04-leads': ([('', lambda d: _many_leads(d, 501, 'fit'))], 'at most 500'),
    'p04-queue': ([('', lambda d: _many_leads(d, 201, 'queue'))], 'at most 200'),
}


@pytest.mark.parametrize('name', sorted(ASSESSMENT_CASES), ids=[f'a{i}' for i in range(len(ASSESSMENT_CASES))])
def test_assessment_invariants(name):
    changes, text = ASSESSMENT_CASES[name]
    assert_rejected(contracts.PilotAssessment, _mutate(changes), text)


def test_the_limit_of_500_leads_and_200_queue_rows_per_context_is_accepted():
    ok = _many_leads(json.loads(json.dumps(ASSESSMENT)), 500, 'fit')
    ok['cves'][0]['counts']['queue'] = 200
    ok['leads'] += [{**LEAD_QUEUE, 'candidate_key': f'{1000 + i:064x}', 'rank': 501 + i, 'tie': _tie(501 + i, 501 + i)}
                    for i in range(200)]
    assert rejection(contracts.PilotAssessment, ok) is None


def test_lead_counts_count_persisted_leads_per_class_over_all_contexts():
    record = contracts.PilotAssessment.model_validate_json(json.dumps(ASSESSMENT))
    counts = record.lead_counts()
    assert counts.model_dump() == {'fit': 1, 'review': 1, 'partial': 0, 'code': 0, 'queue': 1}
    assert contracts.PilotAssessment.lead_counts is not None


def test_abstained_assessment_example_is_complete_and_leadless():
    record = contracts.PilotAssessment.model_validate_json((EXAMPLES / 'valid-PilotAssessment-abstained.json')
                                                           .read_text(encoding='utf-8'))
    assert record.status == 'abstained' and record.leads == () and record.limitations
    keys.verify_assessment(record)


# --- ReviewEvent ------------------------------------------------------------------------------------------------

PIN = doc('valid-ReviewEvent-pin.json')
REVIEW_CASES = {
    'note-empty': (dict(action='note', text=''), 'needs text'),
    'action': (dict(action='verify'), 'action'),
    'long-chars': (dict(action='note', text='x' * 2049), 'text'),
    'long-bytes': (dict(action='note', text='é' * 1100), 'at most 2048 bytes'),
    'control': (dict(action='note', text='bad\x00text'), 'plain text'),
    'cr': (dict(action='note', text='windows\r\nline'), 'plain text'),
    'bidi': (dict(action='note', text='fix‮evil'), 'plain text'),
    'cve': (dict(cve='CVE-1-1'), 'cve'),
    'key': (dict(candidate_key='abc'), 'candidate_key'),
    'time': (dict(created_utc='2026-10-14 12:00'), 'created_utc'),
    'contract': (dict(contract='pilot-review/2'), 'contract'),
}


@pytest.mark.parametrize('name', sorted(REVIEW_CASES), ids=[f'r{i}' for i in range(len(REVIEW_CASES))])
def test_review_event_invariants(name):
    over, text = REVIEW_CASES[name]
    assert_rejected(contracts.ReviewEvent, {**PIN, **over}, text)


def test_review_notes_may_span_lines_and_use_tabs_and_pins_need_no_text():
    note = {**PIN, 'action': 'note', 'text': 'checked the new bound\n\tmatches the advisory title'}
    assert rejection(contracts.ReviewEvent, note) is None
    assert rejection(contracts.ReviewEvent, {**PIN, 'action': 'dismiss', 'text': 'compiler churn'}) is None
    assert rejection(contracts.ReviewEvent, {**PIN, 'cve': None}) is None
    assert rejection(contracts.ReviewEvent, {**PIN, 'action': 'note', 'text': 'x' * 2048}) is None


# --- pointer and manifest -----------------------------------------------------------------------------------------

POINTER = doc('valid-PilotResultPointer.json')
MANIFEST = doc('valid-PilotManifest.json')
POINTER_CASES = {
    'dir-mismatch': (dict(relative_dir='intelligence/pilot/0000000000000000'), 'result_id[:16]'),
    'dir-prefix': (dict(relative_dir=f'runs/x/{POINTER["result_id"][:16]}'), 'relative_dir'),
    'dir-escape': (dict(relative_dir='../../intelligence/pilot/' + POINTER['result_id'][:16]), 'relative_dir'),
    'status': (dict(status='done'), 'status'),
    'counts': (dict(counts={'fit': 1}), 'counts'),
    'digest': (dict(manifest_sha256='abc'), 'manifest_sha256'),
}


@pytest.mark.parametrize('name', sorted(POINTER_CASES), ids=[f'p{i}' for i in range(len(POINTER_CASES))])
def test_pointer_invariants(name):
    over, text = POINTER_CASES[name]
    assert_rejected(contracts.PilotResultPointer, {**POINTER, **over}, text)


PART = MANIFEST['parts'][0]
MANIFEST_CASES = {
    'no-parts': (dict(parts=[]), 'assessment.json.gz'),
    'part-name': (dict(parts=[{**PART, 'name': 'rows.jsonl.gz'}]), 'name'),
    'dup-parts': (dict(parts=[PART, PART]), 'sorted and unique'),
    'part-big': (dict(parts=[{**PART, 'bytes': DEFAULT_LIMITS.p06_sidecar_bytes + 1}]), 'exceed'),
    'part-sha': (dict(parts=[{**PART, 'sha256': 'abc'}]), 'sha256'),
    'partial-no-limits': (dict(status='partial', limitations=[]), 'limitations'),
    'abstained-no-limits': (dict(status='abstained', limitations=[]), 'limitations'),
    'config-field': (dict(config={**MANIFEST['config'], 'locality_min_tokens': 0}), 'locality_min_tokens'),
    'config-window': (dict(config={**MANIFEST['config'], 'confounded_min_cves': 1}), 'confounded_min_cves'),
    'config-float': (dict(config={**MANIFEST['config'], 'locality_min_tokens': 2.0}), 'locality_min_tokens'),
    'inputs-orient': (dict(inputs={**MANIFEST['inputs'], 'orientation': 'newer->older'}), 'orientation'),
    'result': (dict(result_id='abc'), 'result_id'),
}


@pytest.mark.parametrize('name', sorted(MANIFEST_CASES), ids=[f'k{i}' for i in range(len(MANIFEST_CASES))])
def test_manifest_invariants(name):
    over, text = MANIFEST_CASES[name]
    assert_rejected(contracts.PilotManifest, {**MANIFEST, **over}, text)


# --- non-persisted views and plain text ----------------------------------------------------------------------------

def test_views_are_strict_and_not_part_of_the_schema_set():
    key = 'a' * 64
    view = contracts.Candidate(candidate_key=key, older=(contracts.FunctionRef(rva=16, name='f'),), newer=(),
                               identity='unassessed')
    assert view.identity == 'unassessed'
    with pytest.raises(ValidationError):
        contracts.Candidate(candidate_key=key, older=(), newer=(), identity='maybe')
    anchor = contracts.PilotAnchor(anchor_id=f'fn:{key}', kind='function', label='Ipv6pReassembleFragment',
                                   facets=(('class', 'fit'),))
    assert anchor.kind == 'function'
    with pytest.raises(ValidationError):
        contracts.PilotAnchor(anchor_id='no colon', kind='function', label='x')
    persisted = {m.__name__ for m, _ in contracts.SCHEMA_MODELS}
    assert 'Candidate' not in persisted and 'PilotAnchor' not in persisted


@pytest.mark.parametrize('text', ['a\nb', 'a\tb', 'a\r', 'a\x00b', 'a\x1bb', 'a\x7fb', 'a\x85b', 'a‎b',
                                  'a‏b', 'a b', 'a b', 'a‪b', 'a‮b', 'a⁦b',
                                  'a⁩b', 'a\ud800b'], ids=[f't{i}' for i in range(16)])
def test_plain_line_rejects_controls_bidi_separators_and_surrogates(text):
    with pytest.raises(ValueError):
        contracts.plain_line(text)


def test_plain_text_allows_tab_and_newline_only():
    assert contracts.plain_text('a\tb\nc') == 'a\tb\nc'
    for text in ('a\rb', 'a\x00b', 'a‮b', 'a\ud800b'):
        with pytest.raises(ValueError):
            contracts.plain_text(text)
    assert contracts.plain_line('markup <b>stays</b> text, 100% plain') == 'markup <b>stays</b> text, 100% plain'


def test_clean_line_always_yields_what_plain_line_accepts():
    """The adapter-side helper: whatever untrusted text goes in, the stored value passes the contract."""
    for code in [*range(0x3000), 0xFEFF, 0x1F600, 0x10FFFF]:  # includes controls, bidi marks and lone surrogates
        cleaned = contracts.clean_line(f'a{chr(code)}b')
        assert contracts.plain_line(cleaned) == cleaned
    assert contracts.clean_line('line\none\ttwo') == 'line one two'
    assert contracts.clean_line(None) == '' and contracts.clean_line(12345) == '12345'
    assert contracts.clean_line('x' * 300) == 'x' * 300
    capped = contracts.clean_line('x' * 1000)
    assert len(capped) == 300 and capped.endswith('...')
    assert len(contracts.clean_line('y' * 50, 10)) == 10
    for text in ('plain', 'bidi ‮ text', 'ctl \x00\x1b[31m', 'sep   x', 'x' * 400):  # same as the shared one
        assert contracts.clean_line(text) == sanitize_text(text, 300)


def test_plain_line_rejects_everything_sanitize_text_removes():
    """`detail` and names must already be what `sanitize_text` returns (A2/A3 sanitise at adapter time)."""
    for code in range(0x3000):
        if 0xD800 <= code <= 0xDFFF:
            continue
        char = chr(code)
        if sanitize_text(f'a{char}b') != f'a{char}b':
            with pytest.raises(ValueError):
                contracts.plain_line(f'a{char}b')
    for text in ('plain', 'Ipv6pReassembleFragment', 'names share two tokens', 'x' * 300):
        assert sanitize_text(text, 300) == text
        assert contracts.plain_line(text) == text


# --- vocabulary parity with K (no import of another feature at runtime) ------------------------------------------

def _accepts(annotation, value) -> bool:
    try:
        TypeAdapter(annotation).validate_python(value, strict=True)
    except ValidationError:
        return False
    return True


def test_shared_identifier_shapes_match_the_intelligence_contract():
    cves = ['CVE-2099-10001', 'CVE-99-1', 'cve-2099-10001', 'CVE-2099-1', 'CVE-2099-' + '1' * 19, 'CVE-2099-' + '1' * 20,
            'CVE-2099-10001 ', 'CVE-2099-10001\n', '']
    cwes = ['CWE-787', 'CWE-0', 'CWE-1', 'CWE-999999', 'CWE-1000000', 'CWE-', 'cwe-787', 'CWE-787\n']
    pointers = ['', '/a/b', '/a~0b~1c', '/a~2', 'a/b', '/' * 4097, '/a\n']
    for annotation, expected, samples in ((contracts.CveId, intel.CveId, cves), (contracts.CweId, intel.CweId, cwes),
                                          (contracts.Pointer, intel.Pointer, pointers)):
        for value in samples:
            assert _accepts(annotation, value) == _accepts(expected, value), (annotation, value)


def test_literals_shared_with_the_intelligence_contract_are_identical():
    assert get_args(contracts.Resolution) == get_args(intel.Resolution)
    assert get_args(contracts.MappingStatus) == get_args(intel.MappingStatus)
    assert get_args(contracts.Basis) == get_args(intel.CweBasis)
    assert get_args(contracts.CweStatus) == get_args(intel.CweProfile.model_fields['status'].annotation)
    assert get_args(contracts.Side) == get_args(intel.Side)


# --- schemas, examples and regeneration -----------------------------------------------------------------------------

def test_committed_files_equal_a_fresh_regeneration():
    """Regenerate-and-compare (CI drift gate): every file under docs/schemas/pilot is exactly what the generator
    renders now, and nothing else lives there."""
    rendered = generator().render()
    on_disk = {p for p in SCHEMAS.rglob('*') if p.is_file()}
    assert on_disk == set(rendered), sorted(str(p.relative_to(ROOT)) for p in on_disk ^ set(rendered))
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'
    assert len(rendered) == len(contracts.SCHEMA_MODELS) + len(NAMES) + 1  # schemas + examples + index.json


def test_one_schema_per_persisted_model_with_a_stable_id():
    expected = {f'{model.__name__}.json': ident for model, ident in contracts.SCHEMA_MODELS}
    assert {p.name for p in SCHEMAS.glob('*.json')} == set(expected)
    for name, ident in expected.items():
        schema = json.loads((SCHEMAS / name).read_text(encoding='utf-8'))
        assert schema['$id'] == f'https://patchtrace.local/schemas/{ident}/{name}'
        assert schema['$schema'] == 'https://json-schema.org/draft/2020-12/schema'
    assert {m.__name__ for m, _ in contracts.SCHEMA_MODELS} == {
        'PilotAssessment', 'Lead', 'Observation', 'CveContext', 'ReviewEvent', 'PilotResultPointer', 'PilotManifest'}


def test_generator_check_mode_reports_drift(tmp_path, monkeypatch):
    gen = generator()
    assert gen.main(['--check']) == 0
    stale = tmp_path / 'docs' / 'schemas' / 'pilot'
    stale.mkdir(parents=True)
    monkeypatch.setattr(gen, 'OUT', stale)
    monkeypatch.setattr(gen, 'EXAMPLES', stale / 'examples')
    assert gen.main(['--check']) == 1  # empty directory: everything is stale


def test_generator_output_does_not_depend_on_the_hash_seed():
    for seed in ('1', '2'):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, str(ROOT / 'tools' / 'generate_pilot_schemas.py'), '--check'],
                                capture_output=True, text=True, env=env, cwd=ROOT)
        assert result.returncode == 0, result.stderr


def test_gitattributes_pins_pilot_schemas_to_lf():
    lines = (ROOT / '.gitattributes').read_text(encoding='utf-8').splitlines()
    assert 'docs/schemas/pilot/** text eol=lf' in lines
    raw = b''.join(p.read_bytes() for p in SCHEMAS.rglob('*') if p.is_file())
    assert b'\r' not in raw  # generated with LF on every OS


# --- additive-only: patch-intent rows and old readers -----------------------------------------------------------------

@pytest.fixture
def case(tmp_path):
    svc = create_sample(tmp_path / 'p')
    yield svc
    if not svc.store.closed:
        svc.close()


def _ids(svc, kinds=None):
    rows = svc.store.connection.execute('SELECT id, kind FROM enrichment_entries').fetchall()
    return {i for i, k in rows if kinds is None or k in kinds}


def _guard(svc, digest='b' * 64):
    run = svc.project.runs[-1]
    return Guard(svc.project.id, run.id, run.raw_sha256, digest)


REVIEW_UUID = '0a1b2c3d-0000-4000-8000-000000000001'


def _publish_pilot_rows(svc):
    """A pointer row (`pilot-ptr/1`) and a review event row of the reserved `patch-intent` kind."""
    enrichment = EnrichmentStore(svc.store)
    pointer = doc('valid-PilotResultPointer.json')
    event = doc('valid-ReviewEvent-pin.json')
    g = _guard(svc, pointer['result_id'])
    first = enrichment.publish(keys.KIND, g, g, 1, 'complete', pointer, keys.pointer_entry_id(pointer['result_id']))
    second = enrichment.publish(keys.KIND, g, g, 1, 'complete', event, keys.review_entry_id(REVIEW_UUID))
    return first, second


def test_old_reader_ignores_patch_intent(case, monkeypatch):
    """A pre-PIL reader queries known kinds only; patch-intent rows never reach it and never change its view."""
    enrichment = EnrichmentStore(case.store)
    enrichment.ensure()
    before = (load_secondary(enrichment), current_sets(enrichment))
    pointer_row, event_row = _publish_pilot_rows(case)
    meta = case.store.connection.execute("SELECT value FROM enrichment_meta WHERE key='extension_version'")
    assert meta.fetchone()[0] == '1'  # no extension_version bump: v1 clients keep full access
    assert _ids(case, {keys.KIND}) == {pointer_row.id, event_row.id}
    old_kinds = frozenset(storage.KINDS) - {'patch-intent'}
    monkeypatch.setattr(storage, 'KINDS', old_kinds)  # a pre-SPEC-30 reader
    old = EnrichmentStore(case.store)
    for kind in sorted(old_kinds):
        assert all(e.kind == kind for e in old.entries(kind))
    assert (load_secondary(old), current_sets(old)) == before
    g = _guard(case)
    old.apply_retention(g, started=FUTURE)
    assert _ids(case, {keys.KIND}) == {pointer_row.id, event_row.id}
    case.store.save(case.store.load())  # the v1 project contract still opens and saves with pilot rows present
    body = json.loads(case.store.connection.execute(
        'SELECT body FROM enrichment_entries WHERE id=?', (pointer_row.id,)).fetchone()[0])
    assert body['contract'] == 'pilot-ptr/1'
    assert contracts.PilotResultPointer.model_validate_json(json.dumps(body)).result_id == POINTER['result_id']
    monkeypatch.undo()
    new = EnrichmentStore(case.store)  # a PatchTrace that knows the kind reads both rows back
    assert {e.id for e in new.entries(keys.KIND)} == {pointer_row.id, event_row.id}
    for entry in new.entries(keys.KIND):
        model = contracts.PilotResultPointer if entry.id == pointer_row.id else contracts.ReviewEvent
        assert model.model_validate_json(json.dumps(entry.body)).contract in ('pilot-ptr/1', 'pilot-review/1')


def test_patch_intent_rows_survive_enrichment_retention(case):
    pointer_row, event_row = _publish_pilot_rows(case)
    enrichment = EnrichmentStore(case.store)
    g = _guard(case)
    for n in range(12):
        rid = f'r{n}'
        for kind in ('signals', 'ranking', 'wil'):
            enrichment.publish(kind, g, g, 0, 'complete', {'pad': 'x' * 64}, f'{kind}:{rid}')
        enrichment.publish('pipeline', g, g, 0, 'complete', {'stage_ids': {'ranking': rid, 'wil': rid},
                                                             'config_digest': 'c'}, f'pipeline:{rid}')
    assert enrichment.apply_retention(g, started=FUTURE) > 0
    enrichment.prune_runs(keep=0)
    enrichment.make_room(1, g)
    assert _ids(case, {keys.KIND}) == {pointer_row.id, event_row.id}
    assert 'patch-intent' in storage.KINDS and 'patch-intent' not in storage.DERIVED_KINDS


# --- limits, errors and the cooperative budget -------------------------------------------------------------------------

def test_error_codes_and_exit_codes_follow_the_plan():
    assert ERROR_CODES == tuple(f'PT-PILOT-{n}' for n in (
        'INPUT', 'STALE', 'MISMATCH', 'ORIENTATION', 'UNSUPPORTED', 'RULES', 'LIMIT', 'STORAGE', 'INTEGRITY',
        'NOTFOUND', 'CANCEL'))
    assert set(EXIT_CODES) == set(ERROR_CODES)
    assert {c: EXIT_CODES[f'PT-PILOT-{c}'] for c in ('INPUT', 'MISMATCH', 'ORIENTATION', 'UNSUPPORTED')} == {
        'INPUT': 2, 'MISMATCH': 2, 'ORIENTATION': 2, 'UNSUPPORTED': 2}
    assert EXIT_CODES['PT-PILOT-NOTFOUND'] == 4 and EXIT_CODES['PT-PILOT-CANCEL'] == 5
    assert {EXIT_CODES[f'PT-PILOT-{c}'] for c in ('STALE', 'RULES', 'LIMIT', 'STORAGE', 'INTEGRITY')} == {3}
    err = PilotError('PT-PILOT-CANCEL', 'Cancelled', reason='cancelled')
    assert (err.exit_code, err.reason, err.code) == (5, 'cancelled', 'PT-PILOT-CANCEL')
    assert PilotError('PT-PILOT-INPUT', 'x').exit_code == 2
    assert len(PilotError('PT-PILOT-LIMIT', 'y' * 1000).message) == 400
    with pytest.raises(ValueError):
        PilotError('PT-PILOT-NOPE', 'x')
    with pytest.raises(ValueError):
        PilotError('PT-PILOT-RULES', 'x', reason='Bad Reason')
    assert contracts.PilotError is PilotError  # re-exported like the unified contracts


def test_limits_defaults_follow_the_plan_table():
    lim = DEFAULT_LIMITS
    assert (lim.p01_candidates, lim.p02_observations_per_lead, lim.p03_cves, lim.p04_leads_per_context,
            lim.p04_queue_rows_per_context, lim.p05_text_chars, lim.p05_explanation_lines) == (
        250_000, 256, 64, 500, 200, 300, 64)
    assert (lim.p06_sidecar_bytes, lim.p06_pointer_bytes) == (64 * MIB, 128 * KIB)
    assert (lim.p07_rules, lim.p07_changes_per_rule, lim.p07_leaves_per_change) == (64, 16, 16)
    assert (lim.p08_deadline_s, lim.p08_memory_bytes, lim.p09_displayed_rows) == (120, GIB, 100_000)
    assert (lim.p10_markdown_bytes, lim.p10_markdown_leads_per_cve, lim.p10_json_bytes) == (2 * MIB, 200, 32 * MIB)
    assert lim.p11_review_text_bytes == 2048
    assert TARGETS == {'localize_5000_pairs_x_8_cves_s': 5, 'evidence_base_100k_functions_s': 30,
                       'first_paint_ms': 200, 'filter_100k_rows_ms': 100, 'detail_ms': 50}


BAD_LIMITS = [dict(p03_cves=0), dict(p03_cves=True), dict(p03_cves=1.5), dict(p10_markdown_leads_per_cve=501),
              dict(p06_pointer_bytes=65 * MIB), dict(p04_queue_rows_per_context=100_001)]


@pytest.mark.parametrize('bad', BAD_LIMITS, ids=['zero', 'bool', 'float', 'markdown', 'pointer', 'queue'])
def test_limits_reject_non_positive_non_int_and_unordered_values(bad):
    with pytest.raises(ValueError):
        PilotLimits(**bad)


def _max_length(model, field: str):
    values = [m.max_length for m in model.model_fields[field].metadata if hasattr(m, 'max_length')]
    assert len(values) == 1, (model.__name__, field, values)
    return values[0]


def test_contract_caps_are_read_from_the_limits():
    assert _max_length(contracts.Observation, 'detail') == DEFAULT_LIMITS.p05_text_chars
    assert _max_length(contracts.Lead, 'fits') == DEFAULT_LIMITS.p07_rules
    assert _max_length(contracts.HypothesisFit, 'expected_changes') == DEFAULT_LIMITS.p07_changes_per_rule
    assert _max_length(contracts.PilotAssessment, 'cves') == DEFAULT_LIMITS.p03_cves
    assert _max_length(contracts.PilotAssessment, 'leads') == (DEFAULT_LIMITS.p03_cves + 1) * (
        DEFAULT_LIMITS.p04_leads_per_context + DEFAULT_LIMITS.p04_queue_rows_per_context)
    assert _max_length(contracts.ReviewEvent, 'text') == DEFAULT_LIMITS.p11_review_text_bytes


def test_budget_checks_every_n_units_with_an_injected_clock():
    now = [0.0]
    budget = Budget.after(10, check_every=4, clock=lambda: now[0])
    now[0] = 20.0
    budget.tick(3)  # below the check interval: no clock read yet
    with pytest.raises(BudgetExhausted) as info:
        budget.tick(1)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-LIMIT', 'deadline')
    cancel = threading.Event()
    budget = Budget(None, cancel, check_every=1)
    budget.tick()
    cancel.set()
    assert budget.expired()
    with pytest.raises(BudgetExhausted) as info:
        budget.check()
    assert info.value.code == 'PT-PILOT-CANCEL' and isinstance(info.value, PilotError)


def test_budget_deadline_comparison_tolerates_a_coarse_clock():
    """Windows `time.monotonic()` is coarse: a reading equal to the deadline already counts as expired."""
    budget = Budget(10.0, clock=lambda: 10.0)
    assert budget.expired()
    with pytest.raises(BudgetExhausted):
        budget.check()
    assert not Budget(10.0, clock=lambda: 9.999).expired() and not Budget(None).expired()
    with pytest.raises(ValueError):
        Budget(None, check_every=0)


# --- purity: no Qt, I/O, sqlite or other feature at import time ---------------------------------------------------------

MODULES = ('limits', 'contracts', 'keys', 'origins', 'ports')
# Runtime imports per module (besides the standard library). `ports` imports foreign contracts for annotations only.
RUNTIME_ALLOWED = {
    'limits': set(), 'contracts': {'pydantic', 'patchtrace.pilot.limits'},
    'keys': {'patchtrace.enrichment.identity', 'patchtrace.pilot.contracts', 'patchtrace.pilot.limits'},
    'origins': {'patchtrace.enrichment.identity', 'patchtrace.pilot.contracts', 'patchtrace.pilot.limits'},
    'ports': {'patchtrace.pilot.contracts'}}
TYPING_ALLOWED = {'ports': {'patchtrace.intelligence.contracts'}}
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'datetime', 'hashlib', 'json', 're', 'time',
          'types', 'typing', 'uuid'}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    guarded = set()
    for node in ast.walk(tree):  # imports under `if TYPE_CHECKING:` are annotations only
        if isinstance(node, ast.If) and isinstance(node.test, ast.Name) and node.test.id == 'TYPE_CHECKING':
            guarded |= {id(n) for n in ast.walk(node)}
    runtime, typing_only = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                parent = 'patchtrace' if node.level == 2 else 'patchtrace.pilot'
                base = f'{parent}.{base}' if base else parent
            names = {base}
        else:
            continue
        (typing_only if id(node) in guarded else runtime).update(names)
    return runtime, typing_only


@pytest.mark.parametrize('module', MODULES, ids=MODULES)
def test_pilot_modules_respect_import_rules(module):
    runtime, typing_only = _imports(PACKAGE / f'{module}.py')
    assert runtime - STDLIB <= RUNTIME_ALLOWED[module], runtime
    assert typing_only <= TYPING_ALLOWED.get(module, set()), typing_only


def test_init_is_documentation_only():
    tree = ast.parse((PACKAGE / '__init__.py').read_text(encoding='utf-8'))
    assert all(isinstance(n, ast.Expr) for n in tree.body)  # a docstring and nothing that runs


def test_pilot_package_imports_no_qt_sqlite_network_process_or_other_feature():
    # `socket` is not listed: on Python 3.12 pydantic's plugin discovery (importlib.metadata -> email.utils) imports it
    # when the first model class is defined. The AST test above proves that no pilot module imports it directly.
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.pilot, patchtrace.pilot.limits, patchtrace.pilot.contracts, patchtrace.pilot.keys\n'
            'import patchtrace.pilot.origins, patchtrace.pilot.ports\n'
            'bad = [m for m in ("PySide6", "sqlite3", "subprocess", "ssl", "urllib.request", "http.client",\n'
            '                   "patchtrace.intelligence", "patchtrace.unified", "patchtrace.secondary",\n'
            '                   "patchtrace.enrichment.storage", "patchtrace.persistence") if m in sys.modules]\n'
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
