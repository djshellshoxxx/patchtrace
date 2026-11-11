"""R0 contract freeze: `yara-rules/1` records, schemas and examples, limits, errors and ports
(docs/specs/program-e/YRX-integration-plan.md s7, s9). Synthetic data only; nothing here is live evidence.

Gates of R0: regenerate-and-compare, valid and invalid examples behave as labelled (each invalid one for its own reason),
the card's numbers and codes are pinned, hostile text never passes a text field, the pure modules stay pure.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

import patchtrace.rules as rules_package
from patchtrace.intelligence import contracts as intel
from patchtrace.rules import contracts as c
from patchtrace.rules import errors, ports
from patchtrace.rules.errors import CODES, EXIT_CODES, RuleError
from patchtrace.rules.limits import DEFAULT_LIMITS, GIB, KIB, MIB, RuleLimits, limits_digest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = Path(rules_package.__file__).parent  # the package under test, wherever it is imported from
SCHEMAS = ROOT / 'docs' / 'schemas' / 'rules'


def generator():
    spec = importlib.util.spec_from_file_location('generate_rules_schemas', ROOT / 'tools' / 'generate_rules_schemas.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = generator()
EXAMPLES = json.loads((SCHEMAS / 'examples.json').read_text(encoding='utf-8'))
RECORDS = GEN.valid_records()
VALID = [(name, i) for name in GEN.CONTRACTS for i in range(len(EXAMPLES[name]['valid']))]
INVALID = [(name, i) for name in GEN.CONTRACTS for i in range(len(EXAMPLES[name]['invalid']))]


def model(name: str):
    return getattr(c, name)


def rejection(name: str, document) -> str | None:
    """None when the document validates, else the validation error text (JSON mode, as stored rows are read)."""
    try:
        model(name).model_validate_json(json.dumps(document))
    except ValidationError as exc:
        return str(exc)
    return None


def variant(name: str, index: int = 0, **changes):
    document = json.loads(RECORDS[name][index].model_dump_json()) | changes
    return model(name).model_validate_json(json.dumps(document))


# --- generated artefacts ---------------------------------------------------------------------------------------------

def test_committed_files_equal_a_fresh_regeneration():
    rendered = GEN.render()
    assert len(rendered) == len(GEN.CONTRACTS) + 1
    for path, text in rendered.items():
        assert path.read_text(encoding='utf-8') == text, f'{path.relative_to(ROOT)} is stale; regenerate it'


def test_no_stray_schema_files_and_lf_only():
    assert {p.name for p in SCHEMAS.iterdir()} == {p.name for p in GEN.render()}
    assert all(b'\r' not in p.read_bytes() for p in SCHEMAS.iterdir())


def test_every_record_class_of_the_module_is_covered_by_the_generator():
    classes = {n for n, v in vars(c).items() if isinstance(v, type) and issubclass(v, c.Record)
               and v.__module__ == c.__name__ and n not in {'Record', 'Contract', 'WorkerRecord'}}
    assert classes == set(GEN.CONTRACTS)


def test_examples_cover_every_contract_with_valid_and_invalid_cases():
    assert set(EXAMPLES) == set(GEN.CONTRACTS)
    for name, entry in EXAMPLES.items():
        assert entry['valid'] and len(entry['invalid']) >= 1, name


@pytest.mark.parametrize('name, index', VALID, ids=[f'{n}-{i}' for n, i in VALID])
def test_valid_examples_validate_and_round_trip(name, index):
    document = EXAMPLES[name]['valid'][index]
    record = model(name).model_validate_json(json.dumps(document))
    assert json.loads(record.model_dump_json()) == document
    again = model(name).model_validate_json(record.model_dump_json())
    assert again == record and again.model_dump_json() == record.model_dump_json()


@pytest.mark.parametrize('name, index', INVALID, ids=[f'{n}-{i}' for n, i in INVALID])
def test_invalid_examples_are_rejected_for_their_reason(name, index):
    case = EXAMPLES[name]['invalid'][index]
    error = rejection(name, case['example'])
    assert error is not None, case['reason']
    assert case['match'] in error, (case['reason'], error)


def test_schema_ids_and_contract_constants():
    for path in SCHEMAS.glob('*.json'):
        if path.name == 'examples.json':
            continue
        schema = json.loads(path.read_text(encoding='utf-8'))
        assert schema['$id'] == f'https://patchtrace.local/schemas/rules/1/{path.stem}.json'
        if path.stem in GEN.STANDALONE:
            assert schema['properties']['contract']['const'] == GEN.STANDALONE[path.stem]
        else:
            assert 'contract' not in schema['properties']


@pytest.mark.parametrize('name', GEN.CONTRACTS, ids=GEN.CONTRACTS)
def test_records_are_strict_frozen_and_forbid_extra_fields(name):
    record = RECORDS[name][0]
    assert record.model_config['extra'] == 'forbid' and record.model_config['strict'] is True
    assert record.model_config['frozen'] is True
    with pytest.raises(ValidationError):
        setattr(record, next(iter(type(record).model_fields)), None)


def test_no_contract_has_a_float_field():
    schemas = [json.loads(p.read_text(encoding='utf-8')) for p in SCHEMAS.glob('*.json') if p.name != 'examples.json']

    def walk(node):
        if isinstance(node, dict):
            assert node.get('type') != 'number', 'a contract carries no float'
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)
    for schema in schemas:
        walk(schema)


# --- the card's numbers, codes and shapes ----------------------------------------------------------------------------

def test_default_limits_are_the_numbers_of_the_card():
    d = DEFAULT_LIMITS
    assert (d.rule_text_bytes, d.patterns_per_rule, d.hex_patterns_per_rule, d.text_patterns_per_rule) == \
        (64 * KIB, 12, 4, 8)
    assert (d.hex_pattern_bytes, d.text_pattern_bytes, d.meta_string_chars, d.function_bytes) == (512, 256, 512, 64 * KIB)
    assert (d.candidates_per_direction, d.candidates_per_run, d.versions_per_lineage) == (3, 200, 50)
    assert (d.series_targets, d.extra_targets, d.clean_targets) == (8, 64, 2_000)
    assert (d.file_bytes, d.run_bytes, d.rules_per_run, d.cells) == (128 * MIB, 8 * GIB, 50, 105_000)
    assert (d.target_timeout_s, d.target_timeout_min_s, d.target_timeout_max_s, d.run_wall_s) == (30, 5, 300, 3600)
    assert (d.max_matches_per_pattern, d.offsets_per_cell, d.pins_per_feature) == (64, 8, 4)
    assert (d.worker_memory_bytes, d.worker_memory_max_bytes, d.stderr_tail_bytes) == (1 * GIB, 2 * GIB, 8 * KIB)
    assert (d.window_min_bytes, d.label_chars) == (16, 120)
    assert d.targets_per_run == 2_072 and d.targets_per_run * d.rules_per_run <= d.cells


@pytest.mark.parametrize('change', [{'rule_text_bytes': 0}, {'cells': -1}, {'file_bytes': True}, {'cells': 1.5},
                                    {'target_timeout_s': 3}, {'target_timeout_s': 400}, {'worker_memory_bytes': 3 * GIB},
                                    {'file_bytes': 9 * GIB}, {'patterns_per_rule': 13}, {'candidates_per_run': 5},
                                    {'cells': 100}, {'window_min_bytes': 1024}],
                         ids=['zero', 'negative', 'bool', 'float', 'timeout-low', 'timeout-high', 'memory-over-hard',
                              'file-over-run', 'patterns-over-ceilings', 'candidates-over-run', 'cells-too-few',
                              'window-over-pattern'])
def test_limits_reject_invalid_or_misordered_values(change):
    with pytest.raises(ValueError):
        RuleLimits(**change)


def test_limits_digest_is_stable_domain_separated_and_sensitive():
    assert limits_digest() == limits_digest(RuleLimits()) and re.fullmatch(r'[0-9a-f]{64}', limits_digest())
    assert limits_digest(RuleLimits(target_timeout_s=31)) != limits_digest()
    assert limits_digest() != hashlib.sha256(json.dumps(DEFAULT_LIMITS.as_dict(), sort_keys=True,
                                                        separators=(',', ':')).encode()).hexdigest()
    assert list(DEFAULT_LIMITS.as_dict()) == [f.name for f in dataclasses.fields(RuleLimits)]
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_LIMITS.cells = 1  # type: ignore[misc]


def test_error_codes_are_the_cards_fourteen_and_exit_codes_total():
    assert CODES == ('PT-RULE-INPUT', 'PT-RULE-LIMIT', 'PT-RULE-STALE', 'PT-RULE-INTEGRITY', 'PT-RULE-UNAVAILABLE',
                     'PT-RULE-ENGINE', 'PT-RULE-TIMEOUT', 'PT-RULE-CANCEL', 'PT-RULE-MASK', 'PT-RULE-DECODE',
                     'PT-RULE-COMPILE', 'PT-RULE-GATE', 'PT-RULE-STORAGE', 'PT-RULE-EXPORT')
    assert get_args(errors.ErrorCode) == CODES and set(EXIT_CODES) == set(CODES)
    assert all(re.fullmatch(r'PT-RULE-[A-Z]+', code) for code in CODES)
    assert {EXIT_CODES[x] for x in ('PT-RULE-INPUT', 'PT-RULE-UNAVAILABLE')} == {2}
    assert EXIT_CODES['PT-RULE-CANCEL'] == 5 and set(EXIT_CODES.values()) <= {2, 3, 5}  # 4 is the caller's, not a code's


def test_rule_error_is_typed_bounded_and_rejects_unknown_input():
    error = RuleError('PT-RULE-ENGINE', 'x' * 900, reason='worker-oom', diagnostics='tail')
    assert (error.code, error.reason, error.exit_code, error.diagnostics) == ('PT-RULE-ENGINE', 'worker-oom', 3, 'tail')
    assert len(error.message) == 400 and str(error).startswith('PT-RULE-ENGINE: ') and str(error).endswith('[worker-oom]')
    assert 'tail' not in str(error)
    for bad in ({'code': 'PT-RULE-NOPE'}, {'code': 'PT-RULE-INPUT', 'reason': 'Has Space'},
                {'code': 'PT-RULE-INPUT', 'reason': 'x' * 49}):
        with pytest.raises(ValueError):
            RuleError(bad['code'], 'm', reason=bad.get('reason'))
    assert RuleError('PT-RULE-CANCEL', 'c').reason is None


def test_worker_error_codes_are_the_error_vocabulary():
    assert get_args(c.WorkerError.model_fields['code'].annotation) == CODES


def test_shared_identifier_shapes_match_the_intelligence_contract():
    pairs = [(c.Sha256, intel.Sha256), (c.CveId, intel.CveId), (c.CweId, intel.CweId)]
    for ours, theirs in pairs:
        assert TypeAdapter(ours).json_schema() == TypeAdapter(theirs).json_schema()
    assert get_args(c.Resolution) == get_args(intel.Resolution)
    for good, bad in (('2026-10-14T01:02:03Z', '2026-13-14T01:02:03Z'), ('2026-10-14T01:02:03+00:00', '2026-10-14')):
        adapter = TypeAdapter(c.Utc)
        assert adapter.validate_python(good) == good
        with pytest.raises(ValidationError):
            adapter.validate_python(bad)
    with pytest.raises(ValidationError):  # a real calendar check, not just a shape
        TypeAdapter(c.Utc).validate_python('2026-02-31T01:02:03Z')


# --- text hygiene (rule text and every free-text field are untrusted) ------------------------------------------------

HOSTILE = ['a"b', 'a\\', 'new\nline', 'cr\rlf', 'tab\there', '*/ evil /*', 'brace}', 'nul\x00byte', 'bidi‮flip',
           'iso⁦late', 'zero​width', 'bom﻿', 'ls sep', 'del\x7f', 'c1\x85', 'lone\ud800surrogate',
           'tag\U000e0041']


@pytest.mark.parametrize('text', [t for t in HOSTILE if t not in ('a"b', 'a\\', 'brace}', '*/ evil /*')],
                         ids=lambda t: repr(t)[:24])
def test_plain_line_refuses_control_format_and_separator_characters(text):
    with pytest.raises(ValueError):
        c.plain_line(text)


def test_plain_line_and_text_accept_ordinary_unicode_and_text_allows_only_tab_and_newline():
    for ok in ('Example label', 'café テスト \U0001f600', 'KERNEL32.dll'):
        assert c.plain_line(ok) == ok and c.plain_text(ok) == ok
    assert c.plain_text('two\nlines\tand tab') == 'two\nlines\tand tab'
    for bad in ('x\x00', 'x\r', 'x‮', 'x\ud800'):
        with pytest.raises(ValueError):
            c.plain_text(bad)


@given(st.text(max_size=300))
@settings(max_examples=200, deadline=None)
def test_clean_line_always_yields_text_that_plain_line_accepts(text):
    cleaned = c.clean_line(text, 40)
    assert len(cleaned) <= 40 and c.plain_line(cleaned) == cleaned and cleaned == cleaned.strip()


def test_clean_line_blanks_unsafe_characters_collapses_whitespace_and_caps():
    assert c.clean_line('a‮b\x00c\n  d\t\te', 50) == 'a b c d e'
    assert c.clean_line(None, 10) == '' and c.clean_line(12345, 3) == '123' and c.clean_line('x' * 500, 200) == 'x' * 200
    assert c.clean_line('\ud800 lone', 20) == 'lone'


@pytest.mark.parametrize('text', ['{"a": 1, "a": 2}', '{"a": NaN}', '[Infinity]', '[-Infinity]', '{"a": 1.5}',
                                  '[1e999]', '["\\ud800"]', '[' * 200_000 + ']' * 200_000, '[' + '9' * 5000 + ']', '{',
                                  '', '{"a": 1} x'],
                         ids=['duplicate-key', 'nan', 'infinity', 'minus-infinity', 'float', 'overflow-float',
                              'lone-surrogate', 'deep-nesting', 'huge-integer', 'truncated', 'empty', 'trailing-text'])
def test_strict_json_refuses_what_the_contracts_never_contain(text):
    with pytest.raises(ValueError):
        c.strict_json(text)


def test_strict_json_returns_ordinary_documents_unchanged():
    assert c.strict_json('{"a": [1, "x\\u00e9", null, true], "b": {"c": -3}}') == {
        'a': [1, 'xé', None, True], 'b': {'c': -3}}


@pytest.mark.parametrize('text', ['rule x {}\r\n', 'café', 'tab\there', 'nul\x00', 'del\x7f', ''],
                         ids=['crlf', 'non-ascii', 'tab', 'nul', 'del', 'empty'])
def test_rule_text_is_lf_only_printable_ascii(text):
    with pytest.raises(ValidationError):
        TypeAdapter(c.RuleText).validate_python(text)
    assert TypeAdapter(c.RuleText).validate_python('rule x {\n  condition: true\n}\n')


def test_rule_text_is_bounded_by_the_card():
    adapter = TypeAdapter(c.RuleText)
    assert adapter.validate_python('a' * DEFAULT_LIMITS.rule_text_bytes)
    with pytest.raises(ValidationError):
        adapter.validate_python('a' * (DEFAULT_LIMITS.rule_text_bytes + 1))


@pytest.mark.parametrize('text', ['say "hi"', 'back\\', 'x\\q', 'x\\x4', 'x\\x4g', 'new\nline', 'café', 'x\x7f',
                                  'x\x00', '\\'], ids=lambda t: repr(t)[:20])
def test_escaped_text_refuses_anything_that_could_leave_the_string(text):
    with pytest.raises(ValidationError):
        TypeAdapter(c.EscapedText).validate_python(text)


def reference_escape(data: bytes) -> str:
    """The test's own escaper (the real one is R1's): printable ASCII except quote and backslash, else a named escape."""
    named = {0x22: '\\"', 0x5C: '\\\\', 0x0A: '\\n', 0x0D: '\\r', 0x09: '\\t'}
    return ''.join(named.get(b) or (chr(b) if 0x20 <= b < 0x7F else f'\\x{b:02x}') for b in data)


@given(st.binary(min_size=1, max_size=DEFAULT_LIMITS.text_pattern_bytes))
@settings(max_examples=200, deadline=None)
def test_any_bytes_escape_to_text_the_contract_accepts_and_counts(data):
    text = reference_escape(data)
    if len(text) <= 4 * DEFAULT_LIMITS.text_pattern_bytes:
        assert TypeAdapter(c.EscapedText).validate_python(text) == text
        assert c.unescaped_length(text) == len(data)


@given(st.text(min_size=1, max_size=40).filter(lambda s: '"' in s or '\\' in s or not s.isascii() or not s.isprintable()))
@settings(max_examples=200, deadline=None)
def test_unescaped_quotes_backslashes_and_non_printables_never_pass_as_escaped_text(text):
    cleaned = text.replace('\\\\', '').replace('\\"', '')
    if '"' in cleaned or '\\' in cleaned or not cleaned.isascii() or not cleaned.isprintable():
        with pytest.raises(ValidationError):
            TypeAdapter(c.EscapedText).validate_python(text)


def test_pattern_metrics_and_bytes_feature_agree_on_the_same_numbers():
    assert c.pattern_metrics('48 83 ?? ?? EC 28 00') == (7, 5, 3)
    assert c.pattern_metrics('?? ??') == (2, 0, 0)
    assert c.pattern_metrics(' '.join(['AA'] * 20)) == (20, 20, 20)
    feature = RECORDS['BytesFeature'][0]
    assert c.pattern_metrics(feature.pattern) == (feature.length, feature.literal, feature.longest_run)


@pytest.mark.parametrize('pattern', ['48 83 ec 28 31 c9 ba 01 00 00 00 90 48 ff 15 00 00 00 00 48 83 c4 28 c3',
                                     '48  83 EC 28 31 C9 BA 01 00 00 00 90 48 FF 15 00 00 00 00 48 83 C4 28 C3',
                                     '48 83 EC 28 31 C9 BA 01 00 00 00 90 48 FF 15 00 00 00 00 48 83 C4 28 C3 ',
                                     ' '.join(['48'] * 15), ' '.join(['48'] * 513), '??', ' '.join(['4?'] * 16),
                                     ' '.join(['0x48'] * 16), ' '.join(['48'] * 15) + ' [1-2] 48'],
                         ids=['lower-case', 'double-space', 'trailing-space', 'fifteen', 'too-long', 'single-wildcard',
                              'nibble-wildcard', 'prefixed', 'jump'])
def test_hex_patterns_are_canonical_upper_case_tokens_of_16_to_512_bytes(pattern):
    document = json.loads(RECORDS['BytesFeature'][0].model_dump_json()) | {'pattern': pattern}
    assert 'string_pattern_mismatch' in rejection('BytesFeature', document)


def test_a_window_of_wildcards_only_is_representable_so_the_length_gate_can_fail_it():
    document = json.loads(RECORDS['BytesFeature'][0].model_dump_json())
    document |= {'pattern': ' '.join(['??'] * 16), 'length': 16, 'literal': 0, 'longest_run': 0, 'pins': [],
                 'included': False}
    assert rejection('BytesFeature', document) is None
    longest = ' '.join(['AA'] * 512)
    assert rejection('BytesFeature', document | {'pattern': longest, 'length': 512, 'literal': 512,
                                                'longest_run': 512}) is None


# --- cross-field rules the examples do not show one by one ----------------------------------------------------------

def test_candidate_needs_an_eligible_pair_a_function_on_its_side_and_an_included_feature():
    candidate = RECORDS['RuleCandidate'][0]
    base = json.loads(candidate.model_dump_json())
    ineligible = base | {'source': base['source'] | {'materiality': 'review'}}
    assert 'only a pair reviewed as material' in rejection('RuleCandidate', ineligible)
    confirmed = base | {'source': base['source'] | {'materiality': 'review', 'analyst_confirmed_material': True},
                        'unvetted': True}
    assert rejection('RuleCandidate', confirmed) is None
    wrong_side = base | {'direction': 'newer', 'rule_name': c.rule_name_for(base['lineage_id'], 'newer')}
    assert 'needs a newer function' in rejection('RuleCandidate', wrong_side)
    nothing = base | {'features': [dict(f, included=False) for f in base['features']]}
    assert 'includes at least one feature' in rejection('RuleCandidate', nothing)


def test_candidate_refuses_included_features_from_the_other_build_or_shared_by_both():
    base = json.loads(RECORDS['RuleCandidate'][0].model_dump_json())
    for index, patch in ((0, {'side': 'newer', 'separation': 'older-only'}), (1, {'separation': 'unknown'}),
                         (3, {'included': True})):
        features = [dict(f) for f in base['features']]
        features[index].update(patch)
        error = rejection('RuleCandidate', base | {'features': features})
        assert error is not None, (index, patch)


def test_candidate_caps_included_patterns_per_the_card():
    base = json.loads(RECORDS['RuleCandidate'][0].model_dump_json())
    string = json.loads(RECORDS['StringFeature'][0].model_dump_json()) | {'included': True, 'side': 'older',
                                                                           'separation': 'older-only'}
    nine = [dict(string, offset=i) for i in range(9)]
    assert 'pattern ceilings' in rejection('RuleCandidate', base | {'features': base['features'] + nine})
    eight = [dict(string, offset=i) for i in range(8)]
    assert rejection('RuleCandidate', base | {'features': base['features'] + eight}) is None  # 1 + 8 <= 12
    assert 'pattern ceilings' in rejection('RuleCandidate', base | {'features': base['features'] + eight + [
        json.loads(RECORDS['BytesFeature'][0].model_dump_json()) | {'window_rva': 9}] * 4})


def test_version_numbers_are_bounded_and_text_must_be_the_lineages():
    document = json.loads(RECORDS['RuleVersion'][1].model_dump_json())
    assert rejection('RuleVersion', document) is None
    assert rejection('RuleVersion', document | {'version': DEFAULT_LIMITS.versions_per_lineage + 1}) is not None
    assert 'rule of this lineage' in rejection('RuleVersion', document | {'lineage_id': 'e' * 64})


def cell(**fields) -> dict:
    """A cell document; every field is explicit so each case below states exactly what makes it invalid."""
    return {'state': 'hit', 'hits': 1, 'offsets': [], 'rvas': [], 'reason': None, 'elapsed_ms': 1,
            'verdict': 'unscored'} | fields


@pytest.mark.parametrize('document, message', [
    (cell(hits=3, offsets=[1, 2, 3, 4], rvas=[1, 2, 3, 4]), 'cannot exceed the hit count'),
    (cell(hits=9, offsets=list(range(9)), rvas=list(range(9))), 'too_long'),
    (cell(hits=2, offsets=[1, 2], rvas=[1]), 'rvas parallel offsets'),
    (cell(state='no-hit', hits=0, offsets=[4], rvas=[4]), 'only a hit has offsets'),
    (cell(state='timeout', hits=None, reason='slow'), 'only not-scanned and error'),
    (cell(state='error', hits=None, reason=None), 'needs a reason slug'),
    (cell(state='not-scanned', hits=None, reason=None), 'one reason of the closed list'),
    (cell(state='timeout', hits=0), 'no hit count'),
    (cell(state='no-hit', hits=None), 'no-hit means zero'),
    (cell(hits=None), 'at least one match'),
], ids=['too-many-offsets', 'nine-offsets', 'rva-length', 'miss-with-offsets', 'timeout-reason', 'error-no-reason',
        'unscanned-no-reason', 'timeout-zero-hits', 'miss-without-count', 'hit-without-count'])
def test_cell_results_keep_unknown_apart_from_none_found(document, message):
    assert message in rejection('CellResult', document)


def test_unmapped_offsets_have_no_rva_and_a_pattern_free_hit_has_no_offsets():
    cell = {'state': 'hit', 'hits': 2, 'offsets': [10, 20], 'rvas': [4096, None], 'reason': None, 'elapsed_ms': 0,
            'verdict': 'unscored'}
    assert rejection('CellResult', cell) is None
    assert rejection('CellResult', cell | {'hits': 1, 'offsets': [], 'rvas': []}) is None
    assert rejection('CellResult', cell | {'rvas': [4096, -1]}) is not None


def test_matrix_run_is_row_major_targets_by_rules_and_failed_runs_keep_no_cells():
    run = json.loads(RECORDS['MatrixRun'][0].model_dump_json())
    assert rejection('MatrixRun', run) is None
    assert 'targets x rules' in rejection('MatrixRun', run | {'cells': run['cells'][:-1]})
    assert rejection('MatrixRun', run | {'status': 'failed', 'cells': []}) is None
    assert 'targets x rules' in rejection('MatrixRun', run | {'status': 'failed'})
    second = dict(run['rules'][0], version_id='f' * 64)
    two_rules = run | {'rules': [run['rules'][0], second], 'cells': run['cells'] * 2}
    assert rejection('MatrixRun', two_rules) is None
    assert 'must be unique' in rejection('MatrixRun', two_rules | {'rules': [run['rules'][0]] * 2})


def test_worker_result_is_an_ok_document_of_its_op_or_an_error_alone():
    probe, scan, error = (json.loads(r.model_dump_json()) for r in RECORDS['WorkerResult'])
    assert rejection('WorkerResult', probe | {'modules': []}) is not None
    assert rejection('WorkerResult', scan | {'cells': []}) is not None
    assert rejection('WorkerResult', scan | {'engine': None}) is not None
    assert rejection('WorkerResult', error | {'error': None}) is not None
    assert rejection('WorkerResult', probe | {'op': 'lint'}) is not None


def test_worker_request_caps_the_grid_by_the_cell_limit():
    scan = json.loads(RECORDS['WorkerRequest'][2].model_dump_json())
    rules = [dict(scan['rules'][0], name=f'r{i}') for i in range(DEFAULT_LIMITS.rules_per_run)]
    targets = [dict(scan['targets'][0], target_id=f't{i}') for i in range(DEFAULT_LIMITS.targets_per_run)]
    assert rejection('WorkerRequest', scan | {'rules': rules, 'targets': targets}) is None  # 103,600 <= 105,000
    assert 'must be unique' in rejection('WorkerRequest', scan | {'rules': rules[:2] + rules[:1]})
    assert rejection('WorkerRequest', scan | {'targets': targets + [dict(targets[0], target_id='extra')]}) is not None


def test_engine_stamp_pin_constants_name_the_measured_versions():
    assert (c.ENGINE_PIN, c.DECODER_PIN) == ('1.21.0', '1.21.0')
    assert (c.CONTRACT, c.WORKER_CONTRACT, c.GRAMMAR, c.ENGINE) == ('yara-rules/1', 'rules-worker/1', 'yrx-gen/1', 'yara-x')
    stamp = RECORDS['EngineStamp'][1]
    assert (stamp.decoder, stamp.decoder_version, stamp.version_source) == ('none', None, 'pin')


def test_gate_ids_are_the_cards_eight_in_canonical_order():
    assert c.GATE_IDS == ('elig', 'len', 'wild', 'uniq', 'sep', 'compile', 'secret', 'dist')
    assert c.NOT_SCANNED_REASONS == ('too-large', 'unreadable', 'not-pe', 'file-changed', 'cancelled')


# --- ports -------------------------------------------------------------------------------------------------------------

class FakeMasks:
    name = 'iced-x86'
    version = '1.21.0'

    def decode(self, code, rva):
        return (ports.DecodedInstruction(offset=0, size=len(code), flow='next'),)


class FakeLookup:
    def pair(self, project_id, match_id):
        return RECORDS['PairSource'][0]


class FakeStrings:
    def strings(self, pair):
        return ports.StringChannel(ports.Coverage('complete', 'unavailable'))


class FakeCapabilities:
    def capabilities(self, pair):
        return ports.CapabilityChannel(ports.Coverage('complete', 'complete'))


class FakeImports:
    def imports(self, pair, side):
        return None


class FakeBuilds:
    def builds(self, pair):
        return (ports.BuildEntry(RECORDS['TargetRef'][0], '/example/older.bin'),)


class FakeAdvisories:
    def advisory_says(self, cves, sha256s):
        return {s: 'unknown' for s in sha256s}


PORTS = [(ports.MaskSource, FakeMasks), (ports.PairLookup, FakeLookup), (ports.StringSource, FakeStrings),
         (ports.CapabilitySource, FakeCapabilities), (ports.ImportSource, FakeImports), (ports.BuildSource, FakeBuilds),
         (ports.AdvisorySource, FakeAdvisories)]


@pytest.mark.parametrize('protocol, fake', PORTS, ids=[p.__name__ for p, _ in PORTS])
def test_ports_are_runtime_checkable_protocols_a_fake_satisfies(protocol, fake):
    assert isinstance(fake(), protocol) and not isinstance(object(), protocol)


def test_the_card_lists_seven_ports_and_the_pair_port_does_not_shadow_the_record():
    protocols = {n for n, v in vars(ports).items() if getattr(v, '_is_protocol', False) and n != 'Protocol'}
    assert protocols == {'MaskSource', 'PairLookup', 'StringSource', 'CapabilitySource', 'ImportSource', 'BuildSource',
                         'AdvisorySource'}
    assert not hasattr(ports, 'PairSource') or ports.PairSource is c.PairSource  # the record, imported for annotations


def test_channel_data_is_plain_frozen_and_says_unavailable_not_none():
    channel = FakeStrings().strings(RECORDS['PairSource'][0])
    assert channel.items == () and channel.coverage.newer == 'unavailable'
    with pytest.raises(dataclasses.FrozenInstanceError):
        channel.items = ()  # type: ignore[misc]
    assert get_args(ports.ChannelState) == ('complete', 'unavailable')


# --- purity: no Qt, I/O, network, process, sqlite, engine or other feature at import time --------------------------------

PURE = ('limits', 'errors', 'contracts', 'ports')
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'datetime', 'hashlib', 'json', 're', 'typing'}
RUNTIME_ALLOWED = {'limits': set(), 'errors': set(), 'contracts': {'pydantic', 'patchtrace.rules.errors',
                                                                   'patchtrace.rules.limits'},
                   'ports': {'patchtrace.rules.contracts'}}
FORBIDDEN_ROOTS = {'PySide6', 'shiboken6', 'yara_x', 'iced_x86', 'capstone', 'socket', 'ssl', 'urllib', 'http', 'ftplib',
                   'smtplib', 'requests', 'httpx', 'aiohttp', 'sqlite3', 'subprocess', 'multiprocessing', 'ctypes',
                   'asyncio', 'threading'}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding='utf-8'))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                base = f'patchtrace.rules.{base}' if base else 'patchtrace.rules'
            found.add(base)
    return found


@pytest.mark.parametrize('module', PURE, ids=PURE)
def test_pure_modules_respect_the_import_rules(module):
    runtime = _imports(PACKAGE / f'{module}.py')
    assert runtime - STDLIB <= RUNTIME_ALLOWED[module], runtime
    assert not {m.split('.')[0] for m in runtime} & FORBIDDEN_ROOTS


def test_no_rules_module_imports_the_network_or_a_gui_toolkit():
    """Offline-first (plan s3.7): across the whole package, whatever slices have landed."""
    for path in sorted(PACKAGE.rglob('*.py')):
        roots = {m.split('.')[0] for m in _imports(path)}
        if path.name == 'qt_panel.py':  # the Rules dock's widgets are the package's only Qt module
            roots -= {'PySide6', 'shiboken6'}
        assert not roots & {'PySide6', 'shiboken6', 'socket', 'ssl', 'urllib', 'http', 'ftplib', 'smtplib', 'requests',
                            'httpx', 'aiohttp', 'xmlrpc'}, path.name


def test_only_the_engine_side_modules_may_import_the_extension():
    allowed = {PACKAGE / 'engine.py', PACKAGE / 'worker.py', PACKAGE / 'adapters' / 'mask_iced.py'}
    for path in sorted(PACKAGE.rglob('*.py')):
        if path in allowed:
            continue
        roots = {m.split('.')[0] for m in _imports(path)}
        assert not roots & {'yara_x', 'iced_x86'}, path.name


def test_init_is_documentation_only():
    tree = ast.parse((PACKAGE / '__init__.py').read_text(encoding='utf-8'))
    assert all(isinstance(n, ast.Expr) for n in tree.body)  # a docstring and nothing that runs


def test_importing_the_contract_modules_loads_no_qt_engine_sqlite_process_or_other_feature():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] in ("PySide6", "yara_x", "iced_x86"): raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.rules, patchtrace.rules.limits, patchtrace.rules.errors, patchtrace.rules.contracts\n'
            'import patchtrace.rules.ports\n'
            'bad = [m for m in ("PySide6", "yara_x", "iced_x86", "sqlite3", "subprocess", "ssl", "urllib.request",\n'
            '                   "http.client", "patchtrace.intelligence", "patchtrace.unified", "patchtrace.secondary",\n'
            '                   "patchtrace.kbcorrelation", "patchtrace.enrichment", "patchtrace.persistence")\n'
            '       if m in sys.modules]\n'
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(PACKAGE.parents[1]))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
