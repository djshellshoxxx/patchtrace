"""QA-FUZZ: hostile JSON for the strict importers (project and series.json, tool output, CSAF, KEV, CVRF).

Properties: every importer either returns a value or raises its own typed error; NaN, Infinity, duplicate keys,
overflowing floats, oversized integers, lone surrogates and deep nesting are rejected. Nothing is executed and no
network is opened; each example is pure in-memory parsing or a temporary file.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import validate as csaf
from patchtrace.intelligence.tools import diec
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError, load_json_strict
from patchtrace.kbcorrelation.sources.cvrf import SourceError, parse_cvrf
from patchtrace.kev.contracts import KevError
from patchtrace.kev.parse import parse_catalog
from patchtrace.nway.contracts import NwayError
from patchtrace.nway.series import load as load_series
from patchtrace.persistence import strict_json

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'
SETTINGS = settings(max_examples=150, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])

# Text without lone surrogates: those are rejected by design and tested separately.
TEXT = st.text(alphabet=st.characters(blacklist_categories=('Cs',)), max_size=24)
SCALARS = st.one_of(st.none(), st.booleans(), st.integers(-10**12, 10**12),
                    st.floats(allow_nan=False, allow_infinity=False), TEXT)
JSON = st.recursive(SCALARS, lambda kids: st.one_of(st.lists(kids, max_size=4),
                                                    st.dictionaries(TEXT, kids, max_size=4)), max_leaves=40)


def _write(root: Path, name: str, data: bytes) -> Path:
    path = root / name
    path.write_bytes(data)
    return path


# --- strict JSON used by project and series files ------------------------------------------------------------

@SETTINGS
@given(JSON)
def test_strict_json_accepts_every_plain_document(value):
    assert strict_json(json.dumps(value, ensure_ascii=False)) == value


@SETTINGS
@given(st.text(max_size=200))
def test_strict_json_only_returns_or_raises_value_error(text):
    try:
        strict_json(text)
    except ValueError:
        pass


@SETTINGS
@given(TEXT, JSON, JSON)
def test_strict_json_rejects_duplicate_keys_at_any_depth(key, first, second):
    k = json.dumps(key)
    text = '{' + k + ': ' + json.dumps(first) + ', ' + k + ': ' + json.dumps(second) + '}'
    with pytest.raises(ValueError, match='duplicate'):
        strict_json(text)


@pytest.mark.parametrize('text', ['NaN', '{"x": Infinity}', '[-Infinity]', '{"x": [NaN, 1]}'],
                         ids=['bare-nan', 'object-infinity', 'array-neg-infinity', 'nested-nan'])
def test_strict_json_rejects_non_finite_constants(text):
    with pytest.raises(ValueError, match='PT-SCHEMA'):
        strict_json(text)


@SETTINGS
@given(st.integers(309, 5000), st.sampled_from(['1', '-7', '0.5', '9.99']))
def test_strict_json_rejects_float_literals_that_overflow_to_infinity(exponent, mantissa):
    with pytest.raises(ValueError):
        strict_json(f'[{mantissa}e{exponent}]')


@SETTINGS
@given(st.integers(4301, 6000))
def test_strict_json_rejects_integers_past_the_digit_limit(digits):
    if sys.get_int_max_str_digits() == 0:
        pytest.skip('interpreter integer digit limit disabled')
    with pytest.raises(ValueError):
        strict_json('[' + '9' * digits + ']')


@pytest.mark.parametrize('text', ['"\\ud800"', '{"k\\udfff": 1}', '["a", "\\udc00b"]'],
                         ids=['lone-high', 'lone-low-in-key', 'lone-in-array'])
def test_strict_json_rejects_lone_surrogate_escapes(text):
    with pytest.raises(ValueError):
        strict_json(text)


@SETTINGS
@given(st.integers(900, 60000))
def test_strict_json_deep_nesting_is_a_value_error_not_a_crash(depth):
    try:
        strict_json('[' * depth + ']' * depth)
    except ValueError:
        pass


# --- tool JSON loader shared by capa, FLOSS and diec -----------------------------------------------------------

@SETTINGS
@given(st.binary(max_size=300))
def test_tool_loader_only_raises_tool_error(raw):
    try:
        load_json_strict(raw, max_bytes=256, max_depth=8)
    except ToolError:
        pass


@SETTINGS
@given(st.integers(1, 4096))
def test_tool_loader_size_cap_is_enforced_before_decoding(extra):
    limit = 512
    with pytest.raises(ToolError) as info:
        load_json_strict(b'[' + b'0' * (limit + extra), max_bytes=limit)
    assert info.value.code == 'PT-TOOL-LIMIT'


@SETTINGS
@given(st.integers(1, 200))
def test_tool_loader_depth_limit_is_exact(depth):
    raw = b'[' * depth + b']' * depth
    limit = DEFAULT_LIMITS['capa'].json_depth
    if depth <= limit:
        load_json_strict(raw, max_bytes=10**6)
    else:
        with pytest.raises(ToolError):
            load_json_strict(raw, max_bytes=10**6)


@pytest.mark.parametrize('raw', [b'NaN', b'{"a": Infinity}', b'[-Infinity]', b'[1e999]'],
                         ids=['nan', 'infinity-field', 'neg-infinity', 'overflow-float'])
def test_tool_loader_rejects_non_finite_numbers(raw):
    with pytest.raises(ToolError):
        load_json_strict(raw, max_bytes=1024)


@SETTINGS
@given(JSON)
def test_diec_parse_only_raises_tool_error(value):
    ctx = diec.ParseContext('r', 'older', 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec'])
    try:
        diec.parse(json.dumps({'detects': value}).encode('utf-8'), ctx)
    except ToolError:
        pass


@SETTINGS
@given(st.sampled_from(['filetype', 'info', 'offset', 'parentfilepart', 'size', 'values']), JSON)
def test_diec_parse_with_mutated_detect_field_only_raises_tool_error(field, value):
    detect = {'filetype': 'PE64', 'info': '', 'offset': '0', 'parentfilepart': 'Header', 'size': '1',
              'values': [{'info': '', 'name': 'MSVC', 'string': 'Compiler: MSVC', 'type': 'Compiler',
                          'version': '19'}]}
    detect[field] = value
    raw = json.dumps({'detects': [detect]}).encode('utf-8')
    ctx = diec.ParseContext('r', 'older', 'a' * 64, 'c' * 64, 'd' * 64, DEFAULT_LIMITS['diec'])
    try:
        diec.parse(raw, ctx)
    except ToolError:
        pass


def test_nfc_and_nfd_spelled_keys_are_duplicates():
    text = '{"é": 1, "é": 2}'
    with pytest.raises(ValueError):
        strict_json(text)
    with pytest.raises(ToolError):
        load_json_strict(text.encode('utf-8'), max_bytes=1024)


# --- series.json (nway) ----------------------------------------------------------------------------------------

@SETTINGS
@given(JSON)
def test_series_loader_only_raises_nway_error(value):
    with tempfile.TemporaryDirectory() as root:
        path = _write(Path(root), 'series.json', json.dumps(value).encode('utf-8'))
        try:
            load_series(path)
        except NwayError:
            pass


@SETTINGS
@given(st.binary(max_size=400))
def test_series_loader_survives_binary_garbage(raw):
    with tempfile.TemporaryDirectory() as root:
        path = _write(Path(root), 'series.json', raw)
        try:
            load_series(path)
        except NwayError:
            pass


# --- CSAF advisories -------------------------------------------------------------------------------------------

CSAF_BASE = (FIXTURES / 'csaf' / 'synthetic-advisory-rev1.json').read_bytes()


@SETTINGS
@given(st.binary(max_size=400))
def test_csaf_parse_json_only_raises_intel_error(raw):
    try:
        csaf.parse_json(raw, max_bytes=4096)
    except IntelError:
        pass


@SETTINGS
@given(st.sampled_from(['document', 'product_tree', 'vulnerabilities']), JSON)
def test_csaf_load_document_with_mutated_section_only_raises_intel_error(section, value):
    document = json.loads(CSAF_BASE.decode('utf-8'))
    document[section] = value
    try:
        csaf.load_document(json.dumps(document).encode('utf-8'))
    except IntelError:
        pass


# --- KEV catalog -----------------------------------------------------------------------------------------------

KEV_BASE = json.loads((FIXTURES / 'kev' / 'kev-synthetic-2099.json').read_text(encoding='utf-8'))
KEV_ROW_KEYS = sorted(next(v for v in KEV_BASE.values() if isinstance(v, list))[0])


@SETTINGS
@given(st.sampled_from(KEV_ROW_KEYS), JSON)
def test_kev_catalog_row_field_mutation_only_raises_kev_error(field, value):
    document = json.loads(json.dumps(KEV_BASE))
    rows = next(v for v in document.values() if isinstance(v, list))
    rows[0][field] = value
    try:
        parse_catalog(json.dumps(document).encode('utf-8'), source='local-import',
                      retrieved_at='2099-03-02T08:00:00Z')
    except KevError:
        pass


@SETTINGS
@given(st.sampled_from(sorted(KEV_BASE)), JSON)
def test_kev_catalog_top_level_mutation_only_raises_kev_error(key, value):
    document = json.loads(json.dumps(KEV_BASE))
    document[key] = value
    try:
        parse_catalog(json.dumps(document).encode('utf-8'), source='local-import',
                      retrieved_at='2099-03-02T08:00:00Z')
    except KevError:
        pass


# --- CVRF (JSON and XML dialects) --------------------------------------------------------------------------------

CVRF_BASE = (FIXTURES / 'kbcorrelation' / 'cvrf-2099-Feb-neg.json').read_bytes()


@SETTINGS
@given(st.binary(max_size=300))
def test_cvrf_parse_only_raises_source_error_for_any_bytes(raw):
    try:
        parse_cvrf(b'{' + raw)
    except SourceError:
        pass


@SETTINGS
@given(st.integers(0, len(CVRF_BASE) - 1), st.integers(0, 255))
def test_cvrf_single_byte_mutation_only_raises_source_error(offset, value):
    raw = bytearray(CVRF_BASE)
    raw[offset] = value
    try:
        parse_cvrf(bytes(raw))
    except SourceError:
        pass


@SETTINGS
@given(st.text(alphabet='<>/="&;abcCvrfDoc ', max_size=120))
def test_cvrf_xml_fragments_only_raise_source_error(fragment):
    raw = ('<' + fragment).encode('utf-8')
    try:
        parse_cvrf(raw)
    except SourceError:
        pass


@SETTINGS
@given(st.integers(2, 6))
def test_cvrf_xml_entity_expansion_is_refused_not_expanded(levels):
    decls = ['<!ENTITY e0 "lol">'] + [f'<!ENTITY e{i} "' + f'&e{i - 1};' * 10 + '">' for i in range(1, levels)]
    raw = ('<?xml version="1.0"?><!DOCTYPE CvrfDoc [' + ''.join(decls) + ']>'
           f'<CvrfDoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1" ReleaseId="2099-Feb">&e{levels - 1};'
           '</CvrfDoc>').encode('utf-8')
    with pytest.raises(SourceError):
        parse_cvrf(raw)
