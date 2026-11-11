"""QA-FUZZ: capa and FLOSS result parsers on mutated golden documents.

Each example replaces one randomly chosen leaf of a real golden result (capa, FLOSS static or decode) with a random
JSON value, then checks that the adapter either returns an evidence set or raises ToolError. The synthetic PE pair
from tests/intel_tools_support.py supplies the artifact and PE map; no tool binary is executed.
"""
from __future__ import annotations

import copy as copy_module
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from intel_tools_support import golden, image_getter

from patchtrace.intelligence.tools import capa, floss
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolError

SETTINGS = settings(max_examples=120, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
TEXT = st.text(alphabet=st.characters(blacklist_categories=('Cs',)), max_size=20)
JSON = st.recursive(st.none() | st.booleans() | st.integers(-2**70, 2**70) | st.floats(allow_nan=False)
                    | TEXT,
                    lambda kids: st.lists(kids, max_size=3) | st.dictionaries(TEXT, kids, max_size=3),
                    max_leaves=12)


@pytest.fixture(scope='module')
def images(tmp_path_factory):
    get, close = image_getter(tmp_path_factory.mktemp('tool-adapters'))
    yield get
    close()


def _leaf_slots(value, out=None):
    out = [] if out is None else out
    if isinstance(value, dict):
        for key in value:
            if isinstance(value[key], (dict, list)):
                _leaf_slots(value[key], out)
            else:
                out.append((value, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            if isinstance(item, (dict, list)):
                _leaf_slots(item, out)
            else:
                out.append((value, index))
    return out


def _mutate(document: dict, pick: int, replacement) -> bytes:
    doc = copy_module.deepcopy(document)
    slots = _leaf_slots(doc)
    if slots:
        container, key = slots[pick % len(slots)]
        container[key] = replacement
    return json.dumps(doc).encode('utf-8')


@SETTINGS
@given(st.integers(0, 10**6), JSON)
def test_capa_parse_on_mutated_golden_only_raises_tool_error(images, pick, replacement):
    copy, _reader, pe = images('capa-api', 'older')
    ctx = capa.ParseContext('r', 'older', copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
    raw = _mutate(json.loads(golden('capa/capa-api-older.json')), pick, replacement)
    try:
        capa.parse(raw, ctx)
    except ToolError:
        pass


@SETTINGS
@given(st.integers(0, 10**6), JSON)
def test_floss_static_parse_on_mutated_golden_only_raises_tool_error(images, pick, replacement):
    copy, reader, pe = images('floss-static', 'older')
    ctx = floss.ParseContext('r', 'older', copy, 'c' * 64, 'd' * 64, pe, reader, DEFAULT_LIMITS['floss'], False)
    raw = _mutate(json.loads(golden('floss/floss-static-older.static.json')), pick, replacement)
    try:
        floss.parse(raw, ctx)
    except ToolError:
        pass


@SETTINGS
@given(st.binary(max_size=200))
def test_capa_parse_on_arbitrary_bytes_only_raises_tool_error(images, raw):
    copy, _reader, pe = images('capa-api', 'older')
    ctx = capa.ParseContext('r', 'older', copy, 'c' * 64, 'd' * 64, pe, DEFAULT_LIMITS['capa'])
    try:
        capa.parse(raw, ctx)
    except ToolError:
        pass

