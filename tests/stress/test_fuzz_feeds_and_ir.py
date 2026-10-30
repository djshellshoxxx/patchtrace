"""QA-FUZZ: hostile provider feeds and extractor JSON lines (Winbindex gzip records, unified IR records).

Properties: the Winbindex record parser raises only AcquisitionError for corrupt, truncated, non-JSON or oversized
gzip bodies, and the decompression cap holds; the unified IR line parser raises only its typed UnifiedError for any
bytes. The byte budgets are monkeypatched to small values so the examples stay fast; nothing is downloaded or run.
"""
from __future__ import annotations

import gzip
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.acquisition import winbindex
from patchtrace.acquisition.contracts import AcquisitionError
from patchtrace.unified.ir.records import parse_json_line
from patchtrace.unified.limits import UnifiedError

SETTINGS = settings(max_examples=150, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
DATE = '2026-10-01'
FILE = 'kernel32.dll'
TEXT = st.text(alphabet=st.characters(blacklist_categories=('Cs',)), max_size=16)
JSON = st.recursive(st.none() | st.booleans() | st.integers(-10**9, 10**9) | TEXT,
                    lambda kids: st.lists(kids, max_size=3) | st.dictionaries(TEXT, kids, max_size=3),
                    max_leaves=25)


@SETTINGS
@given(st.binary(max_size=300))
def test_winbindex_uncompressed_parse_only_raises_acquisition_error(raw):
    try:
        winbindex.parse(raw, FILE, DATE, compressed=False)
    except AcquisitionError:
        pass


@SETTINGS
@given(st.binary(max_size=300))
def test_winbindex_gzip_parse_only_raises_acquisition_error(raw):
    try:
        winbindex.parse(gzip.compress(raw), FILE, DATE)
    except AcquisitionError:
        pass


@SETTINGS
@given(st.binary(min_size=1, max_size=200), st.booleans())
def test_winbindex_non_utf8_bodies_raise_acquisition_error(raw, compressed):
    body = b'\xff' + raw  # 0xff never starts valid UTF-8, and it is not a UTF-16/32 BOM either
    data = gzip.compress(body) if compressed else body
    with pytest.raises(AcquisitionError):
        winbindex.parse(data, FILE, DATE, compressed=compressed)


@SETTINGS
@given(JSON, st.integers(0, 40))
def test_winbindex_truncated_json_bodies_only_raise_acquisition_error(value, cut):
    body = json.dumps({'entry': value}).encode('utf-8')
    body = body[:max(1, len(body) - cut)]
    try:
        winbindex.parse(gzip.compress(body), FILE, DATE)
    except AcquisitionError:
        pass


def test_winbindex_decompression_cap_stops_a_gzip_bomb(monkeypatch):
    monkeypatch.setattr(winbindex, 'MAX_DECOMPRESSED', 64 * 1024)
    bomb = gzip.compress(b'\x00' * (1024 * 1024))
    with pytest.raises(AcquisitionError) as info:
        winbindex.parse(bomb, FILE, DATE)
    assert info.value.code == 'PT-ACQ-LIMIT'


def test_winbindex_compressed_size_cap_is_checked_first(monkeypatch):
    monkeypatch.setattr(winbindex, 'MAX_COMPRESSED', 16)
    with pytest.raises(AcquisitionError) as info:
        winbindex.parse(gzip.compress(b'{}' * 64), FILE, DATE)
    assert info.value.code == 'PT-ACQ-LIMIT'


@SETTINGS
@given(st.binary(max_size=400))
def test_ir_json_line_only_raises_the_typed_error_for_bytes(raw):
    try:
        parse_json_line(raw)
    except UnifiedError:
        pass


@SETTINGS
@given(JSON)
def test_ir_json_line_accepts_only_objects_and_rejects_the_rest(value):
    try:
        document = parse_json_line(json.dumps(value))
    except UnifiedError:
        assert not isinstance(value, dict)
        return
    assert document == value


@pytest.mark.parametrize('line', ['{"a": NaN}', '{"a": 1, "a": 2}', '{"a": 1e999}', '"\\ud800"', '[1]'],
                         ids=['nan', 'duplicate', 'overflow', 'lone-surrogate', 'not-object'])
def test_ir_json_line_rejects_hostile_lines(line):
    with pytest.raises(UnifiedError):
        parse_json_line(line)


def test_winbindex_rejects_overflowing_float_literals():
    body = b'{"k": {"fileInfo": {"sha256": "' + b'a' * 64 + b'", "x": 1e999}}}'
    with pytest.raises(AcquisitionError):
        winbindex.parse(body, FILE, DATE, compressed=False)
