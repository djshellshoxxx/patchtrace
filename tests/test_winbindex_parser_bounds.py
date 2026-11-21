"""Winbindex byte budgets apply before JSON parsing, with or without gzip."""
from __future__ import annotations

import gzip
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.acquisition import winbindex as wb
from patchtrace.acquisition.contracts import AcquisitionError

PARSERS = ('strict_json', 'parse', 'parse_rows')


def _parse(parser: str, data: bytes, *, compressed: bool = False):
    if parser == 'strict_json':
        return wb.strict_json(data)
    return getattr(wb, parser)(data, 'example.sys', '2026-11-19', compressed=compressed)


@pytest.mark.parametrize('parser', PARSERS)
def test_oversized_raw_document_is_refused_before_json_allocation(monkeypatch, parser):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 16)

    def forbidden(*args, **kwargs):
        pytest.fail('oversized metadata reached JSON decoding')

    monkeypatch.setattr(wb.json, 'loads', forbidden)
    with pytest.raises(AcquisitionError) as error:
        _parse(parser, b'{}' + b' ' * 15)
    assert error.value.code == 'PT-ACQ-LIMIT'


@pytest.mark.parametrize('parser', PARSERS)
def test_exact_byte_limit_remains_eligible(monkeypatch, parser):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 16)
    result = _parse(parser, b'{}' + b' ' * 14)
    if parser == 'strict_json':
        assert result == {}
    else:
        assert result.skipped == 0 and result.warnings == ()


@pytest.mark.parametrize('parser', PARSERS)
def test_limit_is_bytes_and_precedes_utf8_validation(monkeypatch, parser):
    data = json.dumps({'é': {}}, ensure_ascii=False).encode('utf-8')
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', len(data.decode('utf-8')))
    for body in (data, b'\xff' * len(data)):
        with pytest.raises(AcquisitionError) as error:
            _parse(parser, body)
        assert error.value.code == 'PT-ACQ-LIMIT'


@pytest.mark.parametrize('parser', ('parse', 'parse_rows'))
def test_gzip_and_raw_share_decoded_boundary(monkeypatch, parser):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', 16)
    at_limit = b'{}' + b' ' * 14
    assert _parse(parser, at_limit) == _parse(parser, gzip.compress(at_limit, mtime=0), compressed=True)
    for compressed in (False, True):
        over = at_limit + b' '
        with pytest.raises(AcquisitionError) as error:
            _parse(parser, gzip.compress(over, mtime=0) if compressed else over, compressed=compressed)
        assert error.value.code == 'PT-ACQ-LIMIT'


@settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(padding=st.integers(0, 512), limit=st.integers(2, 514))
def test_raw_byte_budget_property(monkeypatch, padding, limit):
    monkeypatch.setattr(wb, 'MAX_DECOMPRESSED', limit)
    data = b'{}' + b' ' * padding
    for parser in PARSERS:
        if len(data) > limit:
            with pytest.raises(AcquisitionError) as error:
                _parse(parser, data)
            assert error.value.code == 'PT-ACQ-LIMIT'
        else:
            _parse(parser, data)
