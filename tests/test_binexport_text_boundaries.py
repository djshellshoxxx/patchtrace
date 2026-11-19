"""BinExport2 nested string boundaries, using real upb decoding of authored wire data.

These are parser regressions, not evidence of compatibility with a live exporter.
"""
from __future__ import annotations

import threading

import pytest
from binexport_builder import SHA, raw, valid
from hypothesis import given, settings
from hypothesis import strategies as st

from patchtrace.secondary.binexport_limits import BinExportLimits, Budget
from patchtrace.secondary.binexport_pipeline import inspect_bytes
from patchtrace.secondary.binexport_proto import load_binexport2_class
from patchtrace.secondary.binexport_run import accept_binexport
from patchtrace.secondary.contracts import SecondaryError

FIELDS = (
    ('expression', 2, 'symbol', 2),
    ('mnemonic', 4, 'name', 1),
    ('library', 14, 'name', 3),
    ('module', 16, 'name', 1),
)
FIELD_IDS = [f'{table}.{name}' for table, _, name, _ in FIELDS]


def _varint(number: int) -> bytes:
    out = bytearray()
    while number >= 128:
        out.append((number & 127) | 128)
        number >>= 7
    out.append(number)
    return bytes(out)


def _record(number: int, payload: bytes) -> bytes:
    return _varint(number << 3 | 2) + _varint(len(payload)) + payload


def _data(field, payload: bytes) -> bytes:
    _, table_number, _, field_number = field
    return raw(valid()) + _record(table_number, _record(field_number, payload))


def _reject(data: bytes, reason: str, limits: BinExportLimits | None = None) -> None:
    with pytest.raises(SecondaryError) as info:
        inspect_bytes(data, limits or BinExportLimits(), Budget())
    assert (info.value.code, info.value.reason) == ('PT-SECONDARY-INPUT', reason)
    assert len(info.value.message) <= 200


@pytest.mark.parametrize('field', FIELDS, ids=FIELD_IDS)
@pytest.mark.parametrize('payload', [b'\xff', b'\xc0\xaf', b'\xe2\x82', b'\xed\xa0\x80'],
                         ids=['invalid-start', 'overlong', 'truncated', 'surrogate'])
def test_nested_invalid_utf8_is_rejected_after_upb_accepts_wire(field, payload):
    data = _data(field, payload)
    parsed = load_binexport2_class().FromString(data)
    table, _, name, _ = field
    assert getattr(getattr(parsed, table)[-1], name) == payload
    _reject(data, 'utf8_invalid')


@pytest.mark.parametrize('field', FIELDS, ids=FIELD_IDS)
@pytest.mark.parametrize('text', ['x' * 65, '\U0001f600' * 17], ids=['ascii', 'utf8-bytes'])
def test_nested_string_limit_counts_utf8_bytes(field, text):
    assert len(text.encode('utf-8')) > 64
    _reject(_data(field, text.encode('utf-8')), 'string_too_long', BinExportLimits(max_string_bytes=64))


@pytest.mark.parametrize('field', FIELDS, ids=FIELD_IDS)
@pytest.mark.parametrize('text', ['', '\U0001f600' * 16, '\x00\t\n\u00e9'],
                         ids=['empty', 'exact-utf8-limit', 'text-controls'])
def test_valid_nested_text_retains_its_exact_value(field, text):
    msg, _, _ = inspect_bytes(_data(field, text.encode('utf-8')), BinExportLimits(max_string_bytes=64), Budget())
    table, _, name, _ = field
    assert getattr(getattr(msg, table)[-1], name) == text


def test_absent_optional_nested_strings_remain_valid():
    msg = valid()
    for table, _, name, _ in FIELDS:
        for item in getattr(msg, table):
            item.ClearField(name)
    inspect_bytes(raw(msg), BinExportLimits(), Budget())


@settings(max_examples=100, deadline=None, database=None)
@given(st.sampled_from(FIELDS), st.text(max_size=32), st.text(max_size=32))
def test_invalid_byte_between_valid_utf8_is_always_rejected(field, before, after):
    _reject(_data(field, before.encode('utf-8') + b'\xff' + after.encode('utf-8')), 'utf8_invalid')


def test_real_worker_rejects_invalid_library_text_and_preserves_source(tmp_path):
    source = tmp_path / 'invalid-library.BinExport'
    data = _data(FIELDS[2], b'\xff')
    source.write_bytes(data)
    private = tmp_path / 'private'
    private.mkdir()
    with pytest.raises(SecondaryError) as info:
        accept_binexport(source, artifact_sha256=SHA, role='older', private_dir=private,
                         cancel=threading.Event())
    assert (info.value.code, info.value.reason) == ('PT-SECONDARY-INPUT', 'utf8_invalid')
    assert source.read_bytes() == data

