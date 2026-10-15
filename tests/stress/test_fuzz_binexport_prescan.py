"""QA-FUZZ: the BinExport2 top-level wire prescan, before any protobuf object is built.

Properties: arbitrary bytes either yield WireStats or a typed SecondaryError (never IndexError, struct or protobuf
errors); well-formed generated wire is accepted with exact per-field counts; varints longer than 64 bits, group wire
types, field 0, duplicate singletons, oversized records and unknown-field excess are refused. Only bytes are parsed.
"""
from __future__ import annotations

import dataclasses

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from patchtrace.secondary.binexport_limits import BinExportLimits, Budget
from patchtrace.secondary.binexport_prescan import KNOWN, prescan
from patchtrace.secondary.contracts import SecondaryError

SETTINGS = settings(max_examples=200, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
LIMITS = BinExportLimits()
BUDGET = Budget()


def _varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _record(field: int, payload: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def _scan(raw: bytes, limits: BinExportLimits = LIMITS):
    return prescan(memoryview(raw), limits, BUDGET)


@SETTINGS
@given(st.binary(max_size=512))
def test_prescan_only_returns_stats_or_a_typed_secondary_error(raw):
    try:
        stats = _scan(raw)
    except SecondaryError:
        return
    assert stats.total_bytes == len(raw)


@SETTINGS
@given(st.lists(st.tuples(st.sampled_from(sorted(set(KNOWN) - {1, 8, 93992622})), st.binary(max_size=24)),
                max_size=30),
       st.lists(st.integers(18, 500), max_size=4))
def test_well_formed_wire_is_accepted_with_exact_counts(records, unknown_fields):
    wire = _record(1, b'meta') + _record(8, b'graph')
    expected: dict[int, int] = {1: 1, 8: 1}
    for field, payload in records:
        wire += _record(field, payload)
        expected[field] = expected.get(field, 0) + 1
    for number in unknown_fields:
        wire += _varint(number << 3) + _varint(7)  # unknown varint field
    stats = _scan(wire)
    for number, label in KNOWN.items():
        assert stats.count(label) == expected.get(number, 0)
    assert stats.unknown_bytes == sum(len(_varint(n << 3)) + len(_varint(7)) for n in unknown_fields)


@SETTINGS
@given(st.integers(2, 0x7F))
def test_varint_longer_than_64_bits_is_refused(last):
    assume(last > 1)
    tag = b'\x80' * 9 + bytes([last])  # a 10th byte may carry only bit 63
    with pytest.raises(SecondaryError):
        _scan(tag + b'\x00')


@pytest.mark.parametrize('wire_type', [3, 4], ids=['start-group', 'end-group'])
def test_group_wire_types_are_refused_at_top_level(wire_type):
    with pytest.raises(SecondaryError):
        _scan(_varint(2 << 3 | wire_type) + _record(1, b'm') + _record(8, b'c'))


def test_field_zero_and_wire_type_mismatch_are_refused():
    with pytest.raises(SecondaryError):
        _scan(b'\x00\x00' + _record(1, b'm') + _record(8, b'c'))
    mismatch = _varint(1 << 3) + _varint(5)  # meta_information as a varint instead of a message
    with pytest.raises(SecondaryError):
        _scan(mismatch + _record(8, b'c'))


@pytest.mark.parametrize('field', [1, 8], ids=['meta-information', 'call-graph'])
def test_duplicate_singletons_are_refused(field):
    wire = _record(1, b'm') + _record(8, b'c')
    with pytest.raises(SecondaryError):
        _scan(wire + _record(field, b'again'))


def test_missing_meta_or_call_graph_is_refused():
    with pytest.raises(SecondaryError):
        _scan(_record(8, b'c'))
    with pytest.raises(SecondaryError):
        _scan(_record(1, b'm'))


@SETTINGS
@given(st.integers(1, 64), st.integers(1, 256))
def test_oversized_records_are_refused_by_the_configured_cap(cap, extra):
    limits = dataclasses.replace(LIMITS, max_record_bytes=cap)
    payload = b'x' * (cap + extra)
    with pytest.raises(SecondaryError):
        _scan(_record(1, b'm') + _record(8, b'c') + _record(4, payload), limits)


@SETTINGS
@given(st.integers(1, 32), st.integers(1, 64))
def test_unknown_field_excess_is_refused(cap, extra):
    limits = dataclasses.replace(LIMITS, max_unknown_bytes=cap)
    filler = _record(99, b'u' * (cap + extra))
    with pytest.raises(SecondaryError):
        _scan(_record(1, b'm') + _record(8, b'c') + filler, limits)


@SETTINGS
@given(st.integers(0, 300))
def test_truncated_length_prefixes_are_refused(cut):
    wire = _record(1, b'meta') + _record(8, b'call-graph-payload')
    if cut >= len(wire):
        return
    with pytest.raises(SecondaryError):
        _scan(wire[:cut])
