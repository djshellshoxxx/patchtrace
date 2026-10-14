"""SPEC-10b §6.4 (C3-2): top-level wire pre-scan without protobuf, and the limits/budget primitives."""
from __future__ import annotations

import threading

import pytest

from patchtrace.secondary.binexport_limits import (
    GIB,
    MIB,
    TICK_EVERY,
    BinExportLimits,
    Budget,
    memory_for,
)
from patchtrace.secondary.binexport_prescan import KNOWN, prescan
from patchtrace.secondary.contracts import SecondaryError

META = b'\x0a\x03\x12\x01x'          # field 1, len 3: Meta{executable_id='x'}
CG = b'\x42\x02\x0a\x00'             # field 8, len 2: CallGraph{vertex{}}


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def rec(field: int, payload: bytes, wt: int = 2) -> bytes:
    return varint(field << 3 | wt) + (varint(len(payload)) + payload if wt == 2 else payload)


def scan(data: bytes, **kw):
    return prescan(memoryview(data), BinExportLimits(**kw), Budget())


def reason(data: bytes, **kw) -> tuple[str, str]:
    with pytest.raises(SecondaryError) as info:
        scan(data, **kw)
    return info.value.code, info.value.reason


def test_minimal_counts_and_md_index_field():
    data = META + CG + rec(9, b'abc') * 3 + rec(93992622, b'\x08\x01')
    stats = scan(data)
    assert stats.counts[9] == 3 and stats.counts[93992622] == 1 and stats.total_bytes == len(data)
    assert stats.count('string_table') == 3 and stats.unknown_bytes == 0
    assert stats.bytes_by_field[9] == 3 * 5


WIRE_CASES = [
    (b'', ('PT-SECONDARY-INPUT', 'meta_missing')),
    (b'\x0a', ('PT-SECONDARY-INPUT', 'wire_truncated')),
    (META, ('PT-SECONDARY-INPUT', 'callgraph_missing')),
    (CG, ('PT-SECONDARY-INPUT', 'meta_missing')),
    (META + CG + b'\x00\x00', ('PT-SECONDARY-INPUT', 'wire_malformed')),            # field number 0
    (META + CG + b'\xff' * 10 + b'\x01', ('PT-SECONDARY-INPUT', 'wire_malformed')),  # 10-byte varint overflow
    (META + CG + b'\x4a' + b'\xff' * 9 + b'\x7f', ('PT-SECONDARY-INPUT', 'wire_malformed')),
    (META + CG + b'\x4a' + varint(2**63), ('PT-SECONDARY-LIMIT', 'record_too_large')),
    (META + CG + b'\x4a\x05ab', ('PT-SECONDARY-INPUT', 'wire_truncated')),
    (META + CG + b'\x4b', ('PT-SECONDARY-INPUT', 'group_wire_type')),                 # start group, field 9
    (META + CG + b'\x4c', ('PT-SECONDARY-INPUT', 'group_wire_type')),
    (META + CG + b'\x4e', ('PT-SECONDARY-INPUT', 'group_wire_type')),                 # wire type 6
    (META + CG + b'\x48\x01', ('PT-SECONDARY-INPUT', 'wire_type_mismatch')),          # field 9 as varint
    (META + CG + b'\x4d\x00\x00\x00\x00', ('PT-SECONDARY-INPUT', 'wire_type_mismatch')),
    (META + CG + b'\x49' + b'\x00' * 7, ('PT-SECONDARY-INPUT', 'wire_truncated')),
    (META + META + CG, ('PT-SECONDARY-INPUT', 'duplicate_singleton')),
    (META + CG + CG, ('PT-SECONDARY-INPUT', 'duplicate_singleton')),
    (META + CG + rec(99, b'x' * (64 * 1024)), ('PT-SECONDARY-INPUT', 'unknown_fields_excess')),
    (META + CG + rec(100000000, b'x' * (64 * 1024)), ('PT-SECONDARY-INPUT', 'unknown_fields_excess')),
]


# Explicit short ids: the default id embeds the bytes, and pytest copies the node id into PYTEST_CURRENT_TEST, which
# Windows rejects above 32767 characters (the 64 KiB cases failed at setup there).
@pytest.mark.parametrize('data, expected', WIRE_CASES,
                         ids=[f'{index:02d}-{case[1][1]}' for index, case in enumerate(WIRE_CASES)])
def test_wire_rejections(data, expected):
    assert reason(data) == expected


def test_unknown_fields_tolerated_up_to_cap_and_negative_varint():
    data = META + CG + rec(99, b'x' * 100) + varint(98 << 3) + varint(2**64 - 1)  # -1 as 10-byte varint
    assert scan(data).unknown_bytes == len(data) - len(META + CG)


def test_count_cap_names_table():
    caps = {'string_table': 2}
    assert reason(META + CG + rec(9, b'') * 3, max_counts=caps) == ('PT-SECONDARY-LIMIT', 'count_cap:string_table')
    scan(META + CG + rec(9, b'') * 2, max_counts=caps)
    assert reason(META + CG + rec(2, b'') * 2, max_counts={'expression': 1})[1] == 'count_cap:expression'


def test_record_cap_and_fields_cover_proto():
    assert reason(META + CG + rec(17, b'x' * 33), max_record_bytes=32) == ('PT-SECONDARY-LIMIT', 'record_too_large')
    assert sorted(KNOWN) == [*range(1, 18), 93992622]


def test_budget_cancel_and_deadline():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(SecondaryError) as info:
        prescan(memoryview(META + CG + rec(9, b'') * (TICK_EVERY + 1)), BinExportLimits(), Budget(None, cancel))
    assert (info.value.code, info.value.reason) == ('PT-SECONDARY-CANCEL', 'cancelled')
    with pytest.raises(SecondaryError) as info:
        Budget(deadline=0.0).check()
    assert (info.value.code, info.value.reason) == ('PT-SECONDARY-RUN', 'worker_timeout')
    Budget().tick(10**6)  # no deadline, no cancel: never raises


def test_limits_defaults_validation_and_json_round_trip():
    limits = BinExportLimits()
    assert limits.max_file_bytes == 256 * MIB and limits.max_record_bytes == 32 * MIB
    assert limits.cap('vertex') == 2_000_000 and limits.cap('mnemonic') == 65_536
    assert BinExportLimits(max_counts={'section': 1}).cap('library') == 4096  # partial override merges
    assert BinExportLimits.from_json(limits.to_json()) == limits
    for bad in ({'max_counts': {'bogus': 1}}, {'max_file_bytes': 0}, {'wall_seconds': 0}, {'max_expr_depth': True}):
        with pytest.raises(ValueError):
            BinExportLimits(**bad)
    with pytest.raises(ValueError):
        BinExportLimits.from_json({'nope': 1})
    assert memory_for(0) == memory_for(14 * MIB) == 512 * MIB  # floor
    assert memory_for(100 * MIB) == 14 * 100 * MIB + 256 * MIB
    assert memory_for(256 * MIB) < 6 * GIB and limits.memory_required(MIB) == memory_for(MIB)
    assert BinExportLimits(memory_bytes=123).memory_required(10**9) == 123
