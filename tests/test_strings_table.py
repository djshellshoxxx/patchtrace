"""strings-table/1: round trip, hostile sidecars, and the S0 gate (200k rows per side: load <= 4 s, <= 400 MiB)."""
from __future__ import annotations

import hashlib
import struct
import time
import tracemalloc

import pytest

from patchtrace.strings import contracts as c
from patchtrace.strings import limits
from patchtrace.strings.table import CONFIDENCE, ENCODINGS, FLAG_SECRET, MAGIC, TYPES, StringRow, StringTable

A, B, C = 'a' * 64, 'b' * 64, 'c' * 64
NONE = limits.NONE_U32


def make_basis(rows: int, side='older'):
    part = c.BasisPart(source='floss', semantics_id=c.STATIC_SEMANTICS_ID, run_id='r1', raw_sha256=B,
                       types=('static',), config_digest=C)
    return c.StringBasis(artifact_sha256=A, side=side, min_length=4, rows_seen=rows, rows_kept=rows,
                         stages={'static': c.StageState(state='complete')}, parts=(part,))


def row(i: int, **kw) -> StringRow:
    base = dict(value_sha256=hashlib.sha256(str(i).encode()).digest(), type=0, encoding=0, length=8 + i % 50,
                offset=i * 16, rva=0x1000 + i * 16, display=f'string number {i}')
    return StringRow(**{**base, **kw})


def table_of(n: int, **kw) -> StringTable:
    return StringTable.from_rows(make_basis(n), [row(i, **kw) for i in range(n)])


def test_round_trip_preserves_every_column():
    rows = [row(0), row(1, fn_rva=0x2000, site=0x2010, confidence=2, flags=FLAG_SECRET, fragment='part one'),
            row(2, type=3, encoding=1, offset=NONE, rva=NONE, display='\\x00 weird \\u202e')]
    table = StringTable.from_rows(make_basis(3), rows)
    back = StringTable.from_bytes(table.to_bytes())
    assert list(back) == rows and back.basis == table.basis and len(back) == 3
    assert back.to_bytes() == table.to_bytes()


def test_display_values_and_fragments_are_deduplicated():
    table = StringTable.from_rows(make_basis(3), [row(i, display='same', fragment='frag') for i in range(3)])
    assert table.displays == ['same'] and table.fragments == ['frag']


def test_empty_table_round_trips():
    table = StringTable.from_rows(make_basis(0), [])
    assert len(StringTable.from_bytes(table.to_bytes())) == 0


def test_row_index_bounds():
    with pytest.raises(IndexError):
        table_of(2).row(2)


@pytest.mark.parametrize('bad', [dict(value_sha256=b'short'), dict(type=len(TYPES)), dict(encoding=len(ENCODINGS)),
                                 dict(confidence=len(CONFIDENCE)), dict(flags=0x8000), dict(length=2**32),
                                 dict(offset=-1)],
                         ids=['hash', 'type', 'enc', 'conf', 'flags', 'length', 'negative'])
def test_builder_rejects_invalid_rows(bad):
    with pytest.raises(c.StringsError) as exc:
        StringTable.from_rows(make_basis(1), [row(0, **bad)])
    assert exc.value.code == 'PT-STR-INPUT'


def test_row_cap_is_enforced(monkeypatch):
    monkeypatch.setattr('patchtrace.strings.table.MAX_ROWS_PER_SIDE', 2)
    with pytest.raises(c.StringsError) as exc:
        table_of(3)
    assert exc.value.code == 'PT-STR-LIMIT'


def test_relocation_does_not_change_identity():
    a = table_of(5)
    b = StringTable.from_rows(make_basis(5), [row(i, offset=i * 16 + 4096, rva=0x9000 + i) for i in range(5)])
    assert [r.value_sha256 for r in a] == [r.value_sha256 for r in b]


@pytest.mark.parametrize('mutate', [
    lambda blob: b'XXXXXXXX' + blob[8:],
    lambda blob: blob[:-1],
    lambda blob: blob + b'\0',
    lambda blob: blob[:20],
    lambda blob: b'',
], ids=['magic', 'short', 'trailing', 'header', 'empty'])
def test_hostile_sidecars_are_refused(mutate):
    with pytest.raises(c.StringsError) as exc:
        StringTable.from_bytes(mutate(table_of(4).to_bytes()))
    assert exc.value.code == 'PT-STR-INPUT'


def test_out_of_range_codes_are_refused():
    blob = bytearray(table_of(2).to_bytes())
    columns_size = 2 * (1 + 1 + 1 + 2 + 7 * 4)  # type, enc, conf, flags, then seven u32 columns
    blob[len(blob) - columns_size] = 200  # first byte of the type column
    with pytest.raises(c.StringsError) as exc:
        StringTable.from_bytes(bytes(blob))
    assert exc.value.code == 'PT-STR-INPUT'


def test_declared_counts_beyond_limits_are_refused_before_reading():
    head = struct.pack('<8sIIII', MAGIC, 2, 10**9, 0, 0) + b'{}'
    with pytest.raises(c.StringsError) as exc:
        StringTable.from_bytes(head)
    assert exc.value.code == 'PT-STR-LIMIT'


def test_row_count_must_match_basis():
    mismatched = StringTable.from_rows(make_basis(2), [row(i) for i in range(3)])
    with pytest.raises(c.StringsError):
        StringTable.from_bytes(mismatched.to_bytes())


GATE_ROWS = 200_000


def test_gate_load_time_for_two_sides():
    blobs = [table_of(GATE_ROWS).to_bytes() for _ in range(2)]
    start = time.perf_counter()
    tables = [StringTable.from_bytes(blob) for blob in blobs]
    elapsed = time.perf_counter() - start
    assert all(len(t) == GATE_ROWS for t in tables)
    assert elapsed <= 4.0, f'loading two 200k-row sides took {elapsed:.2f}s'


def test_gate_load_memory_for_two_sides():
    blobs = [table_of(GATE_ROWS).to_bytes() for _ in range(2)]
    tracemalloc.start()
    try:
        tables = [StringTable.from_bytes(blob) for blob in blobs]
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(tables) == 2
    assert peak <= 400 * 1024 * 1024, f'peak {peak / 2**20:.0f} MiB'
