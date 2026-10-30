"""QA-S2 unified store parts: 100k-row gzip parts written and read back through the shared line reader, framing and
truncation refusals, and the line cap on terminated lines. Synthetic records only, deterministic.
"""
from __future__ import annotations

import gzip
import os
from pathlib import Path

import pytest

from patchtrace.unified.store import LINE_MAX_BYTES, UnifiedError, part_lines, write_part

SCALE = int(os.environ.get('PATCHTRACE_STRESS_SCALE', '1'))


def _records(count: int):
    return ({'row': index, 'label': f'row-{index:07d}', 'flag': index % 3 == 0} for index in range(count))


def _gzip_bytes(path: Path, payload: bytes) -> None:
    with gzip.open(path, 'wb') as handle:
        handle.write(payload)


def test_hundred_thousand_rows_round_trip_through_one_part(tmp_path):
    count = 100_000 * SCALE
    part = write_part(tmp_path, 'facts.jsonl.gz', _records(count))
    assert part.records == count
    lines = list(part_lines(tmp_path / 'facts.jsonl.gz'))
    assert len(lines) == count
    assert lines[0].startswith(b'{"flag":true,"label":"row-0000000"') and lines[-1].endswith(b'}\n')


def test_part_digest_is_stable_across_writes(tmp_path):
    first_dir, second_dir = tmp_path / 'a', tmp_path / 'b'
    first_dir.mkdir()
    second_dir.mkdir()
    first = write_part(first_dir, 'rows.jsonl.gz', _records(5_000))
    second = write_part(second_dir, 'rows.jsonl.gz', _records(5_000))
    assert first.sha256 == second.sha256 and first.records == second.records == 5_000


def test_unterminated_final_line_is_refused_as_truncated(tmp_path):
    target = tmp_path / 'cut'
    _gzip_bytes(target, b'{"a":1}\n{"a":2}')
    with pytest.raises(UnifiedError) as info:
        list(part_lines(target))
    assert info.value.reason == 'part-truncated'


def test_corrupt_deflate_data_is_a_typed_unreadable_refusal(tmp_path):
    target = tmp_path / 'corrupt'
    target.write_bytes(b'\x1f\x8b\x08\x00' + b'\x00' * 6 + b'\xff' * 64)
    with pytest.raises(UnifiedError) as info:
        list(part_lines(target))
    assert info.value.reason in {'part-unreadable', 'part-truncated'}


def test_terminated_oversized_line_is_refused_by_the_reader(tmp_path):
    target = tmp_path / 'long'
    _gzip_bytes(target, b'{"x":"' + b'a' * (LINE_MAX_BYTES + 4096) + b'"}\n')
    with pytest.raises(UnifiedError) as info:
        list(part_lines(target))
    assert info.value.reason == 'line-too-long'


def test_many_lines_near_the_cap_are_each_yielded_once(tmp_path):
    body = b'{"x":"' + b'b' * 200_000 + b'"}\n'
    target = tmp_path / 'near'
    _gzip_bytes(target, body * (20 * SCALE))
    assert len(list(part_lines(target))) == 20 * SCALE
