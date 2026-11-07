"""SPEC-31 harness audit (card har): parity.py MD-index comparison follows 08 s1 G-U3 (functions with n_bb >= 5) and bounds
hostile dump lines."""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path[:0] = [str(TESTS.parent), str(TESTS.parent / 'src')]

from tools.unified import parity  # noqa: E402


def sidecar(path, rows):
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE fn (fid INTEGER PRIMARY KEY, rva INTEGER NOT NULL UNIQUE, n_bb INTEGER NOT NULL, '
               'md_td INTEGER, md_bu INTEGER)')
    db.executemany('INSERT INTO fn VALUES (?,?,?,?,?)', [(i, rva, n_bb, md, None) for i, (rva, n_bb, md) in enumerate(rows)])
    db.commit()
    db.close()
    return path


def test_the_md_comparison_reads_only_functions_with_five_or_more_blocks(tmp_path):
    path = sidecar(tmp_path / 'ir.sqlite3', [(0x1000, 4, 11), (0x1100, 5, 12), (0x1200, 9, 13), (0x1300, 1, 14)])
    assert parity.MD_MIN_BLOCKS == 5                                             # R02 s14 G1
    assert parity.read_ir_md(path, min_blocks=parity.MD_MIN_BLOCKS) == {0x1100: 12, 0x1200: 13}
    assert set(parity.read_ir_md(path)) == {0x1000, 0x1100, 0x1200, 0x1300}      # no filter by default (old callers)


def test_a_dump_line_with_an_enormous_number_is_unparsed_not_expanded():
    huge = '1' * 200_000
    started = time.monotonic()
    values, unparsed = parity.parse_md_dump(f'0x1000 0.{huge}\n0x1010 0.5\n0x1020 {huge}.5\n')
    assert values == {0x1010: '0.5'} and unparsed == 2
    assert time.monotonic() - started < 5


@pytest.mark.parametrize('text', ['0.123456789012', '12.5', '-0.000000000001'])
def test_ordinary_md_numbers_still_parse(text):
    assert parity.parse_md_dump(f'0x1000 {text}\n') == ({0x1000: text}, 0)
