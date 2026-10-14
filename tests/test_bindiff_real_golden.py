"""Importer regression against a database written by the REAL BinDiff 8 (SPEC-29 §9.3).

`bindiff-v8-real-on-synthetic.BinDiff` was produced by the real v8 CLI from the synthetic pair of
tests/bindiff_live_pair.py (provenance JSON next to it). It shows what genuine v8 output looks like to the
hardened importer; it is not real-driver evidence (the inputs are synthetic).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from bindiff_live_pair import write_pair
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.bindiff_run import parse_summary
from patchtrace.secondary.contracts import SecondaryError

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'secondary'
GOLDEN = FIXTURES / 'bindiff-v8-real-on-synthetic.BinDiff'
RECORD = json.loads((FIXTURES / 'bindiff-v8-real-on-synthetic.json').read_text(encoding='utf-8'))
OLD, NEW = RECORD['inputs']['older_sha256'], RECORD['inputs']['newer_sha256']


def test_golden_matches_its_provenance_and_reproducible_inputs(tmp_path):
    assert hashlib.sha256(GOLDEN.read_bytes()).hexdigest() == RECORD['sha256']
    assert GOLDEN.stat().st_size == RECORD['size'] <= 200 * 1024
    stdout = (FIXTURES / RECORD['stdout_file']).read_bytes()
    assert hashlib.sha256(stdout).hexdigest() == RECORD['stdout_sha256']
    pair = write_pair(tmp_path)  # the deterministic encoder still produces the recorded inputs
    assert pair.older.summary.file_sha256 == RECORD['inputs']['older_binexport_sha256']
    assert pair.newer.summary.file_sha256 == RECORD['inputs']['newer_binexport_sha256']
    assert (pair.older_sha256, pair.newer_sha256) == (OLD, NEW)


def test_real_v8_database_imports_with_patched_functions_flagged():
    result = import_bindiff(GOLDEN, OLD, NEW)
    assert result.engine_version == '8 (@568181968, Sep 25 2023)' == RECORD['tool_version'][len('BinDiff '):]
    assert (result.older_sha256, result.newer_sha256, result.file_sha256) == (OLD, NEW, RECORD['sha256'])
    assert len(result.matches) == 20 and {m.algorithm for m in result.matches} == {'function: name hash matching'}
    changed = {m.older_address: (m.similarity_milli, m.flags) for m in result.matches if m.similarity_milli < 1000}
    assert changed == {0x180001300: (945, ('I', 'E')), 0x180001700: (853, ('G', 'E'))}  # the two patched functions
    assert all(m.older_address == m.newer_address and m.older_name == m.newer_name for m in result.matches)
    with pytest.raises(SecondaryError) as info:
        import_bindiff(GOLDEN, NEW, OLD)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'


def test_real_v8_schema_has_seven_tables_and_autoindexes_only(tmp_path):
    copy = tmp_path / 'copy.BinDiff'
    copy.write_bytes(GOLDEN.read_bytes())
    db = sqlite3.connect(f'{copy.as_uri()}?mode=ro&immutable=1', uri=True)
    rows = db.execute('SELECT type, name FROM sqlite_master').fetchall()
    db.close()
    assert sorted(name for kind, name in rows if kind == 'table') == sorted(
        ['basicblockalgorithm', 'functionalgorithm', 'file', 'metadata', 'function', 'basicblock', 'instruction'])
    assert all(kind == 'table' or name.startswith('sqlite_autoindex_') for kind, name in rows)


def test_real_v8_stdout_summary():
    text = (FIXTURES / RECORD['stdout_file']).read_text(encoding='utf-8')
    assert parse_summary(text) == {'matched': '20', 'primary_functions': '20', 'secondary_functions': '21',
                                   'similarity': '97.1948', 'confidence': '99.2608'}


@settings(max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_mutated_real_database_only_raises_secondary_error(tmp_path_factory, data):
    blob = bytearray(GOLDEN.read_bytes())
    for _ in range(data.draw(st.integers(1, 6))):
        blob[data.draw(st.integers(0, len(blob) - 1))] = data.draw(st.integers(0, 255))
    target = tmp_path_factory.mktemp('real-fuzz') / 'm.BinDiff'
    target.write_bytes(bytes(blob))
    try:
        import_bindiff(target, OLD, NEW)
    except SecondaryError:
        pass
