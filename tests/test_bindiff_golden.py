"""SPEC-29 §9.3: committed SYNTHETIC `.BinDiff` golden (tools/make_bindiff_fixtures.py) and stdout golden.

These are not BinDiff output (see bindiff-synthetic.json); a live-produced v8 golden replaces them later.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.bindiff_run import parse_summary
from patchtrace.secondary.contracts import SecondaryError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'tests' / 'fixtures' / 'secondary'
GOLDEN = FIXTURES / 'bindiff-synthetic-pair.BinDiff'
RECORD = json.loads((FIXTURES / 'bindiff-synthetic.json').read_text(encoding='utf-8'))
sys.path.insert(0, str(ROOT / 'tools'))

import make_bindiff_fixtures  # noqa: E402


def content(match_set):
    return [m.model_dump() for m in match_set.matches], match_set.engine_version, match_set.limitations


def test_record_matches_committed_bytes_and_is_labelled_synthetic():
    assert hashlib.sha256(GOLDEN.read_bytes()).hexdigest() == RECORD['file_sha256']
    assert RECORD['synthetic'] is True and 'Not produced by BinDiff' in RECORD['note']
    assert GOLDEN.stat().st_size <= 200 * 1024


def test_golden_imports_to_expected_snapshot():
    result = import_bindiff(GOLDEN, RECORD['older_sha256'], RECORD['newer_sha256'])
    assert result.file_sha256 == RECORD['file_sha256']
    assert len(result.matches) == RECORD['functions'] == 5
    by_old = {m.older_address: m for m in result.matches}
    assert by_old[0x140001200].algorithm == 'function: edges flowgraph MD index'
    assert by_old[0x140001200].flags == ('G', 'I', 'C')
    assert by_old[0x140002000].older_name is None and by_old[0x140002000].confidence_milli == 400
    assert by_old[0x8000000000001000].newer_address == 0x8000000000001010  # signed BIGINT masked back
    assert {m.algorithm for m in result.matches} == {name for _, name in make_bindiff_fixtures.ALGORITHMS}


def test_regeneration_is_import_equal(tmp_path):
    record = make_bindiff_fixtures.generate(tmp_path)
    fresh = import_bindiff(tmp_path / record['file'], record['older_sha256'], record['newer_sha256'])
    committed = import_bindiff(GOLDEN, RECORD['older_sha256'], RECORD['newer_sha256'])
    assert content(fresh) == content(committed)


def test_golden_rejects_wrong_pair_and_orientation():
    with pytest.raises(SecondaryError) as info:
        import_bindiff(GOLDEN, RECORD['newer_sha256'], RECORD['older_sha256'])
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'


def test_stdout_golden_feeds_parse_summary():
    text = (FIXTURES / 'bindiff-synthetic-stdout.txt').read_text(encoding='utf-8')
    assert parse_summary(text) == {'matched': '5', 'primary_functions': '7', 'secondary_functions': '8',
                                   'similarity': '61.4', 'confidence': '83.7'}


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_header_and_schema_mutations_fail_cleanly(tmp_path_factory, data):
    blob = bytearray(GOLDEN.read_bytes())
    # Concentrate on the header and the first pages (sqlite_master, schema rows).
    for _ in range(data.draw(st.integers(1, 6))):
        blob[data.draw(st.integers(0, min(len(blob), 8192) - 1))] = data.draw(st.integers(0, 255))
    target = tmp_path_factory.mktemp('golden') / 'm.BinDiff'
    target.write_bytes(bytes(blob))
    try:
        import_bindiff(target, RECORD['older_sha256'], RECORD['newer_sha256'])
    except SecondaryError:
        pass
