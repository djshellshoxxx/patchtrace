"""tier-r-bodies/1: deterministic per-lineage masked-body records (synthetic hashes, hermetic)."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import bodyrecord as BR  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402


def h(n: int) -> str:
    return hashlib.sha256(f'body-{n}'.encode()).hexdigest()


def test_record_is_sorted_unique_and_stable():
    a = BR.make_record('zlib', [h(3), h(1), h(3), h(2)])
    b = BR.make_record('zlib', [h(2), h(3), h(1)])
    assert a == b
    assert a['masked_sha256'] == sorted({h(1), h(2), h(3)})
    assert C.dump_json(a) == C.dump_json(b)


def test_from_hashed_uses_the_masked_hash():
    rec = BR.from_hashed('zlib', {0x1000: ('raw-a', h(1)), 0x2000: ('raw-b', h(1)), 0x3000: ('raw-c', h(2))})
    assert rec['masked_sha256'] == sorted({h(1), h(2)})


def test_write_is_lf_and_unions_existing(tmp_path):
    path = BR.write_record(tmp_path, 'zlib', [h(1)])
    BR.write_record(tmp_path, 'zlib', [h(2), h(1)])
    data = path.read_bytes()
    assert b'\r' not in data and data.endswith(b'\n')
    assert BR.load_record(data).masked_sha256 == tuple(sorted({h(1), h(2)}))
    assert path.name == 'zlib.bodies.json'


def test_load_folder_orders_by_lineage(tmp_path):
    for name, n in (('zstd', 2), ('brotli', 1)):
        BR.write_record(tmp_path, name, [h(n)])
    assert list(BR.load_folder(tmp_path)) == ['brotli', 'zstd']


@pytest.mark.parametrize('doc', [
    {'masked_sha256': []},
    {'masked_sha256': ['abc']},
    {'lineage': 'bad lineage'},
    {'extra': 1},
], ids=['empty', 'bad-hash', 'bad-lineage', 'extra-key'])
def test_invalid_records_are_rejected(doc):
    good = BR.make_record('zlib', [h(1)])
    bad = {**good, **doc}
    with pytest.raises(C.ContractError):
        BR.load_record(json.dumps(bad).encode())


def test_unsorted_hashes_rejected():
    good = BR.make_record('zlib', [h(1), h(2)])
    bad = {**good, 'masked_sha256': list(reversed(good['masked_sha256']))}
    with pytest.raises(C.ContractError):
        BR.load_record(json.dumps(bad).encode())


def test_edit_after_generation_fails_digest(tmp_path):
    path = BR.write_record(tmp_path, 'zlib', [h(1)])
    doc = json.loads(path.read_text(encoding='utf-8'))
    doc['masked_sha256'] = sorted([h(1), h(2)])
    path.write_text(json.dumps(doc), encoding='utf-8', newline='\n')
    with pytest.raises(C.ContractError, match='digest'):
        BR.load_folder(tmp_path)


def test_file_name_must_match_lineage(tmp_path):
    BR.write_record(tmp_path, 'zlib', [h(1)])
    (tmp_path / 'zlib.bodies.json').rename(tmp_path / 'other.bodies.json')
    with pytest.raises(C.ContractError, match='file name'):
        BR.load_folder(tmp_path)


def test_duplicate_key_json_rejected():
    with pytest.raises(C.ContractError):
        BR.load_record(b'{"contract": "tier-r-bodies/1", "contract": "x"}')
