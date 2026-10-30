"""R1: one artifact can have several build recipes; preserve every observed receipt."""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from tools.calibration.tier_r import build as B


def record(opt: str) -> dict:
    return {'contract': 'tier-r-build/1', 'project': 'r1-fixture',
            'debug_sha256': 'd' * 64, 'sha256': 'e' * 64, 'pdb_sha256': None,
            'output': 'fixture.dll', 'recipe': {'opt': opt},
            'recipe_digest': hashlib.sha256(opt.encode()).hexdigest(),
            'source_digest': 'a' * 64, 'inputs': {'f.c': 'b' * 64}}


def test_distinct_recipes_for_one_artifact_retain_both_receipts(tmp_path):
    older, newer = record('O2'), record('O3')
    a = B.persist_build_record(tmp_path, older)
    b = B.persist_build_record(tmp_path, newer)

    assert a != b
    assert a.parent == b.parent == tmp_path / 'builds'
    assert json.loads(a.read_bytes()) == older
    assert json.loads(b.read_bytes()) == newer
    assert a.stem == hashlib.sha256(a.read_bytes()).hexdigest()
    assert b.stem == hashlib.sha256(b.read_bytes()).hexdigest()
    assert json.loads((tmp_path / 'build.json').read_bytes()) == newer


def test_equal_rebuild_is_idempotent_without_rewriting_immutable_record(tmp_path):
    first = B.persist_build_record(tmp_path, record('O2'))
    os.utime(first, ns=(1_000_000_000, 1_000_000_000))
    before = first.stat().st_mtime_ns

    repeated = B.persist_build_record(tmp_path, record('O2'))

    assert repeated == first
    assert first.stat().st_mtime_ns == before
    assert list((tmp_path / 'builds').iterdir()) == [first]


def test_tampered_existing_receipt_fails_and_preserves_legacy_record(tmp_path):
    receipt = B.persist_build_record(tmp_path, record('O2'))
    B.persist_build_record(tmp_path, record('O3'))
    legacy = (tmp_path / 'build.json').read_bytes()
    receipt.write_bytes(b'{"tampered":true}\n')

    with pytest.raises(B.BuildError, match='receipt'):
        B.persist_build_record(tmp_path, record('O2'))

    assert receipt.read_bytes() == b'{"tampered":true}\n'
    assert (tmp_path / 'build.json').read_bytes() == legacy


def test_observing_new_build_does_not_invent_receipt_for_legacy_history(tmp_path):
    (tmp_path / 'build.json').write_text(json.dumps(record('O0')), encoding='utf-8')

    observed = B.persist_build_record(tmp_path, record('O2'))

    assert list((tmp_path / 'builds').iterdir()) == [observed]
    assert json.loads(observed.read_bytes())['recipe']['opt'] == 'O2'
