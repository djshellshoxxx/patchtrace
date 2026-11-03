"""R1: one artifact can have several build recipes; preserve every observed receipt."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

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


@pytest.mark.parametrize(('code', 'reason'), [
    (errno.EOPNOTSUPP, 'hard links unsupported'),
    (errno.EACCES, 'hard links denied'),
], ids=['unsupported-filesystem', 'permission-denied'])
def test_failed_atomic_publication_preserves_existing_provenance(tmp_path, monkeypatch, code, reason):
    original = B.persist_build_record(tmp_path, record('O2'))
    legacy = (tmp_path / 'build.json').read_bytes()

    def unavailable(*_args, **_kwargs):
        raise OSError(code, reason)

    monkeypatch.setattr(B.os, 'link', unavailable)
    with pytest.raises(B.BuildError, match=reason):
        B.persist_build_record(tmp_path, record('O3'))

    assert (tmp_path / 'build.json').read_bytes() == legacy
    assert list((tmp_path / 'builds').iterdir()) == [original]
    assert json.loads(original.read_bytes()) == record('O2')


def test_publication_exposes_complete_bytes_and_refuses_late_collision(tmp_path, monkeypatch):
    original = B.persist_build_record(tmp_path, record('O2'))
    legacy = (tmp_path / 'build.json').read_bytes()
    seen = []

    def competing_link(staged, target):
        data = Path(staged).read_bytes()
        assert json.loads(data) == record('O3')
        assert Path(target).stem == hashlib.sha256(data).hexdigest()
        Path(target).write_bytes(b'competing receipt')
        seen.append(Path(target))
        raise FileExistsError('late collision')

    monkeypatch.setattr(B.os, 'link', competing_link)
    with pytest.raises(B.BuildError, match='integrity mismatch'):
        B.persist_build_record(tmp_path, record('O3'))

    assert seen[0].read_bytes() == b'competing receipt'
    assert json.loads(original.read_bytes()) == record('O2')
    assert (tmp_path / 'build.json').read_bytes() == legacy
    assert sorted(p.name for p in (tmp_path / 'builds').iterdir()) == sorted([original.name, seen[0].name])


def test_compatibility_view_failure_keeps_published_full_receipt(tmp_path, monkeypatch):
    original = B.persist_build_record(tmp_path, record('O2'))
    legacy = (tmp_path / 'build.json').read_bytes()
    write_bytes = Path.write_bytes

    def fail_view(path, data):
        if path == tmp_path / 'build.json':
            raise PermissionError('compatibility view denied')
        return write_bytes(path, data)

    monkeypatch.setattr(Path, 'write_bytes', fail_view)
    with pytest.raises(PermissionError, match='compatibility view denied'):
        B.persist_build_record(tmp_path, record('O3'))

    retained = list((tmp_path / 'builds').iterdir())
    assert len(retained) == 2
    assert {json.loads(p.read_bytes())['recipe']['opt'] for p in retained} == {'O2', 'O3'}
    assert original in retained
    assert (tmp_path / 'build.json').read_bytes() == legacy
