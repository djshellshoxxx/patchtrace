"""Replay binds actual verified inputs to baseline identities before matching."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import struct
import sys
from pathlib import Path

import pytest
from unified_facts_builder import SIZE, build_reader, function

from patchtrace.sample import synthetic_pe

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def tool(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    spec = importlib.util.spec_from_file_location('replay_under_test', ROOT / 'tools/research/r2_ghidra_replay.py')
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


@pytest.fixture
def preserved_case(tmp_path):
    preserved = tmp_path / 'preserved'
    case_dir = preserved / 'moved'
    case_dir.mkdir(parents=True)
    shas, refs = {}, {}
    for variant, label in enumerate(('older', 'newer')):
        image = bytearray(synthetic_pe(variant))
        struct.pack_into('<I', image, 0x98 + 56, SIZE)
        path = case_dir / f'{label}.dll'
        path.write_bytes(image)
        shas[label] = hashlib.sha256(image).hexdigest()
        reader = build_reader(tmp_path, label, [function(0x1000, [('ret',)], name='f')], sha=shas[label])
        try:
            manifest = reader.manifest
            refs['ir_' + label] = {'ir_key': manifest.ir_key, 'content_digest': manifest.content_digest}
            shutil.copytree(reader.directory, case_dir / f'{label}-1-ir')
        finally:
            reader.close()
    baseline = {'kind': 'moved', 'artifact_sha256': shas, 'truth': [], 'symbol_visibility': 'synthetic unit fixture',
                'compute': {'manifest': {**refs, 'older_sha256': shas['older'], 'newer_sha256': shas['newer'],
                            'created_utc': '2026-10-30T00:00:00+00:00', 'config_digest': '1' * 64,
                            'result_id': '2' * 64, 'limitations': []},
                            'decision_counts': {}, 'materiality_counts': {}, 'rows': []}}
    work = tmp_path / 'work'
    work.mkdir()
    return preserved, baseline, work


@pytest.mark.parametrize('mutation', ['artifact', 'baseline-artifact', 'ir-key', 'ir-content', 'ir-artifact'])
def test_mismatched_baseline_or_ir_identity_never_reaches_compute(tool, preserved_case, tmp_path, monkeypatch, mutation):
    preserved, case, work = preserved_case
    case = copy.deepcopy(case)
    if mutation == 'artifact':
        case['artifact_sha256']['older'] = 'f' * 64
    elif mutation == 'baseline-artifact':
        case['compute']['manifest']['older_sha256'] = 'f' * 64
    elif mutation == 'ir-key':
        case['compute']['manifest']['ir_older']['ir_key'] = 'f' * 64
    elif mutation == 'ir-content':
        case['compute']['manifest']['ir_older']['content_digest'] = 'f' * 64
    else:
        wrong = build_reader(tmp_path, 'foreign', [function(0x1000, [('ret',)], name='f')], sha='f' * 64)
        try:
            dest = preserved / 'moved/older-1-ir'
            shutil.rmtree(dest)
            shutil.copytree(wrong.directory, dest)
            # Even a self-consistent claimed key/content cannot bind a foreign IR to this DLL.
            case['compute']['manifest']['ir_older'].update(ir_key=wrong.manifest.ir_key,
                                                          content_digest=wrong.manifest.content_digest)
        finally:
            wrong.close()
    reached = []

    def forbidden_compute(*_args, **_kwargs):
        reached.append(True)
        raise AssertionError('matching/compute reached before provenance validation')

    monkeypatch.setattr(tool.compute, 'compute_result', forbidden_compute)
    result = tool.replay(case, preserved, work)
    assert result['status'] == 'error'
    assert not reached
    assert 'identity' in result['error']['message'].lower()
    assert not list(work.iterdir())


def test_valid_verified_inputs_can_be_replayed_without_native_analysis(tool, preserved_case):
    preserved, case, work = preserved_case
    result = tool.replay(case, preserved, work)
    assert result['status'] == 'complete' and result['original_inputs_unchanged']
    assert result['comparison']['ir_older_content_digest_equal']
    assert result['comparison']['ir_newer_content_digest_equal']


def test_digest_rejects_directory_and_oversize_regular_input(tool, tmp_path):
    with pytest.raises(ValueError, match='regular'):
        tool.digest(tmp_path)
    large = tmp_path / 'large'
    large.write_bytes(b'12345')
    with pytest.raises(ValueError, match='size'):
        tool.digest(large, max_bytes=4)


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='FIFO creation unavailable')
def test_digest_rejects_fifo_without_blocking(tool, tmp_path):
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match='regular'):
        tool.digest(fifo)


def test_replay_uses_explicit_preserved_input_not_baseline_path(tool, tmp_path, monkeypatch):
    selected = tmp_path / 'selected-input'
    selected.mkdir()
    untrusted = tmp_path / 'must-not-be-followed'
    baseline = tmp_path / 'baseline.json'
    original = json.dumps({'work_directory': str(untrusted), 'cases': [{'kind': 'moved'}]}).encode()
    baseline.write_bytes(original)
    checkout = tmp_path / 'report-checkout'
    checkout.mkdir()
    monkeypatch.setattr(tool, 'ROOT', checkout)
    monkeypatch.setattr(tool, 'tree', lambda _root: {'production_source_sha256': {}})
    seen = []

    def observed_replay(case, preserved, _work):
        seen.append(preserved)
        return {'kind': case['kind'], 'status': 'complete', 'original_inputs_unchanged': True}

    monkeypatch.setattr(tool, 'replay', observed_replay)
    output = checkout / 'docs/research/unified-matching-r2/results/replay.json'
    monkeypatch.setattr(sys, 'argv', ['replay', '--production-root', str(ROOT), '--baseline', str(baseline),
        '--preserved', str(selected), '--work', str(tmp_path / 'fresh-work'), '--output', str(output)])
    tool.main()
    assert seen == [selected.resolve()]
    report = json.loads(output.read_bytes())
    assert report['baseline_declared_work_directory'] == str(untrusted)
    assert report['preserved_native_inputs'] == str(selected.resolve())
    assert baseline.read_bytes() == original and not untrusted.exists()


def test_baseline_reader_is_bounded_and_requires_a_case_list(tool, tmp_path, monkeypatch):
    baseline = tmp_path / 'baseline.json'
    baseline.write_bytes(b'{}')
    with pytest.raises(ValueError, match='case list'):
        tool.read_baseline(baseline)
    baseline.write_bytes(b'123456789')
    monkeypatch.setattr(tool, 'MAX_BASELINE_BYTES', 8)
    with pytest.raises(ValueError, match='size'):
        tool.read_baseline(baseline)
