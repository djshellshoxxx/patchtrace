"""cJSON runner preflight rejects destructive paths before any native analysis."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'docs/research/unified-matching-r2/results'
SCRIPT = ROOT / 'tools/research/r2_cjson_probe.py'


def _run(output, work, selected_root):
    missing = selected_root / 'nonexistent-native-input'
    return subprocess.run([sys.executable, str(SCRIPT), '--production-root', str(selected_root),
                           '--pilot-store', str(missing), '--ghidra-dir', str(missing),
                           '--rz-diff', str(missing), '--acceptance', str(missing),
                           '--work', str(work), '--output', str(output)],
                          capture_output=True, text=True, timeout=20)


def _symlink(link, target):
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError:
        pytest.skip('symlink creation unavailable')


def test_output_boundary_is_script_checkout_not_selected_production_root(tmp_path):
    # Choosing another production root must not authorize writes under its results-shaped subtree.
    selected_root = tmp_path / 'selected-source'
    output = selected_root / 'docs/research/unified-matching-r2/results/prior.json'
    output.parent.mkdir(parents=True)
    original = b'{"prior": "preserve exactly"}\n'
    output.write_bytes(original)
    work = tmp_path / 'fresh-work'
    result = _run(output, work, selected_root)
    assert result.returncode != 0 and 'checkout results' in result.stderr
    assert output.read_bytes() == original
    assert not work.exists()


def test_reused_output_is_refused_before_work_creation_or_native_metadata(tmp_path):
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-cjson-preflight-') as folder:
        output = Path(folder) / 'prior.json'
        original = b'{"receipt": [1, 2, 3]}\n'
        output.write_bytes(original)
        work = tmp_path / 'fresh-work'
        result = _run(output, work, tmp_path)
        assert result.returncode != 0 and 'report already exists' in result.stderr
        assert output.read_bytes() == original and not work.exists()


@pytest.mark.parametrize('symlink', [False, True])
def test_existing_or_symlink_work_root_is_refused_without_report_or_mutation(tmp_path, symlink):
    target = tmp_path / 'existing'
    target.mkdir()
    sentinel = target / 'previous-work.txt'
    sentinel.write_bytes(b'keep')
    work = tmp_path / 'work-link' if symlink else target
    if symlink:
        _symlink(work, target)
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-cjson-preflight-') as folder:
        output = Path(folder) / 'fresh.json'
        result = _run(output, work, tmp_path)
        assert result.returncode != 0 and 'FileExistsError' in result.stderr
        assert not output.exists()
    assert sentinel.read_bytes() == b'keep'
    assert set(target.iterdir()) == {sentinel}
    if symlink:
        assert work.is_symlink()


def test_report_symlink_preserves_external_target_and_does_not_create_work(tmp_path):
    prior = tmp_path / 'prior.json'
    prior.write_bytes(b'{"unrelated": true}\n')
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-cjson-preflight-') as folder:
        output = Path(folder) / 'linked.json'
        _symlink(output, prior)
        work = tmp_path / 'fresh-work'
        result = _run(output, work, tmp_path)
        assert result.returncode != 0 and 'symlink' in result.stderr
        assert json.loads(prior.read_bytes()) == {'unrelated': True}
        assert not work.exists()


def test_work_preflight_does_not_create_missing_parent_directories(tmp_path):
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-cjson-preflight-') as folder:
        output = Path(folder) / 'fresh.json'
        parent = tmp_path / 'missing-parent'
        result = _run(output, parent / 'work', tmp_path)
        assert result.returncode != 0 and 'FileNotFoundError' in result.stderr
        assert not parent.exists() and not output.exists()


def test_fresh_private_work_and_initial_report_exist_before_native_metadata(tmp_path):
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-cjson-preflight-') as folder:
        output = Path(folder) / 'fresh.json'
        work = tmp_path / 'fresh-work'
        # Missing production source deliberately blocks import/metadata; no tool path is usable.
        result = _run(output, work, tmp_path / 'missing-production-source')
        assert result.returncode != 0
        initial = json.loads(output.read_bytes())
        assert initial['status'] == 'preflight'
        assert initial['work_directory'] == str(work.absolute())
        assert work.is_dir() and not work.is_symlink()
        if os.name == 'posix':
            assert work.stat().st_mode & 0o777 == 0o700
