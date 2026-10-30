"""Research report CLI destinations must not overwrite arbitrary caller-selected paths."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'docs/research/unified-matching-r2/results'


def _graph(destination):
    if sys.platform != 'linux':
        pytest.skip('graph benchmark uses Linux resource accounting')
    return subprocess.run([sys.executable, str(ROOT / 'tools/research/r2_graph_benchmark.py'),
                           '--mode', 'collision', '--n', '6', '--output', str(destination)],
                          cwd=ROOT, text=True, capture_output=True, timeout=20)


def _symlink(link, target, *, directory=False):
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError:
        pytest.skip('symlink creation unavailable')


def test_graph_cli_refuses_outside_existing_file(tmp_path):
    target = tmp_path / 'unrelated.json'
    target.write_text('preserve me', encoding='utf-8')
    result = _graph(target)
    assert result.returncode != 0
    assert target.read_text(encoding='utf-8') == 'preserve me'


def test_graph_cli_refuses_report_symlink_to_outside(tmp_path):
    target = tmp_path / 'unrelated.json'
    target.write_text('preserve me', encoding='utf-8')
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-path-regression-') as folder:
        link = Path(folder) / 'report.json'
        _symlink(link, target)
        result = _graph(link)
        assert result.returncode != 0
        assert target.read_text(encoding='utf-8') == 'preserve me'


def test_rizin_cli_error_path_preserves_existing_report_and_refuses_outside(tmp_path):
    command = [sys.executable, str(ROOT / 'tools/research/r2_rizin_probe.py'), '--rz-diff',
               str(tmp_path / 'missing-tool'), '--archive', str(tmp_path / 'missing-archive')]
    outside = tmp_path / 'outside.json'
    outside.write_text('preserve me', encoding='utf-8')
    result = subprocess.run([*command, '--output', str(outside)], capture_output=True, text=True, timeout=20)
    assert result.returncode != 0 and outside.read_text() == 'preserve me'
    with tempfile.TemporaryDirectory(dir=RESULTS, prefix='r2-path-regression-') as folder:
        existing = Path(folder) / 'existing.json'
        existing.write_text('{"preserved": true}', encoding='utf-8')
        result = subprocess.run([*command, '--output', str(existing)], capture_output=True, text=True, timeout=20)
        assert result.returncode != 0 and json.loads(existing.read_text()) == {'preserved': True}
        result = subprocess.run([*command, '--output', str(existing), '--append-orientation'],
                                capture_output=True, text=True, timeout=20)
        updated = json.loads(existing.read_text())
        assert result.returncode != 0 and updated['preserved'] is True and updated['status'] == 'failed'
        assert 'FileNotFoundError' in updated['fatal_error']


def test_helper_rejects_parent_traversal_even_if_normalized_inside(tmp_path):
    from tools.research.r2_paths import report_destination
    with pytest.raises(ValueError, match='parent'):
        report_destination('docs/research/unified-matching-r2/results/../results/report.json', checkout_root=tmp_path)


def test_helper_rejects_symlink_directory_and_nonregular_target(tmp_path):
    from tools.research.r2_paths import report_destination
    results = tmp_path / 'docs/research/unified-matching-r2/results'
    results.mkdir(parents=True)
    (results / 'directory.json').mkdir()
    with pytest.raises(ValueError, match='regular'):
        report_destination(results / 'directory.json', checkout_root=tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    _symlink(results / 'escape', outside, directory=True)
    with pytest.raises(ValueError, match='symlink'):
        report_destination(results / 'escape' / 'report.json', checkout_root=tmp_path)


def test_helper_default_preserves_existing_and_explicit_replace_is_atomic(tmp_path, monkeypatch):
    from tools.research import r2_paths
    target = tmp_path / 'docs/research/unified-matching-r2/results/nested/report.json'
    r2_paths.write_report_json(target, {'old': 1}, checkout_root=tmp_path)
    with pytest.raises(FileExistsError):
        r2_paths.write_report_json(target, {'new': 2}, checkout_root=tmp_path)
    assert json.loads(target.read_text()) == {'old': 1}
    real_replace = r2_paths.os.replace

    def fail_before_replace(source, destination):
        assert json.loads(target.read_text()) == {'old': 1}
        assert json.loads(Path(source).read_text()) == {'new': 2}
        raise OSError('simulated publication failure')

    monkeypatch.setattr(r2_paths.os, 'replace', fail_before_replace)
    with pytest.raises(OSError, match='publication'):
        r2_paths.write_report_json(target, {'new': 2}, checkout_root=tmp_path, replace=True)
    assert json.loads(target.read_text()) == {'old': 1}
    assert sorted(p.name for p in target.parent.iterdir()) == ['report.json']
    monkeypatch.setattr(r2_paths.os, 'replace', real_replace)
    r2_paths.write_report_json(target, {'new': 2}, checkout_root=tmp_path, replace=True)
    assert r2_paths.read_report_json(target, checkout_root=tmp_path) == {'new': 2}


def test_helper_accepts_only_checkout_results_and_checks_regular_inputs(tmp_path):
    from tools.research.r2_paths import regular_input, report_destination
    assert report_destination('docs/research/unified-matching-r2/results/new.json', checkout_root=tmp_path) == (
        tmp_path / 'docs/research/unified-matching-r2/results/new.json')
    with pytest.raises(ValueError, match='results'):
        report_destination(tmp_path / 'other.json', checkout_root=tmp_path)
    with pytest.raises(ValueError, match='regular'):
        regular_input(tmp_path, max_bytes=100)
    large = tmp_path / 'large.bin'
    large.write_bytes(b'12345')
    with pytest.raises(ValueError, match='size'):
        regular_input(large, max_bytes=4)
    assert regular_input(large, max_bytes=5) == large
    selected_link = tmp_path / 'explicit-input-link'
    _symlink(selected_link, large)
    assert regular_input(selected_link, max_bytes=5) == large


def test_new_report_publication_cannot_clobber_a_racing_writer(tmp_path, monkeypatch):
    from tools.research import r2_paths
    target = tmp_path / 'docs/research/unified-matching-r2/results/report.json'
    real_link = r2_paths.os.link

    def racing_link(source, destination):
        Path(destination).write_text('{"other_writer": true}', encoding='utf-8')
        real_link(source, destination)

    monkeypatch.setattr(r2_paths.os, 'link', racing_link)
    with pytest.raises(FileExistsError):
        r2_paths.write_report_json(target, {'ours': True}, checkout_root=tmp_path)
    assert json.loads(target.read_text()) == {'other_writer': True}
    assert sorted(p.name for p in target.parent.iterdir()) == ['report.json']
