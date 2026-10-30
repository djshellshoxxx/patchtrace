"""Research tools reject reused work roots and baseline-controlled path escapes.

These tests stop before metadata subprocesses or native analysis; filesystem setup
and replay case validation are real. No preserved native artifacts are accessed.
"""
from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_tool(name, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT))
    monkeypatch.syspath_prepend(str(ROOT / 'tools'))
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools/research' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AfterSetup(Exception):
    """The replay's first repository-metadata operation, beyond the setup under test."""


def invoke_setup(tool, name, work, tmp_path, monkeypatch, *, output=None):
    # Track environment/tempfile changes so a probe invocation cannot affect later tests.
    for key in ('TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'PYTHONDONTWRITEBYTECODE'):
        monkeypatch.setenv(key, os.environ.get(key, ''))
    monkeypatch.setattr(tempfile, 'tempdir', tempfile.tempdir)
    checkout = tmp_path / 'script-checkout'
    checkout.mkdir(exist_ok=True)
    monkeypatch.setattr(tool, 'ROOT', checkout, raising=False)
    if output is None:
        output = checkout / 'docs/research/unified-matching-r2/results/fresh.json'
    if name == 'r2_ghidra_probe':
        argv = [name, '--python', sys.executable, '--ghidra-dir', str(tmp_path / 'no-ghidra'),
                '--work', str(work), '--output', str(output)]
    else:
        baseline = tmp_path / 'baseline.json'
        preserved = tmp_path / 'preserved'
        preserved.mkdir(exist_ok=True)
        baseline.write_text(json.dumps({'cases': [], 'work_directory': str(preserved)}))

        def metadata_not_needed(_root):
            raise AfterSetup

        monkeypatch.setattr(tool, 'tree', metadata_not_needed)
        argv = [name, '--production-root', str(ROOT), '--baseline', str(baseline),
                '--preserved', str(preserved), '--work', str(work), '--output', str(output)]
    monkeypatch.setattr(sys, 'argv', argv)
    return output


@pytest.mark.parametrize('name', ['r2_ghidra_probe', 'r2_ghidra_replay'])
@pytest.mark.parametrize('kind', ['directory', 'symlink', 'dangling-symlink'])
def test_existing_or_symlink_work_root_is_rejected_without_writes(name, kind, tmp_path, monkeypatch):
    tool = load_tool(name, monkeypatch)
    work, target = tmp_path / 'work', tmp_path / 'target'
    if kind == 'directory':
        work.mkdir()
    else:
        if kind == 'symlink':
            target.mkdir()
        try:
            work.symlink_to(target, target_is_directory=True)
        except OSError:
            pytest.skip('directory symlinks unavailable on this platform')
    output = invoke_setup(tool, name, work, tmp_path, monkeypatch)
    with pytest.raises(FileExistsError):
        tool.main()
    assert not output.exists()
    if kind == 'directory':
        assert list(work.iterdir()) == []
    elif kind == 'symlink':
        assert work.is_symlink() and list(target.iterdir()) == []
    else:
        assert work.is_symlink() and not target.exists()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX private mode bits')
@pytest.mark.parametrize('name', ['r2_ghidra_probe', 'r2_ghidra_replay'])
def test_fresh_work_root_is_private_even_with_permissive_umask(name, tmp_path, monkeypatch):
    tool = load_tool(name, monkeypatch)
    work = tmp_path / 'fresh'
    invoke_setup(tool, name, work, tmp_path, monkeypatch)
    previous = os.umask(0)
    try:
        with pytest.raises((AfterSetup, FileNotFoundError)):
            tool.main()
    finally:
        os.umask(previous)
    assert work.is_dir() and stat.S_IMODE(work.stat().st_mode) == 0o700


@pytest.mark.parametrize('kind', ['../escape', '/absolute-escape', r'C:\absolute-escape',
                                'nested/case', '.', '', 'unknown', None])
def test_replay_rejects_invalid_case_before_any_input_or_output_join(kind, monkeypatch):
    tool = load_tool('r2_ghidra_replay', monkeypatch)

    class NoPathAccess:
        def __truediv__(self, _part):
            raise AssertionError('invalid baseline case reached a filesystem path join')

    with pytest.raises(ValueError, match='case kind'):
        tool.replay({'kind': kind}, NoPathAccess(), NoPathAccess())


@pytest.mark.parametrize('kind', ['constant-changed', 'condition-changed', 'added-check', 'moved', 'split', 'merged'])
def test_replay_accepts_known_case_then_checks_its_preserved_inputs(kind, tmp_path, monkeypatch):
    tool = load_tool('r2_ghidra_replay', monkeypatch)
    with pytest.raises(FileNotFoundError):
        tool.replay({'kind': kind}, tmp_path / 'missing-inputs', tmp_path / 'fresh-output')
    assert not (tmp_path / 'fresh-output').exists()


@pytest.mark.parametrize('name', ['r2_ghidra_probe', 'r2_ghidra_replay'])
@pytest.mark.parametrize('destination', ['outside', 'existing', 'production-checkout'])
def test_report_preflight_preserves_targets_and_stops_before_work_or_metadata(
        name, destination, tmp_path, monkeypatch):
    tool = load_tool(name, monkeypatch)
    work = tmp_path / 'fresh-work'
    if destination == 'outside':
        target = tmp_path / 'outside.json'
    elif destination == 'existing':
        target = tmp_path / 'script-checkout/docs/research/unified-matching-r2/results/prior.json'
    else:
        # A caller-selected production checkout must not become the report boundary.
        target = ROOT / 'docs/research/unified-matching-r2/results/should-not-be-written.json'
    if destination != 'production-checkout':
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b'preserve prior evidence')
    invoke_setup(tool, name, work, tmp_path, monkeypatch, output=target)
    expected = FileExistsError if destination == 'existing' else ValueError
    with pytest.raises(expected):
        tool.main()
    assert not work.exists()
    if destination != 'production-checkout':
        assert target.read_bytes() == b'preserve prior evidence'
    else:
        assert not target.exists()


def test_probe_checkpoints_update_only_the_report_created_by_this_run(tmp_path, monkeypatch):
    tool = load_tool('r2_ghidra_probe', monkeypatch)
    work = tmp_path / 'fresh-work'
    target = invoke_setup(tool, 'r2_ghidra_probe', work, tmp_path, monkeypatch)
    properties = tmp_path / 'no-ghidra/Ghidra/application.properties'
    properties.parent.mkdir(parents=True)
    properties.write_text('application.version=test\n')
    monkeypatch.setattr(sys, 'argv', [*sys.argv, '--kinds', 'constant-changed,condition-changed'])
    monkeypatch.setattr(tool.importlib.metadata, 'version', lambda _name: 'test')
    monkeypatch.setattr(tool.subprocess, 'check_output', lambda *_args, **_kwargs: 'test-commit')
    monkeypatch.setattr(tool.subprocess, 'run', lambda *_args, **_kwargs: SimpleNamespace(stderr='test-java'))

    def native_analysis_not_needed(kind, _backend, _work):
        # Observe real report writes at the native-work boundary, without executing a target/tool.
        previous = json.loads(target.read_text())
        expected = [] if kind == 'constant-changed' else ['constant-changed']
        assert [c['kind'] for c in previous['cases']] == expected
        return {'kind': kind, 'status': 'complete'}

    monkeypatch.setattr(tool, 'probe_pair', native_analysis_not_needed)
    tool.main()
    saved = json.loads(target.read_text())
    assert [c['kind'] for c in saved['cases']] == ['constant-changed', 'condition-changed']
    assert saved['status'] == 'finished'
    assert [p.name for p in target.parent.iterdir()] == ['fresh.json']


def test_replay_creates_one_final_report_in_script_checkout(tmp_path, monkeypatch):
    tool = load_tool('r2_ghidra_replay', monkeypatch)
    target = invoke_setup(tool, 'r2_ghidra_replay', tmp_path / 'fresh-work', tmp_path, monkeypatch)
    monkeypatch.setattr(tool.compute, 'MATCH_POLICY_VERSION', 'matching/test', raising=False)

    def metadata_without_subprocesses(_root):
        assert not target.exists()  # replay publishes only after all work/metadata completes
        return {'production_source_sha256': {}}

    monkeypatch.setattr(tool, 'tree', metadata_without_subprocesses)
    tool.main()
    saved = json.loads(target.read_text())
    assert saved['cases'] == [] and not saved['native_extraction_repeated']
    assert saved['production_source_hashes_unchanged_during_replay']
    assert target.is_relative_to(tool.ROOT) and not target.is_relative_to(ROOT)
