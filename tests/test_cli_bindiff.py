"""SPEC-29 §8 CLI: `secondary run --engine bindiff` with a fake `bindiff` and a fake C3 acceptor (mocked)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from fake_bindiff import launcher_names, make_fake_bindiff, spy_calls, write_fake_binexport

from patchtrace import cli
from patchtrace.secondary import bindiff_probe, cli_bindiff
from patchtrace.service import ProjectService

REAL_C3_ACCEPTOR = cli_bindiff.c3_acceptor


@dataclass(frozen=True)
class Summary:
    file_sha256: str
    executable_id: str
    id_binding: str


@dataclass(frozen=True)
class Accepted:
    snapshot_path: Path
    summary: Summary


def fake_acceptor_factory(private_dir: Path):
    def accept(path: Path, *, artifact_sha256, role, accept_unbound, cancel, other_sha256=None):
        data = Path(path).read_bytes()
        ident = data.split(b'\n', 1)[0].split()[1].decode()
        return Accepted(Path(path), Summary(hashlib.sha256(data).hexdigest(), ident,
                                            'sha256' if len(ident) == 64 else 'other'))
    return accept


@pytest.fixture(autouse=True)
def _setup(monkeypatch):
    bindiff_probe.clear_probe_cache()
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    monkeypatch.setattr(cli_bindiff, 'c3_acceptor', fake_acceptor_factory)
    monkeypatch.delenv('PATCHTRACE_BINDIFF', raising=False)
    yield
    bindiff_probe.clear_probe_cache()


@pytest.fixture
def project(tmp_path):
    service = ProjectService.sample(tmp_path / 'case')
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    root = service.root
    service.close()
    return root, sides


def inputs(tmp_path: Path, sides: dict, swap: bool = False) -> list[str]:
    older = write_fake_binexport(tmp_path / 'older.BinExport', sides['newer' if swap else 'older'])
    newer = write_fake_binexport(tmp_path / 'newer.BinExport', sides['older' if swap else 'newer'])
    return ['--older-binexport', str(older), '--newer-binexport', str(newer)]


def run_cli(root, *extra, capsys):
    code = cli.main(['secondary', 'run', str(root), '--json', '--engine', 'bindiff', *extra])
    return code, json.loads(capsys.readouterr().out)


def test_bindiff_run_stores_set_then_caches_and_reconciles(project, tmp_path, capsys):
    root, sides = project
    exe = make_fake_bindiff(tmp_path / 'bd')
    code, doc = run_cli(root, '--bindiff', str(exe), *inputs(tmp_path, sides), capsys=capsys)
    assert code == 0 and doc['status'] == 'complete', doc
    [row] = doc['result']['runs']
    assert row['engine'] == 'bindiff' and row['status'] == 'ok' and row['matches'] == 2
    kept = list((root / 'runs').rglob('raw/secondary/bindiff-*.BinDiff'))
    assert len(kept) == 1
    code, doc = run_cli(root, '--bindiff', str(exe), *inputs(tmp_path, sides), capsys=capsys)
    assert code == 0 and doc['result']['runs'][0]['status'] == 'cached'
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    assert [r['engine'] for r in json.loads(capsys.readouterr().out)['result']['reports']] == ['bindiff']


def test_env_variable_configures_executable(project, tmp_path, capsys, monkeypatch):
    root, sides = project
    monkeypatch.setenv('PATCHTRACE_BINDIFF', str(make_fake_bindiff(tmp_path / 'bd')))
    code, doc = run_cli(root, *inputs(tmp_path, sides), capsys=capsys)
    assert code == 0 and doc['result']['runs'][0]['status'] == 'ok'


def test_swapped_binexports_exit_2_without_spawn(project, tmp_path, capsys):
    root, sides = project
    exe = make_fake_bindiff(tmp_path / 'bd')
    code, doc = run_cli(root, '--bindiff', str(exe), *inputs(tmp_path, sides, swap=True), capsys=capsys)
    assert code == 2 and doc['result']['runs'][0]['error_code'] == 'PT-SECONDARY-ORIENTATION'
    assert [c['argv'] for c in spy_calls(tmp_path / 'bd')] == [['--version'], ['--nologo', '--help']]


def test_failed_rerun_keeps_previous_set_and_exits_3(project, tmp_path, capsys):
    root, sides = project
    code, _ = run_cli(root, '--bindiff', str(make_fake_bindiff(tmp_path / 'ok')), *inputs(tmp_path, sides),
                      capsys=capsys)
    assert code == 0
    code, doc = run_cli(root, '--bindiff', str(make_fake_bindiff(tmp_path / 'bad', 'exit-1-error')), '--no-cache',
                        *inputs(tmp_path, sides), capsys=capsys)
    assert code == 3 and doc['result']['runs'][0]['error_code'] == 'PT-SECONDARY-RUN'
    assert cli.main(['secondary', 'reconcile', str(root), '--json']) == 0
    report = json.loads(capsys.readouterr().out)['result']['reports'][0]
    assert report['engine'] == 'bindiff' and sum(report['counts'].values()) >= 1


def test_without_c3_acceptor_bindiff_is_unsupported(project, tmp_path, capsys, monkeypatch):
    root, sides = project
    monkeypatch.setattr(cli_bindiff, 'c3_acceptor', lambda private_dir: None)
    code, doc = run_cli(root, '--bindiff', str(make_fake_bindiff(tmp_path / 'bd')), *inputs(tmp_path, sides),
                        capsys=capsys)
    assert code == 2 and doc['result']['runs'][0]['status'] == 'unsupported'


def test_missing_inputs_and_unconfigured_exit_2(project, tmp_path, capsys):
    root, _ = project
    code, doc = run_cli(root, '--bindiff', str(make_fake_bindiff(tmp_path / 'bd')), capsys=capsys)
    assert code == 2 and doc['result']['runs'][0]['status'] == 'unsupported'
    code, doc = run_cli(root, capsys=capsys)
    assert code == 2 and doc['result']['runs'][0]['status'] == 'unsupported'


def test_real_c3_acceptor_wrapper_matches_module_presence(tmp_path):
    import importlib.util
    present = importlib.util.find_spec('patchtrace.secondary.binexport_run') is not None
    acceptor = REAL_C3_ACCEPTOR(tmp_path)
    assert (acceptor is not None) == present  # None until C3 merges: BinDiff then reports unsupported


def test_c3_wrapper_turns_mismatch_matching_other_artifact_into_orientation(tmp_path, monkeypatch):
    import sys
    import threading
    import types

    from patchtrace.secondary.contracts import SecondaryError

    def accept_binexport(path, *, artifact_sha256, role, private_dir, cancel, accept_unbound):
        if artifact_sha256 != 'b' * 64:
            error = SecondaryError('PT-SECONDARY-PAIR', 'mismatch')
            error.reason = 'executable_id_mismatch'
            raise error
        return 'accepted'

    fake = types.ModuleType('patchtrace.secondary.binexport_run')
    fake.accept_binexport = accept_binexport
    monkeypatch.setitem(sys.modules, 'patchtrace.secondary.binexport_run', fake)
    acceptor = REAL_C3_ACCEPTOR(tmp_path)
    kwargs = dict(role='older', accept_unbound=False, cancel=threading.Event())
    with pytest.raises(SecondaryError) as info:
        acceptor(tmp_path / 'x', artifact_sha256='a' * 64, other_sha256='b' * 64, **kwargs)
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'
    with pytest.raises(SecondaryError) as info:
        acceptor(tmp_path / 'x', artifact_sha256='a' * 64, other_sha256='c' * 64, **kwargs)
    assert info.value.code == 'PT-SECONDARY-PAIR'
    assert acceptor(tmp_path / 'x', artifact_sha256='b' * 64, **kwargs) == 'accepted'
