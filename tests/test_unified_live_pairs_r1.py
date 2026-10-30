"""Dev harness regressions with synthetic primary JSON and substituted external analysis.

The project store, primary import, unified pipeline and outcome collection are real.
No Ghidra/Ghidriff process or target binary is executed; these are not live acceptance evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest
from unified_s0_fixtures import patch_document
from unified_s6_helpers import label_doc

from patchtrace.backend import BackendConfig
from patchtrace.models import AnalysisRun
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline
from tools.unified import live_pairs, outcomes


def images(tmp_path):
    payloads = [synthetic_pe(0), synthetic_pe(1)]
    digests = [hashlib.sha256(payload).hexdigest() for payload in payloads]
    doc = label_doc('r1-synthetic', 'release', older=digests[0], newer=digests[1])
    for side, payload in zip((doc.older, doc.newer), payloads, strict=True):
        folder = tmp_path / 'images' / side.sha256
        folder.mkdir(parents=True)
        (folder / side.file_name).write_bytes(payload)
    return doc


@pytest.mark.parametrize('orientation', ['forward', 'swapped'])
def test_completed_primary_is_persisted_before_real_unified_consumption(tmp_path, monkeypatch, orientation):
    """Dropping apply_analysis leaves no completed run and makes the real pipeline reject the project."""
    doc = images(tmp_path)
    backend = BackendConfig('synthetic-python', '/synthetic-ghidra', 123, java_home='/synthetic-java',
                            cache_dir='/synthetic-cache', no_cache=True, refresh=True, restrict_env=True,
                            env_passthrough=('R1_TEST',), bundle=True, symbol_mode='local',
                            symbol_pdb_dirs=('/synthetic-pdbs',))

    def comparison(config, project, root, cancel, on_event):
        # This external boundary must preserve containment, cache and symbol policy.
        assert config == replace(backend, retain_gzf=True)
        run = AnalysisRun(status='completed', backend='synthetic', backend_version='r1-unit',
                          settings={'synthetic': True})
        run_dir = root / 'runs' / run.id
        raw = run_dir / 'raw' / 'synthetic.json'
        raw.parent.mkdir(parents=True)
        raw.write_text(json.dumps(patch_document(project)), encoding='utf-8')
        run.raw_path = raw.relative_to(root).as_posix()
        run.raw_sha256 = hashlib.sha256(raw.read_bytes()).hexdigest()
        gzf = run_dir / 'unified' / 'gzf'
        gzf.mkdir(parents=True)
        for side in ('older', 'newer'):
            (gzf / f'{side}.gzf').write_bytes(b'synthetic-not-a-program')
        return raw, run

    class SyntheticSide:
        def __init__(self, *args):
            pass

        def run(self, *args):
            return {'directory': tmp_path}

        def close(self):
            pass

    real_unified = pipeline.run_unified
    monkeypatch.setattr(live_pairs.backend_module, 'run_comparison', comparison)
    monkeypatch.setattr(live_pairs, 'Side', SyntheticSide)
    monkeypatch.setattr(live_pairs, 'place_ir', lambda *args: None)
    monkeypatch.setattr(live_pairs.pipeline, 'run_unified',
                        lambda service, options: real_unified(service, replace(options, isolate=False)))
    work = tmp_path / 'work'
    result = live_pairs.analyse_pair(doc, tmp_path, backend, work, orientation)
    assert result.orientation == orientation and result.rows
    assert any(row.materiality == 'material' for row in result.rows)
    service = ProjectService.open(work / f'{doc.pair_id}-{orientation}')
    try:
        assert service.project.runs[-1].status == 'completed'
        assert service.project.runs[-1].backend == 'synthetic'
        assert service.project.matches
        assert pipeline.load_current(service, pipeline.make_plan(service)).state == 'current'
    finally:
        service.close()


def test_identical_shortcut_is_not_reported_as_executed_engine_evidence(tmp_path, monkeypatch):
    """The backend shortcut must leave no outcome and explain why independent analysis is needed."""
    doc = images(tmp_path)
    monkeypatch.setattr(live_pairs.backend_module, 'run_comparison',
                        lambda *args: (tmp_path, AnalysisRun(status='identical')))
    done, failed = live_pairs.run_all([doc], tmp_path, BackendConfig('python', '/ghidra'),
                                      swap=False, work=tmp_path / 'work')
    assert done == [] and len(failed) == 1
    assert 'not executed' in failed[0]
    assert 'independent' in failed[0]


def test_failed_pair_diagnostics_survive_temporary_work_cleanup(tmp_path, monkeypatch, capsys):
    """A failed native pair needs a bounded retained explanation, not only a transient stderr line."""
    doc = label_doc('failed-native', 'release')
    monkeypatch.setattr(live_pairs, 'load_labels', lambda *args: [doc])
    monkeypatch.setattr(live_pairs, 'run_all', lambda *args, **kwargs: ([], ['native failed ' + 'x' * 100_000]))
    output = tmp_path / 'outcomes-r1.json'
    code = live_pairs.main(['--labels', str(tmp_path), '--store', str(tmp_path), '--ghidra-dir', str(tmp_path),
                            '--out', str(output)])
    capsys.readouterr()
    assert code == live_pairs.PAIR_FAILED
    assert outcomes.load(output.read_bytes()).pairs == ()
    diagnostics = output.with_suffix('.failures.txt').read_bytes()
    assert diagnostics.startswith(b'native failed ')
    assert len(diagnostics) <= 65_536


@pytest.mark.skipif(os.name == 'nt', reason='POSIX executable permission bits are a Linux workflow concern')
@pytest.mark.parametrize('job', ['pairs', 'mutants'])
def test_workflow_restores_archived_executables_after_python_zip_extraction(tmp_path, job):
    """Python extraction drops Ghidra native executable bits; run the real recovery step on a synthetic ZIP."""
    yaml = pytest.importorskip('yaml')
    workflow = Path(__file__).resolve().parents[1] / '.github/workflows/unified-live-gates.yml'
    steps = yaml.safe_load(workflow.read_text())['jobs'][job]['steps']
    restore = next((step for step in steps if step.get('name') == 'Restore Ghidra executable permissions'), None)
    assert restore is not None, 'Python ZIP extraction needs executable permissions restored'
    assert restore['if'] == "runner.os == 'Linux'"
    executable = ZipInfo('ghidra-test/Ghidra/Features/Decompiler/os/linux_x86_64/decompile')
    executable.external_attr = 0o100751 << 16
    regular = ZipInfo('ghidra-test/readme.txt')
    regular.external_attr = 0o100644 << 16
    with ZipFile(tmp_path / 'ghidra.zip', 'w') as archive:
        archive.writestr(executable, b'synthetic data; never execute')
        archive.writestr(regular, b'ordinary data')
    with ZipFile(tmp_path / 'ghidra.zip') as archive:
        archive.extractall(tmp_path / 'ghidra-runtime')
    program = tmp_path / 'ghidra-runtime' / executable.filename
    assert program.stat().st_mode & 0o111 == 0
    subprocess.run(['bash', '-e', '-c', restore['run']], cwd=tmp_path, check=True, capture_output=True)
    assert program.stat().st_mode & 0o111 == 0o111
    assert (tmp_path / 'ghidra-runtime' / regular.filename).stat().st_mode & 0o111 == 0
