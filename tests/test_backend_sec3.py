"""SEC-3: external Python argv and cwd isolation, without starting a child."""
import json
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime  # noqa: F401 - pytest fixture reuse

from patchtrace import backend
from patchtrace.backend import BackendConfig
from patchtrace.jobs import ProcessResult


@pytest.mark.parametrize('bundle', [False, True], ids=['external', 'bundle'])
def test_sec3_probe_uses_isolated_python_and_private_cwd(tmp_path, monkeypatch, bundle):
    config = BackendConfig(str(tmp_path / 'python'), str(tmp_path / 'ghidra'), bundle=bundle)
    seen = []

    def runner(argv, **kwargs):
        assert argv[1:5] == ['-I', '-X', 'utf8', '-c']
        cwd = Path(kwargs['cwd'])
        seen.append(cwd)
        assert cwd.is_dir() and list(cwd.iterdir()) == []
        assert cwd != Path(config.ghidra_dir)
        return ProcessResult(0, json.dumps({
            'python': '3.12.0', 'ghidriff': 'test', 'pyghidra': 'test', 'available': True}), None)

    monkeypatch.setattr(backend, 'run_process', runner)
    assert backend._probe_backend(config)['available'] is True
    assert len(seen) == 1 and not seen[0].exists()


def test_sec3_analysis_uses_isolated_python_and_scratch_cwd(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime
    seen = []

    def runner(argv, **kwargs):
        assert argv[1:6] == ['-I', '-X', 'utf8', '-m', 'ghidriff']
        cwd = Path(kwargs['cwd'])
        seen.append(cwd)
        assert cwd.is_dir() and cwd != Path(config.ghidra_dir)
        assert (cwd / 'ghidra-settings').is_dir()
        out = Path(argv[argv.index('--output-path') + 1]) / 'json'
        out.mkdir()
        (out / 'result.ghidriff.json').write_text(
            json.dumps({'functions': {'added': [], 'deleted': [], 'modified': []}}),
            encoding='utf-8', newline='\n')
        return ProcessResult(0, '', None)

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), lambda _e: None)
    assert run.status == 'completed' and path.is_file()
    assert len(seen) == 1 and not seen[0].exists()
