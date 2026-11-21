"""Authored probe outcomes exercise live-harness evidence; these are not native acceptance."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import test_live_intel_tools as live

from patchtrace.intelligence.tools import process


@pytest.mark.parametrize('engine', ['capa', 'floss'])
def test_failed_probe_retains_existing_output_and_original_failure(
        engine, tmp_path, monkeypatch, record_live_status):
    executable = tmp_path / f'{engine}.exe'
    executable.write_bytes(b'authored executable placeholder; never executed')
    status = tmp_path / 'status'
    monkeypatch.setenv(live.ENV[engine], str(executable))
    monkeypatch.setenv('PATCHTRACE_LIVE_STATUS_DIR', str(status))
    monkeypatch.setenv('PATCHTRACE_LIVE_MOCKED', '1')
    outputs = [process.Execution(1, None, 'version stdout', 'loader error', False, 12),
               process.Execution(0, None, 'help stdout', 'help stderr', False, 8)]
    calls = []

    def original(exe, args, **kwargs):
        calls.append((exe, args, kwargs))
        return outputs[len(calls) - 1]

    monkeypatch.setattr(process, 'run_version_probe', original)

    def probe(engine, config, cancel, runner):
        for args in (['--version'], ['--help']):
            result = process.run_version_probe(config.executable, args, cancel=cancel, runner=runner,
                                               environ={'SECRET_TOKEN': 'must-not-be-recorded'})
            assert result is outputs[len(calls) - 1]
        return SimpleNamespace(supported=False, pin_status='pinned', reason='version failed (exit 1)')

    monkeypatch.setattr(live.runner, 'probe_engine', probe)
    with pytest.raises(pytest.fail.Exception, match='version failed \(exit 1\)'):
        live.test_pinned_tool_probes_and_reproduces_the_goldens(engine, tmp_path, record_live_status)
    document = json.loads((status / f'intel-tools-{engine}.json').read_text())
    assert document['status'] == 'failed' and document['mocked'] is True
    assert len(calls) == 2 and process.run_version_probe is original
    assert 'probe_diagnostics' in document, 'live failure discarded existing version/help probe outputs'
    probes = document['probe_diagnostics']['probes']
    assert [p['returncode'] for p in probes] == [1, 0]
    assert [p['stdout'] for p in probes] == ['version stdout', 'help stdout']
    assert [p['stderr'] for p in probes] == ['loader error', 'help stderr']
    assert [p['argv'] for p in probes] == [[executable.name, '--version'], [executable.name, '--help']]
    assert 'must-not-be-recorded' not in json.dumps(document)
    assert str(tmp_path) not in json.dumps(document)
