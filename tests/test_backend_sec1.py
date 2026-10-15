"""SEC-1: Ghidriff reads verified private snapshots; no child is started."""
import hashlib
import json
import threading
from pathlib import Path

import pytest
from test_jobs import fake_runtime  # noqa: F401 - pytest fixture reuse

from patchtrace import backend
from patchtrace.jobs import ProcessResult


@pytest.mark.parametrize('side', ['older', 'newer'], ids=['old', 'new'])
def test_sec1_change_after_preflight_refuses_engine(fake_runtime, monkeypatch, side):  # noqa: F811
    root, _package, project, config = fake_runtime
    calls = []

    def runner(*args, **kwargs):
        calls.append(args)
        return ProcessResult(1, '', None)

    def change(event):
        if event.stage == 'analysis':
            (root / f'{side}.bin').write_bytes(b'changed-after-hash')

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), change)
    assert run.status == 'failed' and run.error.startswith('PT-INPUT:')
    assert calls == []
    assert (path / 'failure.txt').is_file()


def test_sec1_engine_reads_snapshot_after_original_changes(fake_runtime, monkeypatch):  # noqa: F811
    root, _package, project, config = fake_runtime
    expected = {a.side: (root / a.relative_path).read_bytes() for a in project.artifacts}
    seen = []

    def runner(argv, **kwargs):
        start = argv.index('ghidriff') + 1
        for side, value in zip(('older', 'newer'), argv[start:start + 2]):
            original = root / f'{side}.bin'
            original.write_bytes(b'changed-at-spawn')
            snapshot = Path(value)
            seen.append(snapshot)
            assert snapshot != original
            assert snapshot.name == original.name
            assert snapshot.read_bytes() == expected[side]
            artifact = next(a for a in project.artifacts if a.side == side)
            assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == artifact.sha256
        out = Path(argv[argv.index('--output-path') + 1]) / 'json'
        out.mkdir()
        (out / 'result.ghidriff.json').write_text(
            json.dumps({'functions': {'added': [], 'deleted': [], 'modified': []}}),
            encoding='utf-8', newline='\n')
        return ProcessResult(0, '', None)

    monkeypatch.setattr(backend, 'run_process', runner)
    path, run = backend.run_comparison(config, project, root, threading.Event(), lambda _e: None)
    assert run.status == 'completed' and path.is_file()
    assert len(seen) == 2 and all(not p.exists() for p in seen)
    assert run.settings['older_sha256'] == project.artifacts[0].sha256
    assert run.settings['newer_sha256'] == project.artifacts[1].sha256
