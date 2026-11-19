from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path('/workspace/scratch/792fd5ca6555/pt-adapters')
SOURCE = REPOSITORY / 'tools/journey_gate.py'
EXPECTED = subprocess.check_output(['git', 'show', 'b7aa97f5:tools/journey_gate.py'], cwd=REPOSITORY)
assert SOURCE.read_bytes() == EXPECTED
SPEC = importlib.util.spec_from_file_location('journey_gate_independent', SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize('index_flag', ['--assume-unchanged', '--skip-worktree'])
def test_static_consumed_source_change_cannot_retain_same_clean_identity(tmp_path, index_flag):
    root = tmp_path / 'checkout'
    root.mkdir()

    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True, text=True)

    git('init', '-q')
    for name in (*MODULE.SOURCE_FILES, 'src/patchtrace/service.py'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'original = 1\n')
    git('add', '.')
    git('-c', 'user.name=Authored review', '-c', 'user.email=review@example.invalid',
        '-c', 'commit.gpgsign=false', 'commit', '-qm', 'authored source')
    before = MODULE.source_identity(root)
    git('update-index', index_flag, '--', 'src/patchtrace/service.py')
    (root / 'src/patchtrace/service.py').write_bytes(b'changed_implementation = 2\n')
    assert git('status', '--porcelain').stdout == ''
    assert git('show', 'HEAD:src/patchtrace/service.py').stdout == 'original = 1\n'
    try:
        after = MODULE.source_identity(root)
    except MODULE.GateError:
        return
    assert after != before, 'changed production source is admitted under the same clean source identity'
