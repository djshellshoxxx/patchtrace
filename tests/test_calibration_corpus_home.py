"""Explicit corpus roots work in restricted workers without a discoverable user home."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('command', ['root', 'tier-r-help'])
def test_corpus_import_and_explicit_root_do_not_resolve_home(tmp_path, command):
    """The Windows shard supplies a root but deliberately omits USERPROFILE."""
    script = '''
import pathlib
import sys

def unavailable(cls):
    raise RuntimeError('Could not determine home directory.')

pathlib.Path.home = classmethod(unavailable)
from tools.calibration import corpus
assert corpus.calib_root() == pathlib.Path(sys.argv[1]).resolve()
if sys.argv[2] == 'tier-r-help':
    from tools.calibration.tier_r.cli import main
    main(['--help'])
'''
    env = dict(os.environ, PATCHTRACE_CALIB_ROOT=str(tmp_path), PYTHONPATH=str(ROOT / 'src'))
    for name in ('HOME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH'):
        env.pop(name, None)
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path), command], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    if command == 'tier-r-help':
        assert 'known-answer corpus factory' in result.stdout


def test_default_corpus_root_is_resolved_only_when_requested(tmp_path, monkeypatch):
    from tools.calibration import corpus

    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: tmp_path))
    assert corpus.calib_root({}) == (tmp_path / '.patchtrace-calibration').resolve()


def test_missing_home_does_not_silently_fall_back_to_the_checkout(monkeypatch):
    from tools.calibration import corpus

    def unavailable(cls):
        raise RuntimeError('Could not determine home directory.')

    monkeypatch.setattr(Path, 'home', classmethod(unavailable))
    with pytest.raises(RuntimeError, match='Could not determine home directory'):
        corpus.calib_root({})
