"""Real authored repositories distinguish source roots from ancestor Git discovery."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from patchtrace import buildinfo as b


def git(root, *args):
    executable = shutil.which('git')
    if executable is None:
        pytest.skip('Git is unavailable')
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    return subprocess.run([executable, *args], cwd=root, env=env, check=True,
                          capture_output=True, text=True, timeout=10).stdout.strip()


def source(root: Path):
    package = root / 'src' / 'patchtrace'
    package.mkdir(parents=True)
    (package / '__init__.py').write_bytes(b'__version__ = "0.1.0"\n')
    (package / 'buildinfo.py').write_bytes(b'authored_source = 1\n')
    return package


def commit(root):
    git(root, 'add', '.')
    git(root, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    return git(root, 'rev-parse', 'HEAD')


def test_nested_source_does_not_inherit_enclosing_git_commit(tmp_path, monkeypatch):
    outer = tmp_path / 'outer'
    outer.mkdir()
    git(outer, 'init', '-q')
    (outer / 'unrelated.txt').write_bytes(b'unrelated repository')
    head = commit(outer)
    nested = outer / 'untracked-source'
    package = source(nested)
    monkeypatch.setattr(b, '__file__', str(package / 'buildinfo.py'))
    assert git(nested, 'rev-parse', 'HEAD') == head  # The actual inherited-discovery negative.
    assert not (nested / '.git').exists()
    assert b.git_info(nested) == {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}
    record, warnings = b.read_info()
    assert warnings and record['basis'] == 'source-tree'
    assert record['git_commit'] == 'unknown' and record['git_describe'] == 'unknown'
    assert record['source_sha256'] == b.source_sha256(nested / 'src') and record['dirty'] is None


def test_real_detached_worktree_keeps_its_own_commit_observation(tmp_path, monkeypatch):
    original = tmp_path / 'original'
    package = source(original)
    git(original, 'init', '-q')
    head = commit(original)
    worktree = tmp_path / 'worktree'
    git(original, 'worktree', 'add', '--detach', str(worktree), head)
    assert (worktree / '.git').is_file()
    monkeypatch.setattr(b, '__file__', str(worktree / 'src' / 'patchtrace' / 'buildinfo.py'))
    record, warnings = b.read_info()
    assert warnings and record['basis'] == 'source-tree'
    assert record['git_commit'] == head and record['dirty'] is None
    assert record['source_sha256'] == b.source_sha256(package.parent)


def test_changed_top_level_refuses_even_when_head_is_equal(tmp_path, monkeypatch):
    monkeypatch.setattr(b.shutil, 'which', lambda name: '/authored/git')
    answers = iter([str(tmp_path), 'a' * 40, 'description', 'a' * 40, str(tmp_path.parent)])
    monkeypatch.setattr(b, '_git', lambda *args: next(answers))
    assert b.git_info(tmp_path) == {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}


def test_replaced_selected_root_refuses(tmp_path, monkeypatch):
    root = tmp_path / 'selected'
    root.mkdir()
    monkeypatch.setattr(b.shutil, 'which', lambda name: '/authored/git')
    answers = iter([str(root), 'a' * 40, 'description', 'a' * 40, str(root)])
    calls = 0
    def observe(*args):
        nonlocal calls
        calls += 1
        if calls == 5:
            root.rename(tmp_path / 'retained')
            root.mkdir()
        return next(answers)
    monkeypatch.setattr(b, '_git', observe)
    assert b.git_info(root) == {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}
