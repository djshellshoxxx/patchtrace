"""Build provenance and packaging tests (SPEC-05 §2.7, §6.5 T-P01/T-P02, SRC-1..SRC-4)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import __version__
from patchtrace.buildinfo import VERSION_KEYS, git_info, source_sha256, version_info

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'src'
HAS_GIT = shutil.which('git') is not None


def _load_build_windows():
    spec = importlib.util.spec_from_file_location('build_windows_under_test',
                                                  ROOT / 'tools' / 'build_windows.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_windows = _load_build_windows()


def _git(repo: Path, *args: str) -> str:
    env = {**os.environ, 'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.invalid',
           'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.invalid',
           'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_NOSYSTEM': '1'}
    return subprocess.run(['git', *args], cwd=repo, env=env, capture_output=True, text=True,
                          check=True).stdout


@pytest.fixture
def temp_repo(tmp_path):
    if not HAS_GIT:
        pytest.skip('git not available')
    repo = tmp_path / 'repo'
    repo.mkdir()
    _git(repo, 'init', '-q')
    (repo / 'a.txt').write_text('a\n', encoding='utf-8')
    return repo


def _commit(repo: Path):
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-q', '-m', 'c')


def test_tp01_refuses_tree_without_head(temp_repo):
    with pytest.raises(build_windows.DirtyTreeError, match='HEAD is not a commit'):
        build_windows.check_source_tree(temp_repo)


def test_tp01_refuses_dirty_tree_and_allow_dirty_records_it(temp_repo):
    _commit(temp_repo)
    head = _git(temp_repo, 'rev-parse', 'HEAD').strip()
    clean = build_windows.check_source_tree(temp_repo)
    assert clean['commit'] == head and clean['dirty'] is False
    (temp_repo / 'a.txt').write_text('changed\n', encoding='utf-8')
    with pytest.raises(build_windows.DirtyTreeError, match='uncommitted'):
        build_windows.check_source_tree(temp_repo)
    _git(temp_repo, 'checkout', '--', 'a.txt')
    (temp_repo / 'untracked.txt').write_text('u\n', encoding='utf-8')
    with pytest.raises(build_windows.DirtyTreeError):
        build_windows.check_source_tree(temp_repo)
    allowed = build_windows.check_source_tree(temp_repo, allow_dirty=True)
    assert allowed['dirty'] is True and allowed['commit'] == head
    info = build_windows.make_build_info('9.9.9', allowed, 'f' * 64, '3.12.0', '6.22.3', '6.12.0',
                                         '2026-01-01T00:00:00Z')
    assert info['dirty'] is True


def test_git_info_never_raises(tmp_path, temp_repo):
    assert git_info(tmp_path / 'missing') == {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}
    _commit(temp_repo)
    info = git_info(temp_repo)
    assert len(info['commit']) == 40 and info['dirty'] is False and info['describe'] != 'unknown'


def _copy_package(tmp_path: Path) -> Path:
    src = tmp_path / 'src'
    shutil.copytree(SRC / 'patchtrace', src / 'patchtrace',
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    return src


def test_tp02_source_sha256_deterministic_and_sensitive(tmp_path):
    src = _copy_package(tmp_path)
    first = source_sha256(src)
    assert first == source_sha256(src) == source_sha256(SRC)
    # Independent recomputation of the documented definition.
    lines = sorted(f'{p.relative_to(src).as_posix()}\t{hashlib.sha256(p.read_bytes()).hexdigest()}\n'
                   for p in (src / 'patchtrace').rglob('*.py'))
    assert first == hashlib.sha256(''.join(lines).encode()).hexdigest()
    cache = src / 'patchtrace' / '__pycache__'
    cache.mkdir()
    (cache / 'stray.py').write_text('x = 1\n', encoding='utf-8')
    (src / 'patchtrace' / 'notes.txt').write_text('not python\n', encoding='utf-8')
    assert source_sha256(src) == first
    target = src / 'patchtrace' / '__init__.py'
    target.write_text(target.read_text(encoding='utf-8') + '# edit\n', encoding='utf-8')
    assert source_sha256(src) != first
    (src / 'patchtrace' / 'extra.py').write_text('', encoding='utf-8')
    assert len({first, source_sha256(src)}) == 2


def test_build_info_document_keys():
    git = {'commit': 'a' * 40, 'describe': 'v0.1.0-1-gaaaaaaa', 'dirty': False}
    info = build_windows.make_build_info('0.1.0', git, 'b' * 64, '3.12.4', '6.22.3', '6.12.0',
                                         '2026-10-11T00:00:00Z')
    assert set(info) == {'version', 'git_commit', 'git_describe', 'dirty', 'source_sha256', 'python',
                         'pyinstaller', 'pyside6', 'built_utc'}
    assert set(info) | {'frozen'} == set(VERSION_KEYS)
    assert info['git_commit'] == 'a' * 40 and info['dirty'] is False
    json.dumps(info)


def test_source_txt_content_matches_windows_doc():
    text = build_windows.source_txt('0.1.0', 'c' * 40, False)
    assert 'https://github.com/djshellshoxxx/patchtrace' in text
    assert 'c' * 40 in text and 'DIRTY' not in text
    assert 'PatchTrace-0.1.0-source.zip' in text
    doc = (ROOT / 'docs' / 'windows.md').read_text(encoding='utf-8')
    for command in build_windows.BUILD_COMMANDS:
        assert command in text and command in doc
    assert 'DIRTY' in build_windows.source_txt('0.1.0', 'c' * 40, True)


def test_version_output_check():
    commit = 'd' * 40
    assert build_windows.check_version_output(0, json.dumps({'git_commit': commit}), commit) is None
    assert 'warning' in build_windows.check_version_output(64, '', commit)
    assert 'warning' in build_windows.check_version_output(2, '', commit)
    assert 'warning' in build_windows.check_version_output(0, 'not json', commit)
    with pytest.raises(RuntimeError, match='git_commit'):
        build_windows.check_version_output(0, json.dumps({'git_commit': 'e' * 40}), commit)
    with pytest.raises(RuntimeError, match='exit code 1'):
        build_windows.check_version_output(1, '', commit)


def test_build_script_uses_console_subsystem_and_bundles_build_info():
    text = (ROOT / 'tools' / 'build_windows.py').read_text(encoding='utf-8')
    assert "'--windowed'" not in text
    assert "'--console', '--hide-console', 'hide-early'" in text
    assert "'--add-data'" in text and 'git' in text and "'archive'" in text


def test_build_refuses_non_windows():
    if sys.platform == 'win32':
        pytest.skip('guard only applies off Windows')
    with pytest.raises(SystemExit, match='Build on Windows'):
        build_windows.main([])


def test_version_info_from_source_keys():
    info = version_info()
    assert tuple(info) == VERSION_KEYS
    assert info['version'] == __version__ and info['frozen'] is False
    assert info['pyinstaller'] is None and info['built_utc'] is None
    assert info['source_sha256'] == source_sha256(SRC)


def test_version_info_does_not_import_qt():
    code = ('import json, sys\n'
            'from patchtrace.buildinfo import version_info\n'
            'info = version_info()\n'
            'assert not any(m == "PySide6" or m.startswith("PySide6.") or m == "patchtrace.ui" '
            'for m in sys.modules), sorted(m for m in sys.modules if "PySide6" in m)\n'
            'print(json.dumps(info))\n')
    env = {**os.environ, 'PYTHONPATH': str(SRC)}
    completed = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True,
                               timeout=60, check=False)
    assert completed.returncode == 0, completed.stderr
    assert tuple(json.loads(completed.stdout)) == VERSION_KEYS


def test_version_info_frozen_reads_bundled_build_info(tmp_path, monkeypatch):
    bundle = tmp_path / 'patchtrace'
    bundle.mkdir()
    stored = {'version': '0.1.0', 'git_commit': 'f' * 40, 'git_describe': 'v0.1.0', 'dirty': False,
              'source_sha256': '0' * 64, 'python': '3.12.4', 'pyinstaller': '6.22.3',
              'pyside6': '6.12.0', 'built_utc': '2026-10-11T00:00:00Z'}
    (bundle / 'build-info.json').write_text(json.dumps(stored), encoding='utf-8')
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, '_MEIPASS', str(tmp_path), raising=False)
    info = version_info()
    assert info == {**stored, 'frozen': True}


def test_src1_quarantine_and_run_prefix_literals_only_in_workspace():
    """SRC-1 static guard. workspace.py may not exist yet (written concurrently)."""
    offenders = []
    for path in sorted((SRC / 'patchtrace').rglob('*.py')):
        if path.name == 'workspace.py' and path.parent.name == 'patchtrace':
            continue
        text = path.read_text(encoding='utf-8')
        offenders += [f'{path.relative_to(SRC).as_posix()}: {literal}'
                      for literal in ('.quarantine', 'runs/.') if literal in text]
    assert not offenders, offenders
