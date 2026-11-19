"""Real local source/record admission controls; no packaged or native qualification."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading

import pytest

from patchtrace import __version__
from patchtrace import buildinfo as b
from patchtrace.owned_publication import OwnedPublicationError


def source(tmp_path):
    package = tmp_path / 'src' / 'patchtrace'
    package.mkdir(parents=True)
    (package / 'z.py').write_bytes(b'z = 2\n')
    (package / 'a.py').write_bytes(b'a = 1\n')
    return package.parent


def record():
    return {'version': __version__, 'git_commit': 'a' * 40, 'git_describe': 'v0.1.0', 'dirty': False,
            'source_sha256': 'b' * 64, 'python': '3.12.14', 'pyinstaller': '6.22.3', 'pyside6': '6.12.0',
            'built_utc': '2026-11-19T10:00:00Z', 'frozen': True}


def frozen(tmp_path, monkeypatch, raw):
    package = tmp_path / 'patchtrace'
    package.mkdir()
    (package / b.BUILD_INFO_NAME).write_bytes(raw)
    monkeypatch.setattr(b.sys, 'frozen', True, raising=False)
    monkeypatch.setattr(b.sys, '_MEIPASS', str(tmp_path), raising=False)
    monkeypatch.setattr(b, 'source_sha256', lambda *a, **k: pytest.fail('frozen source must not be scanned'))
    monkeypatch.setattr(b, 'git_info', lambda *a, **k: pytest.fail('frozen Git must not be invoked'))
    return package


def test_source_digest_matches_historical_canonical_definition(tmp_path):
    root = source(tmp_path)
    (root / 'patchtrace' / '__pycache__').mkdir()
    (root / 'patchtrace' / '__pycache__' / 'ignored.py').write_bytes(b'ignore')
    (root / 'patchtrace' / 'other.txt').write_bytes(b'ignore')
    expected = ''.join(f'patchtrace/{name}\t{hashlib.sha256(raw).hexdigest()}\n'
                       for name, raw in [('a.py', b'a = 1\n'), ('z.py', b'z = 2\n')])
    assert b.source_sha256(root) == hashlib.sha256(expected.encode()).hexdigest()


@pytest.mark.parametrize('limit', ['MAX_FILE_BYTES', 'MAX_SOURCE_BYTES', 'MAX_ENTRIES'])
def test_source_budgets_refuse_actual_files(tmp_path, monkeypatch, limit):
    root = source(tmp_path)
    monkeypatch.setattr(b, limit, 1)
    with pytest.raises((b.BuildInfoError, OwnedPublicationError)):
        b.source_sha256(root)


def test_source_changed_after_first_held_read_is_not_fingerprinted(tmp_path, monkeypatch):
    root = source(tmp_path)
    real = b.owned.read_bytes

    def changing(path, **kwargs):
        raw = real(path, **kwargs)
        if path.name == 'a.py':
            (root / 'patchtrace' / 'z.py').write_bytes(b'z = 9\n')
        return raw

    monkeypatch.setattr(b.owned, 'read_bytes', changing)
    with pytest.raises(b.BuildInfoError, match='changed'):
        b.source_sha256(root)


@pytest.mark.parametrize('directory', [False, True])
def test_source_links_are_refused(tmp_path, directory):
    root = source(tmp_path)
    external = tmp_path / 'outside'
    external.mkdir()
    (external / 'x.py').write_bytes(b'outside')
    try:
        (root / 'patchtrace' / ('linked' if directory else 'linked.py')).symlink_to(
            external if directory else external / 'x.py', target_is_directory=directory)
    except OSError:
        pytest.skip('host cannot create a symbolic link')
    with pytest.raises(b.BuildInfoError, match='link'):
        b.source_sha256(root)


def test_source_empty_missing_and_depth_refuse(tmp_path, monkeypatch):
    package = tmp_path / 'patchtrace'
    package.mkdir()
    with pytest.raises(b.BuildInfoError, match='no Python'):
        b.source_sha256(tmp_path)
    (package / 'nested').mkdir()
    (package / 'nested' / 'x.py').write_bytes(b'x')
    monkeypatch.setattr(b, 'MAX_DEPTH', 0)
    with pytest.raises(b.BuildInfoError, match='depth'):
        b.source_sha256(tmp_path)


def test_precancelled_observation_never_touches_source(tmp_path, monkeypatch):
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(b.owned, 'directory_anchor', lambda *a: pytest.fail('no I/O after cancellation'))
    with pytest.raises(b.BuildInfoCancelled):
        b.source_sha256(tmp_path, cancel=cancel)
    with pytest.raises(b.BuildInfoCancelled):
        b.read_info(cancel=cancel)


def test_frozen_record_preserves_validated_build_fields(tmp_path, monkeypatch):
    expected = record()
    frozen(tmp_path, monkeypatch, json.dumps(expected).encode())
    got, warnings = b.read_info()
    assert not warnings
    assert {key: got[key] for key in b.VERSION_KEYS} == expected
    assert got['basis'] == 'packaged-record'


@pytest.mark.parametrize('edit', [
    {'dirty': 0}, {'frozen': 'true'}, {'version': '999.0.0'}, {'git_commit': 'x' * 40},
    {'source_sha256': '0' * 63}, {'built_utc': '2026-02-30T00:00:00Z'}, {'python': []}, {'extra': True},
])
def test_invalid_frozen_record_never_contributes_partial_provenance(tmp_path, monkeypatch, edit):
    data = record() | edit
    frozen(tmp_path, monkeypatch, json.dumps(data).encode())
    got, warnings = b.read_info()
    assert warnings and got['git_commit'] == 'unknown' and got['source_sha256'] == 'unknown'
    assert got['dirty'] is None and got['version'] == __version__ and got['frozen'] is True


@pytest.mark.parametrize('raw', [b'{"version": "0.1.0", "version": "0.1.0"}', b'{"dirty": NaN}',
                                 b'[' * 2000 + b'0' + b']' * 2000, b' ' * (b.MAX_BUILD_BYTES + 1)])
def test_hostile_frozen_json_is_bounded_and_unknown(tmp_path, monkeypatch, raw):
    frozen(tmp_path, monkeypatch, raw)
    got, warnings = b.read_info()
    assert warnings and got['git_commit'] == 'unknown'


def test_git_observes_real_commit_without_claiming_cleanliness_and_ignores_git_dir(tmp_path, monkeypatch):
    git = shutil.which('git')
    if git is None:
        pytest.skip('Git is unavailable')

    def run(*args):
        return subprocess.run([git, *args], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()

    run('init', '-q')
    (tmp_path / 'one').write_text('one')
    run('add', 'one')
    run('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    expected = run('rev-parse', 'HEAD')
    monkeypatch.setenv('GIT_DIR', str(tmp_path / 'absent.git'))
    got = b.git_info(tmp_path)
    assert got['commit'] == expected and got['dirty'] is None
    (tmp_path / 'untracked').write_text('two')
    assert b.git_info(tmp_path)['dirty'] is None


def test_git_missing_description_cannot_imply_clean_and_moving_head_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(b.shutil, 'which', lambda name: '/local/git')
    answers = iter([str(tmp_path), 'a' * 40, None, 'a' * 40, str(tmp_path)])
    monkeypatch.setattr(b, '_git', lambda *args: next(answers))
    assert b.git_info(tmp_path)['dirty'] is None
    answers = iter([str(tmp_path), 'a' * 40, 'tag', 'b' * 40, str(tmp_path)])
    assert b.git_info(tmp_path) == {'commit': 'unknown', 'describe': 'unknown', 'dirty': None}
