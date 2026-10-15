from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import pytest

from patchtrace.search import paths
from patchtrace.search.errors import SearchError

DIGEST = '0123456789abcdef'


def test_default_cache_root_prefers_localappdata_then_xdg_then_home(tmp_path):
    assert paths.default_cache_root({'LOCALAPPDATA': 'C:/L', 'XDG_CACHE_HOME': '/x'}) == Path('C:/L/PatchTrace/cache')
    assert paths.default_cache_root({'XDG_CACHE_HOME': '/x'}) == Path('/x/PatchTrace')
    assert paths.default_cache_root({}, home=tmp_path) == tmp_path / '.cache' / 'PatchTrace'


def test_cache_root_outside_project_is_accepted(tmp_path):
    project = tmp_path / 'proj'
    project.mkdir()
    cache = tmp_path / 'cache'
    assert paths.validate_cache_root(cache, project) == cache
    assert paths.validate_cache_root(tmp_path / 'proj-sibling', project)  # shares only a name prefix


@pytest.mark.parametrize('relative', ['.', 'search', 'a/b/c', '../proj/x'], ids=['same', 'child', 'deep', 'dotdot'])
def test_cache_root_inside_project_is_refused(tmp_path, relative):
    project = tmp_path / 'proj'
    project.mkdir()
    with pytest.raises(SearchError) as err:
        paths.validate_cache_root(project / relative, project)
    assert err.value.code == 'PT-SEARCH-STORE' and err.value.exit_code == 3
    assert str(tmp_path) not in err.value.message


def test_relative_cache_root_is_refused(tmp_path):
    with pytest.raises(SearchError, match='absolute'):
        paths.validate_cache_root(Path('cache'), tmp_path)


@pytest.mark.skipif(sys.platform == 'win32', reason='symlink creation needs privileges on Windows')
def test_symlink_into_project_is_refused(tmp_path):
    project = tmp_path / 'proj'
    project.mkdir()
    link = tmp_path / 'link'
    link.symlink_to(project, target_is_directory=True)
    with pytest.raises(SearchError):
        paths.validate_cache_root(link / 'cache', project)


def test_windows_comparison_is_case_insensitive(monkeypatch, tmp_path):
    project = tmp_path / 'Proj'
    project.mkdir()
    monkeypatch.setattr(paths.os.path, 'normcase', str.lower)
    with pytest.raises(SearchError):
        paths.validate_cache_root(tmp_path / 'PROJ' / 'cache', project)


def test_project_directory_hashes_the_id():
    root = Path('/cache')
    expected = hashlib.sha256(b'proj-1').hexdigest()[:16]
    assert paths.project_dir(root, 'proj-1') == root / 'search' / expected
    assert paths.project_dir(root, 'proj-1') != paths.project_dir(root, 'proj-2')
    with pytest.raises(SearchError):
        paths.project_dir(root, '')


@pytest.mark.parametrize('group,name', [
    ('fn', f'fn-{DIGEST}.sqlite3'), ('pe:older', f'pe.older-{DIGEST}.sqlite3'),
    ('tool:floss:newer', f'tool.floss.newer-{DIGEST}.sqlite3')], ids=['fn', 'pe', 'tool'])
def test_segment_names_round_trip_and_are_windows_safe(group, name):
    assert paths.segment_filename(group, DIGEST) == name
    assert paths.parse_segment_filename(name) == (group, DIGEST)
    assert not set(name) & set('<>:"/\\|?*')


@pytest.mark.parametrize('group', ['', 'FN', 'fn/..', 'pe:', 'a:b:c:d', 'con\x00', 'x' * 9, 'pe:Older'],
                         ids=['empty', 'upper', 'slash', 'colon', 'deep', 'nul', 'long', 'case'])
def test_hostile_group_is_refused(group):
    with pytest.raises(SearchError):
        paths.segment_filename(group, DIGEST)


@pytest.mark.parametrize('digest', ['', 'xyz', DIGEST.upper(), DIGEST + '0', '../' + DIGEST[3:]],
                         ids=['empty', 'nonhex', 'upper', 'long', 'traversal'])
def test_hostile_digest_is_refused(digest):
    with pytest.raises(SearchError):
        paths.segment_filename('fn', digest)


@pytest.mark.parametrize('name', ['.staging-abc', 'fn.sqlite3', f'fn-{DIGEST}.sqlite3-wal', f'FN-{DIGEST}.sqlite3',
                                  'notes.txt'], ids=['staging', 'nodigest', 'wal', 'upper', 'stranger'])
def test_strangers_are_not_segments(name):
    assert paths.parse_segment_filename(name) is None


def test_staging_paths_are_unique_hidden_siblings(tmp_path):
    first, second = paths.staging_path(tmp_path), paths.staging_path(tmp_path)
    assert first != second and first.parent == tmp_path
    assert first.name.startswith(paths.STAGING_PREFIX)
    assert paths.parse_segment_filename(first.name) is None


def test_ensure_writable_creates_directory_and_leaves_nothing(tmp_path):
    target = tmp_path / 'a' / 'b'
    paths.ensure_writable(target)
    assert target.is_dir() and not list(target.iterdir())


def test_ensure_writable_reports_store_error(tmp_path):
    blocker = tmp_path / 'file'
    blocker.write_text('x', encoding='utf-8')
    with pytest.raises(SearchError) as err:
        paths.ensure_writable(blocker / 'sub')
    assert err.value.code == 'PT-SEARCH-STORE' and err.value.recoverable
    assert os.fspath(blocker) not in err.value.message
