"""Preserve project paths and SQLite open modes without access to a network share."""
import os
import sqlite3
from contextlib import closing
from pathlib import Path, PureWindowsPath
from urllib.parse import unquote, urlsplit

import pytest

from patchtrace import verified_backup
from patchtrace.sqlite_paths import project_database_uri


@pytest.mark.parametrize('path', [
    PureWindowsPath('//fileserver/share/case #1/100%/project.sqlite3'),
    PureWindowsPath('//localhost/share/δοκιμή/project.sqlite3'),
])
def test_windows_share_name_stays_in_database_path(path):
    uri = urlsplit(project_database_uri(path))
    assert uri.scheme == 'file' and uri.netloc == ''
    assert uri.query == uri.fragment == ''
    assert unquote(uri.path) == path.as_posix()


def test_windows_drive_filename_uses_normal_file_uri():
    path = PureWindowsPath('C:/case #1/100%/project.sqlite3')
    assert project_database_uri(path) == path.as_uri()


@pytest.mark.skipif(os.name == 'nt', reason='exercises SQLite URI parser against a local POSIX file')
@pytest.mark.parametrize('mode', ['mode=ro&immutable=1', 'mode=rw'])
def test_sqlite_accepts_share_shaped_uri_without_a_network_request(tmp_path, mode):
    path = tmp_path / 'database #100%?.sqlite3'
    with closing(sqlite3.connect(path)) as database:
        database.execute('CREATE TABLE user_notes(note TEXT)')
    # POSIX accepts this double-leading-slash path as an alias for the local temporary file.
    windows = PureWindowsPath('/' + path.as_posix())
    with closing(sqlite3.connect(project_database_uri(windows) + '?' + mode, uri=True)) as reopened:
        assert reopened.execute('SELECT count(*) FROM user_notes').fetchone() == (0,)


@pytest.mark.skipif(os.name == 'nt', reason='maps a Windows share URI onto a local POSIX file')
def test_verified_backup_reopens_share_shaped_name_read_only(tmp_path, monkeypatch):
    path = tmp_path / 'pre-prune #100%?.sqlite3'
    with closing(sqlite3.connect(path)) as database:
        database.execute('CREATE TABLE user_notes(note TEXT)')
    windows_uri = PureWindowsPath('/' + path.as_posix()).as_uri()
    # Only the platform-specific URI spelling is simulated. Exercise the real database connection.
    monkeypatch.setattr(Path, 'as_uri', lambda self: windows_uri)
    with closing(verified_backup._open_read_only(path)) as reopened:
        assert reopened.execute('SELECT count(*) FROM user_notes').fetchone() == (0,)
        with pytest.raises(sqlite3.OperationalError, match='readonly'):
            reopened.execute("INSERT INTO user_notes VALUES ('must refuse')")
