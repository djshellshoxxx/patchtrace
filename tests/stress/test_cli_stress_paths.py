"""QA-CLI: unusual project paths (unicode, spaces and shell metacharacters, long, relative, file-not-directory) and
read-only project locations. The read-only checks need a non-root process to be meaningful, so they say so."""
from __future__ import annotations

import os
import sqlite3
import sys

import pytest
from cli_stress_support import assert_clean, json_documents, make_sample, run_main, run_process

from patchtrace import cli
from patchtrace.enrichment import pipeline

UNICODE_NAME = 'проект α 日本 café'
METACHARACTERS = "case #1 (copy) & more; $HOME 'quoted' %TEMP%"
WINDOWS_MAX_PATH = 260


@pytest.mark.parametrize('name', [UNICODE_NAME, METACHARACTERS], ids=['unicode-and-spaces', 'shell-metacharacters'])
def test_persisting_rank_on_unusual_project_name(name, tmp_path, capsys):
    root = make_sample(tmp_path / name)
    code, out, err = run_main(['rank', root, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.OK, err[-500:]
    documents = json_documents(out)
    assert len(documents) == 1 and documents[0]['status'] == 'complete'
    assert documents[0]['result']['entries'], 'ranking must list the sample pair'


def test_long_nested_project_path(tmp_path, capsys):
    segments = [('segment' + str(i) + 'x' * 50) for i in range(4)]
    root = tmp_path.joinpath(*segments)
    if sys.platform == 'win32' and len(str(root)) >= WINDOWS_MAX_PATH:
        pytest.skip('Windows MAX_PATH (260) without the long-path opt-in: the path cannot be created here')
    make_sample(root)
    assert len(str(root)) > 200
    code, out, err = run_main(['rank', root, '--json', '--dry-run'], capsys)
    assert_clean(code, out, err)
    assert code == cli.OK, err[-500:]
    assert len(json_documents(out)) == 1


def test_relative_and_trailing_separator_paths(tmp_path, monkeypatch, capsys):
    make_sample(tmp_path / 'case')
    monkeypatch.chdir(tmp_path)
    for argv in (['rank', 'case', '--json', '--dry-run'], ['rank', 'case' + os.sep, '--json', '--dry-run'],
                 ['rank', './case/', '--json', '--dry-run']):
        code, out, err = run_main(argv, capsys)
        assert_clean(code, out, err)
        assert code == cli.OK, (argv, err[-500:])
        assert len(json_documents(out)) == 1


def test_project_path_that_is_a_file_is_an_environment_error(tmp_path, capsys):
    plain = tmp_path / 'not-a-directory.sqlite3'
    plain.write_bytes(b'SQLite format 3\x00' + b'\x00' * 100)
    code, out, err = run_main(['rank', plain, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.ENVIRONMENT, err[-500:]
    documents = json_documents(out)
    assert len(documents) == 1 and documents[0]['status'] == 'failed'


def test_unicode_path_through_the_real_entry_point(tmp_path):
    root = make_sample(tmp_path / UNICODE_NAME)
    result = run_process(['rank', root, '--json', '--dry-run'], tmp_path)
    assert_clean(result.returncode, result.stdout, result.stderr)
    assert result.returncode == cli.OK, result.stderr[-500:]
    assert len(json_documents(result.stdout)) == 1


def _readonly_sqlite_error(*_args, **_kwargs):
    raise sqlite3.OperationalError('attempt to write a readonly database')


def test_read_only_store_on_persisting_rank_is_a_runtime_error_with_a_document(tmp_path, monkeypatch, capsys):
    """Deterministic stand-in for a read-only project: the write fails inside publish and the verb must map it."""
    root = make_sample(tmp_path / 'case')
    monkeypatch.setattr(pipeline, 'publish', _readonly_sqlite_error)
    code, out, err = run_main(['rank', root, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.RUNTIME, (code, err[-500:])
    documents = json_documents(out)
    assert len(documents) == 1 and documents[0]['status'] == 'failed'


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX permission bits')
def test_read_only_project_directory_for_dry_run_and_persisting_rank(tmp_path, capsys):
    if hasattr(os, 'geteuid') and os.geteuid() == 0:
        pytest.skip('running as root: directory permission bits do not stop root; runs on the non-root CI matrix')
    root = make_sample(tmp_path / 'case')
    root.chmod(0o555)
    try:
        code, out, err = run_main(['rank', root, '--json', '--dry-run'], capsys)
        assert_clean(code, out, err)
        assert code == cli.OK, err[-500:]
        code, out, err = run_main(['rank', root, '--json'], capsys)
        assert_clean(code, out, err)
        assert code in {cli.ENVIRONMENT, cli.RUNTIME}, (code, err[-500:])
        assert len(json_documents(out)) == 1
    finally:
        root.chmod(0o755)


@pytest.mark.xfail(strict=True, reason='QA-CLI-3: cache verify on a --cache-dir that is a regular file exits 3 '
                   '(status "failed", error "_Unsafe"); the expected config exit is 2, but cache status on the same '
                   'path is pinned at 3 by tests/test_cli.py: needs a decision on one exit code for both')
def test_cache_verify_on_a_file_reports_failure(tmp_path, capsys):
    cache_file = tmp_path / 'cache-file'
    cache_file.write_text('not a directory\n', encoding='utf-8', newline='\n')
    code, out, err = run_main(['cache', 'verify', '--cache-dir', cache_file, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.ENVIRONMENT, (code, out[-300:])


def test_rank_reports_an_unusable_cache_dir(tmp_path, capsys):
    root = make_sample(tmp_path / 'case')
    cache_file = tmp_path / 'cache-file'
    cache_file.write_text('not a directory\n', encoding='utf-8', newline='\n')
    code, out, err = run_main(['rank', root, '--cache-dir', cache_file, '--json', '--dry-run'], capsys)
    assert_clean(code, out, err)
    document = json_documents(out)[0]
    assert code == cli.ENVIRONMENT or any('cache' in warning.lower() for warning in document['warnings']), \
        document['warnings']
