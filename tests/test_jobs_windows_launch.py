"""Launch hardening of `jobs.run_process` (process-supervision audit items 2, 3 and 5; architecture.md "Launch
argument rules"): batch-launcher arguments, the Windows environment block, the Job Object flags and handle release.
The pure checks run on every OS; the `.cmd` and Job Object cases run only in qa-windows."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fake_exe import make_fake_exe

from patchtrace import jobs
from patchtrace.jobs import run_process

PYTHON = str(Path(sys.executable).resolve())
METACHARACTERS = ['&', '|', '<', '>', '^', '%', '!', '\r', '\n']
META_IDS = ['amp', 'pipe', 'lt', 'gt', 'caret', 'pct', 'bang', 'cr', 'lf']
BATCH = ['C:\\tools\\X.CMD', 'C:\\tools\\x.bat.', 'C:\\tools\\x.bat ']
BATCH_IDS = ['upper-cmd', 'bat-dot', 'bat-space']


def run(argv, tmp_path, **kwargs):
    return run_process(argv, cwd=tmp_path, env=dict(os.environ), cancel=threading.Event(), **kwargs)


@pytest.mark.parametrize('program', BATCH, ids=BATCH_IDS)
@pytest.mark.parametrize('char', METACHARACTERS, ids=META_IDS)
def test_batch_launcher_refuses_cmd_metacharacters(program, char):
    hostile = f'C:\\case\\inputs\\older\\x{char}calc.exe'
    error = jobs._argv_error([program, '--flag', hostile], windows=True)
    assert error is not None and error.startswith('PT-BACKEND:') and 'configure the program .exe' in error
    assert 'calc' not in error  # the refused text is never echoed
    assert jobs._argv_error([f'C:\\t{char}ols\\x.cmd', '--flag'], windows=True) is not None  # argv[0] too


@pytest.mark.parametrize('char', METACHARACTERS, ids=META_IDS)
def test_metacharacters_pass_for_an_exe_and_off_windows(char):
    hostile = f'C:\\case\\x{char}calc.exe'
    for program in ['C:\\tools\\python.exe', 'C:\\tools\\x.cmd.exe', 'C:\\tools\\xbat', 'C:\\tools\\x.bat\\y.exe']:
        assert jobs._argv_error([program, hostile], windows=True) is None
    for program in [*BATCH, '/opt/tools/x.cmd']:
        assert jobs._argv_error([program, hostile], windows=False) is None


@pytest.mark.parametrize('arg', [
    'say "hi"', 'two words', 'a=b', '(x)',
    'import json,sys;print(json.dumps({"v":sys.version.split()[0],"ok":"a"=="a"}))',
], ids=['quote', 'space', 'eq', 'paren', 'probe'])
def test_batch_launcher_allows_quotes_spaces_equals_and_parentheses(arg):
    assert jobs._argv_error(['C:\\tools\\x.cmd', arg], windows=True) is None


@pytest.mark.parametrize('windows', [True, False], ids=['nt', 'posix'])
@pytest.mark.parametrize('argv', [
    ['C:\\tools\\python.exe', '-c', 'print(1)\0'], ['C:\\tools\\py\0thon.exe'], ['/opt/tools/x.cmd', '\0'],
], ids=['arg', 'program', 'batch'])
def test_nul_is_refused_on_every_os(argv, windows):
    error = jobs._argv_error(argv, windows=windows)
    assert error is not None and error.startswith('PT-BACKEND:')


def test_clean_argv_has_no_error():
    assert jobs._argv_error([PYTHON, '-c', 'print(1)'], windows=os.name == 'nt') is None


def test_run_process_refuses_a_nul_argument_and_spawns_nothing(tmp_path, monkeypatch):
    def spawn(*_args, **_kwargs):
        raise AssertionError('a child was spawned')

    monkeypatch.setattr(jobs.subprocess, 'Popen', spawn)
    monkeypatch.setattr(jobs, '_windows_process', spawn)
    with pytest.raises(ValueError, match='PT-BACKEND'):
        run([PYTHON, '-c', 'print(1)\0'], tmp_path, timeout_seconds=5)


def test_env_block_sorts_names_case_insensitively():
    block = jobs._windows_env_block({'b': '2', '_Z': 'z', 'C': '3', 'A': '1', '=C:': 'C:\\work'})
    # A code-point sort would put 'b' after '_Z'; Windows documents a case-insensitive order.
    assert block == '=C:=C:\\work\0A=1\0b=2\0C=3\0_Z=z\0\0'
    assert jobs._windows_env_block({}) == '\0\0'


@pytest.mark.parametrize('env', [
    {'A\0B': '1'}, {'A': '1\0'}, {'A=B': '1'}, {'': '1'},
], ids=['nul-name', 'nul-value', 'eq-name', 'empty-name'])
def test_env_block_refuses_nul_and_equals_in_a_name(env):
    with pytest.raises(ValueError, match='PT-BACKEND'):
        jobs._windows_env_block(env)


def test_job_flags_kill_on_close_and_die_on_unhandled_exception():
    assert jobs._job_limit_flags(None) == 0x2000 | 0x400
    assert jobs._job_limit_flags(1 << 30) == 0x2000 | 0x400 | 0x100
    for memory in (None, 1 << 30):
        assert not jobs._job_limit_flags(memory) & (0x800 | 0x1000)  # never allow breakaway from the job


@pytest.mark.skipif(os.name == 'nt', reason='POSIX process-group kill; the Job Object case is below')
def test_a_failing_group_kill_still_reaps_and_closes_the_pipe(tmp_path, monkeypatch):
    spawned, before = [], set(threading.enumerate())

    class Recording(subprocess.Popen):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            spawned.append(self)

    def refuse(_pid, _signal):
        for thread in set(threading.enumerate()) - before:  # let the reader see EOF first: deterministic close
            thread.join(timeout=10)
        raise PermissionError('PT-TEST: kill refused')

    monkeypatch.setattr(jobs.subprocess, 'Popen', Recording)
    monkeypatch.setattr(jobs.os, 'killpg', refuse)
    with pytest.raises(PermissionError, match='kill refused'):
        run([PYTHON, '-c', 'pass'], tmp_path, timeout_seconds=30)
    [child] = spawned
    assert child.returncode == 0
    assert child.stdout.closed


@pytest.mark.skipif(os.name != 'nt', reason='Windows Job Object handles')
def test_a_failing_kill_tree_still_closes_the_job_handles(tmp_path, monkeypatch):
    real, closed = jobs._windows_process, []

    def spawn(*args, **kwargs):
        child = real(*args, **kwargs)
        release = child.close

        def kill_tree():
            raise OSError('PT-TEST: kill refused')

        def close():
            closed.append(True)
            release()

        child.kill_tree, child.close = kill_tree, close
        return child

    monkeypatch.setattr(jobs, '_windows_process', spawn)
    with pytest.raises(OSError, match='kill refused'):
        run([PYTHON, '-c', 'pass'], tmp_path, timeout_seconds=30)
    assert closed == [True]


@pytest.mark.skipif(os.name != 'nt', reason='CreateProcessW runs .cmd launchers through cmd.exe only on Windows')
def test_cmd_launcher_refuses_an_injected_command(tmp_path):
    exe = make_fake_exe(tmp_path / 'bin', 'tool', 'print("ran")\n')
    with pytest.raises(ValueError, match='configure the program .exe'):
        run([str(exe), 'x&echo>marker'], tmp_path, timeout_seconds=60)
    assert not (tmp_path / 'marker').exists()


@pytest.mark.skipif(os.name != 'nt', reason='CreateProcessW runs .cmd launchers through cmd.exe only on Windows')
def test_cmd_launcher_still_runs_safe_arguments(tmp_path):
    exe = make_fake_exe(tmp_path / 'bin', 'tool', 'import json, sys\nprint(json.dumps(sys.argv[1:]))\n')
    args = ['two words', 'a=b', '(x)', 'say "hi"']
    result = run([str(exe), *args], tmp_path, timeout_seconds=60)
    assert (result.returncode, result.reason) == (0, None)
    assert json.loads(result.log_tail) == args
