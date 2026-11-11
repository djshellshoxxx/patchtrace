"""Security regression: a child process gets exactly the environment it is handed, and its arguments stay literal."""
from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

from patchtrace.jobs import run_process

PYTHON = str(Path(sys.executable).resolve())


def _minimal_env() -> dict[str, str]:
    return {key: os.environ[key] for key in ('PATH', 'SYSTEMROOT') if key in os.environ}


def _run(tmp_path: Path, env: dict[str, str], code: str, args: tuple[str, ...] = ()):
    return run_process([PYTHON, '-I', '-c', code, *args], cwd=tmp_path, env=env,
                       cancel=threading.Event(), timeout_seconds=30)


def test_the_child_sees_only_the_environment_it_was_given(tmp_path, monkeypatch):
    monkeypatch.setenv('PT_SEC_PARENT_SECRET', 'parent-only')
    env = {**_minimal_env(), 'PT_SEC_GIVEN': 'yes'}
    code = 'import json, os, sys; sys.stdout.write(json.dumps(sorted(k for k in os.environ if k.startswith("PT_SEC_"))))'
    result = _run(tmp_path, env, code)
    assert result.returncode == 0
    assert json.loads(result.log_tail) == ['PT_SEC_GIVEN']


def test_shell_metacharacters_in_arguments_stay_literal(tmp_path):
    pwned, pwned_too = tmp_path / 'pwned', tmp_path / 'pwned-too'
    hostile = f'x; touch {pwned} #$(touch {pwned_too}) `touch {pwned_too}` | cat'
    result = _run(tmp_path, _minimal_env(), 'import sys; sys.stdout.write(sys.argv[1])', (hostile,))
    assert result.returncode == 0
    assert result.log_tail == hostile
    assert not pwned.exists() and not pwned_too.exists()
