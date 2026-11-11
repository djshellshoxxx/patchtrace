"""Shared helpers for the CLI and persistence stress suite (QA-CLI). Hermetic: no network, no target execution.

Subprocesses run `python -m patchtrace` with the source tree on PYTHONPATH and the working directory moved away
from the repository, so the package under test is the one in this worktree, not a stale installed copy.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from patchtrace import cli
from patchtrace.service import ProjectService

SRC = Path(__file__).resolve().parents[2] / 'src'
EXIT_CODES = frozenset({cli.OK, cli.ENVIRONMENT, cli.RUNTIME, cli.NO_RESULTS, cli.CANCELLED})
CVE = 'CVE-2024-38063'


def run_main(argv, capsys) -> tuple[int, str, str]:
    """In-process `cli.main`; the exit code is the return value, never a SystemExit."""
    code = cli.main([str(item) for item in argv])
    out, err = capsys.readouterr()
    return code, out, err


def run_process(argv, cwd: Path, timeout: float = 120) -> subprocess.CompletedProcess:
    """A real process through the package entry point, for the exit status the shell would see."""
    env = dict(os.environ, PYTHONPATH=str(SRC), QT_QPA_PLATFORM='offscreen', PYTHONDONTWRITEBYTECODE='1')
    return subprocess.run([sys.executable, '-m', 'patchtrace', *[str(item) for item in argv]], cwd=str(cwd),
                          env=env, capture_output=True, text=True, encoding='utf-8', timeout=timeout)


def json_documents(text: str) -> list[dict]:
    """Every non-empty stdout line parsed as JSON; a `--json` run must yield exactly one."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def assert_clean(code: int, *streams: str) -> None:
    assert code in EXIT_CODES, f'exit {code} is outside 0/2/3/4/5'
    for stream in streams:
        assert 'Traceback' not in stream, stream[-2000:]


def make_sample(root: Path) -> Path:
    """A committed sample project (artifacts, one completed run) at `root`."""
    service = ProjectService.sample(root)
    service.close()
    return root
