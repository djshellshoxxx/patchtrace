"""Run the pytest suite the way CI does, keep the log out of the terminal, and triage failures against a base ref.

usage: run_test_suite.py [--workers N] [--log FILE] [--base REF] [pytest args ...]

Steps: (1) environment check: Qt can load (a bare Linux container needs ``libegl1 libgl1 libxkbcommon0
libfontconfig1 libdbus-1-3``), and the optional extras CI installs (``.[dev,search,rules]``: rapidfuzz, yara_x,
iced_x86) are importable; a missing extra is printed with the tests it is known to fail; (2) pytest with
``QT_QPA_PLATFORM=offscreen`` and ``-p no:cacheprovider``, on ``--workers`` processes when ``pytest-xdist`` is
installed (``--dist loadfile``; xdist is a local convenience, not a repository dependency), full output written to
``--log``; (3) only the summary line and the ``FAILED``/``ERROR`` node ids are printed; (4) with ``--base REF`` each
failing node id is run again on a temporary detached worktree of REF (``git worktree add``, removed afterwards), so a
failure is classified ``also fails on REF`` (pre-existing or environmental) or ``new``. Nothing is pushed, fetched or
deleted except that temporary worktree. Exit code: pytest's.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILED = re.compile(r'^(FAILED|ERROR) (\S+)')
EXTRAS = {'rapidfuzz': 'search extra: tests/test_search_synergy.py, tests/test_search_capability.py fail without it',
          'yara_x': 'rules extra: rules engine tests skip or fail without it',
          'iced_x86': 'rules extra: disassembly-backed rules tests skip or fail without it'}


def environment_report() -> list[str]:
    """Human-readable problems with this interpreter; empty when it matches CI's install."""
    notes = []
    try:
        from PySide6 import QtGui  # noqa: F401
    except ImportError as exc:
        notes.append(f'Qt cannot load ({exc}); on Debian/Ubuntu install libegl1 libgl1 libxkbcommon0 libfontconfig1 '
                     'libdbus-1-3')
    for module, effect in EXTRAS.items():
        if importlib.util.find_spec(module) is None:
            notes.append(f'{module} missing ({effect}); CI installs .[dev,search,rules]')
    return notes


def failing_ids(log_text: str) -> list[str]:
    """Node ids of ``FAILED``/``ERROR`` summary lines, in order, without duplicates or the trailing message."""
    found = []
    for line in log_text.splitlines():
        match = FAILED.match(line)
        if match and match.group(2) not in found:
            found.append(match.group(2))
    return found


def summary_line(log_text: str) -> str:
    lines = [line for line in log_text.splitlines() if re.search(r'\b(passed|failed|error)\b', line)]
    return lines[-1].strip('= ') if lines else '(no pytest summary line; see the log)'


def pytest_command(workers: int, extra: list[str]) -> list[str]:
    command = [sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider']
    if workers > 1 and importlib.util.find_spec('xdist') is not None:
        command += ['-n', str(workers), '--dist', 'loadfile']
    return command + extra


def run(command: list[str], cwd: Path, log: Path, env: dict[str, str]) -> tuple[int, str]:
    with log.open('w', encoding='utf-8') as out:
        code = subprocess.run(command, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, check=False).returncode
    return code, log.read_text(encoding='utf-8', errors='replace')


def triage(ids: list[str], base: str, log: Path, env: dict[str, str]) -> dict[str, bool]:
    """For each node id: True when it also fails on ``base``."""
    work = Path(tempfile.mkdtemp(prefix='pt-base-'))
    tree = work / 'tree'
    subprocess.run(['git', '-C', str(ROOT), 'worktree', 'add', '--detach', '-q', str(tree), base], check=True)
    try:
        base_env = dict(env, PYTHONPATH=str(tree / 'src') + os.pathsep + env.get('PYTHONPATH', ''))
        present = [i for i in ids if (tree / i.split('::')[0]).exists()]
        _, text = run(pytest_command(1, present), tree, log, base_env) if present else (0, '')
        failing = set(failing_ids(text))
        return {i: (i in failing) if i in present else False for i in ids}
    finally:
        subprocess.run(['git', '-C', str(ROOT), 'worktree', 'remove', '--force', str(tree)], check=False)
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--workers', type=int, default=os.cpu_count() or 1)
    parser.add_argument('--log', type=Path, default=ROOT / 'build' / 'test-suite.log')
    parser.add_argument('--base', metavar='REF', help='re-run failures on a worktree of REF (for example origin/main)')
    args, extra = parser.parse_known_args(argv)
    for note in environment_report():
        print(f'ENV: {note}')
    args.log.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen')
    code, text = run(pytest_command(args.workers, extra), ROOT, args.log, env)
    ids = failing_ids(text)
    print(summary_line(text))
    print(f'log: {args.log}')
    verdicts = triage(ids, args.base, args.log.with_suffix('.base.log'), env) if args.base and ids else {}
    for node in ids:
        tag = '' if not verdicts else ('  [also fails on base]' if verdicts[node] else '  [new]')
        print(f'  {node}{tag}')
    return code


if __name__ == '__main__':
    raise SystemExit(main())
