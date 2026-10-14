"""Repeat the GUI test files in ONE pytest session to expose teardown aborts and thread leaks (GUI plan 8.8).

    python tools/qt_gate.py --repeat 20                    # Linux PR job and nightly (Windows PR job: 5)
    python tools/qt_gate.py --repeat 5 tests/test_gui_tasks.py

The files are listed ``--repeat`` times with ``--keep-duplicates`` (the method behind the ``docs/qa.md`` Qt abort
rows) and ``PYTHONFAULTHANDLER=1``, so a SIGABRT from a destroyed running QThread prints every thread's stack.
Exit status: pytest's; 134 style signal deaths are reported as ABORT and exit 1."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS = ('test_gui_*.py', 'test_ui_*.py', 'test_evidence_ui.py', 'test_tooltips.py')


def default_files(root: Path = ROOT) -> list[str]:
    found = {path for pattern in DEFAULT_PATTERNS for path in (root / 'tests').glob(pattern)}
    return sorted(path.relative_to(root).as_posix() for path in found)


def build_command(files: list[str], repeat: int, python: str = sys.executable) -> list[str]:
    if repeat < 1:
        raise ValueError('--repeat must be at least 1')
    if not files:
        raise ValueError('no GUI test files to repeat')
    return [python, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', '--keep-duplicates', *(files * repeat)]


def environment(base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env.setdefault('QT_QPA_PLATFORM', 'offscreen')
    env['PYTHONFAULTHANDLER'] = '1'
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--repeat', type=int, default=20, help='times to list each file (default 20)')
    parser.add_argument('--print-command', action='store_true', help='print the pytest command and exit')
    parser.add_argument('files', nargs='*', help='test files (default: every GUI test file)')
    args = parser.parse_args(argv)
    try:
        command = build_command(args.files or default_files(), args.repeat)
    except ValueError as exc:
        parser.error(str(exc))
    if args.print_command:
        print(' '.join(command))
        return 0
    code = subprocess.run(command, cwd=ROOT, env=environment(), check=False).returncode
    if code < 0 or code >= 128:
        print(f'qt_gate: ABORT, pytest died with status {code} (see the faulthandler dump above)', file=sys.stderr)
        return 1
    return code


if __name__ == '__main__':
    raise SystemExit(main())
