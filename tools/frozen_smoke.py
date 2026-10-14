"""Headless smoke of the frozen desktop executable (windows-acceptance spec section 2, A1-A4).

usage: frozen_smoke.py PATH_TO_PatchTrace.exe

A1 every command answers --help with exit 0 and `usage:` on stdout; A2 unknown command exits 2 without a
traceback; A3 missing project exits 2 with a message and no traceback; A4 --self-test exits 0 and removes its
patchtrace-self-test-* temp directory. A5 (JSON contract on a sample project) is not covered here.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

COMMANDS = ('rank', 'flags', 'correlate', 'cache', 'acquire', 'series', 'secondary')


def run(exe: str, *args: str, env: dict | None = None, timeout: int = 120):
    return subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout, env=env)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    exe = str(Path(sys.argv[1]).resolve())
    failures: list[str] = []

    def check(label: str, ok: bool, detail: str = '') -> None:
        print(f'{"PASS" if ok else "FAIL"} {label}')
        if not ok:
            failures.append(f'{label}: {detail[-400:]}')

    for command in COMMANDS:
        r = run(exe, command, '--help')
        check(f'A1 {command} --help', r.returncode == 0 and 'usage:' in r.stdout, f'rc={r.returncode} {r.stderr}')
    r = run(exe, 'bogus-command')
    check('A2 unknown command exits 2, no traceback', r.returncode == 2 and 'Traceback' not in r.stderr,
          f'rc={r.returncode} {r.stderr}')
    with tempfile.TemporaryDirectory(prefix='pt-smoke-') as scratch:
        missing = str(Path(scratch) / 'does' / 'not' / 'exist')
        r = run(exe, 'rank', missing)
        check('A3 missing project exits 2 with message, no traceback',
              r.returncode == 2 and bool(r.stderr.strip()) and 'Traceback' not in r.stderr,
              f'rc={r.returncode} {r.stderr}')
        temp = Path(scratch) / 'tmp'
        temp.mkdir()
        env = dict(os.environ, QT_QPA_PLATFORM='offscreen', TMP=str(temp), TEMP=str(temp), TMPDIR=str(temp))
        r = run(exe, '--self-test', env=env, timeout=180)
        check('A4 --self-test exits 0', r.returncode == 0, f'rc={r.returncode} {r.stdout} {r.stderr}')
        left = [p.name for p in temp.glob('patchtrace-self-test-*')]
        check('A4 self-test temp directory removed', not left, str(left))
    if failures:
        print('\n'.join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
