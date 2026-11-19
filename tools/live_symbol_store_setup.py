"""CI-only positive prerequisite for the native persisted-symbol-store matrix.

The later plain --no-symbols reproduction intentionally fails. These seed and
symbol-enabled setup commands must both succeed; never hide their exit status.
Only the installed interpreter runs. The input DLLs are never executed.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('analysed', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args(argv)
    seed = Path(__file__).resolve().with_name('seed_symbol_cache.py')
    commands = (
        [sys.executable, str(seed), str(args.output / 'symbols'),
         str(args.fixtures / 'old.dll'), str(args.fixtures / 'new.dll')],
        [sys.executable, '-m', 'ghidriff', str(args.analysed / 'old.dll'),
         str(args.analysed / 'new.dll'), '--output-path', str(args.output)],
    )
    for command in commands:
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as exc:
            print(f'Symbol-store setup failed with child exit {exc.returncode}.', file=sys.stderr)
            return exc.returncode if exc.returncode > 0 else 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
