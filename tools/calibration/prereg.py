"""C9 preregistration hash check (PREREG 8.2, 8.5 i; LBL-remaining 4.2 P-1).

Recomputes the SHA-256 of the preregistration file bytes and prints it, or verifies it against a recorded value
(`--expect`, or the `C9-PREREG-v1` row of a qa file). Read-only: it never writes the lock or edits any file.
Exit 0 match / plain print, 1 mismatch, 2 usage or nothing recorded.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from .common import sha256_bytes

DEFAULT_FILE = Path(__file__).resolve().parents[2] / 'docs' / 'plans' / 'c9-preregistration-v1.md'
QA_ROW = 'C9-PREREG-v1'
_SHA = re.compile(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])')


class PreregError(ValueError):
    pass


def prereg_sha256(path: Path) -> str:
    """SHA-256 of the file bytes exactly as on disk; CR is refused because the locked bytes are LF."""
    data = Path(path).read_bytes()
    if b'\r' in data:
        raise PreregError(f'{path}: contains CR bytes; the locked hash is over LF bytes (check .gitattributes)')
    return sha256_bytes(data)


def recorded_sha(qa_text: str, row: str = QA_ROW) -> str | None:
    """The 64-hex value on the first qa line that names `row` (lowercase hex only), else None."""
    for line in qa_text.splitlines():
        if row in line:
            found = _SHA.search(line)
            if found:
                return found.group(0)
    return None


def verify(path: Path, expected: str) -> bool:
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise PreregError('recorded SHA must be 64 lowercase hex characters')
    return prereg_sha256(path) == expected


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Recompute or verify the C9 preregistration SHA-256 (read-only).')
    parser.add_argument('--file', type=Path, default=DEFAULT_FILE)
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--expect', help='recorded SHA-256 to compare with')
    group.add_argument('--qa', type=Path, help=f'qa file whose {QA_ROW} row holds the recorded SHA-256')
    args = parser.parse_args(argv)
    try:
        actual = prereg_sha256(args.file)
        expected = args.expect
        if args.qa is not None:
            expected = recorded_sha(args.qa.read_text(encoding='utf-8'))
            if expected is None:
                print(f'no recorded SHA in {args.qa} for {QA_ROW}; computed {actual}', file=sys.stderr)
                return 2
        print(actual)
        if expected is None:
            return 0
        if verify(args.file, expected):
            print('MATCH')
            return 0
        print(f'MISMATCH: recorded {expected}', file=sys.stderr)
        return 1
    except (PreregError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
