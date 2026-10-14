"""Live rz-diff acceptance (SPEC-28 §11). Runs the REAL pinned rizin; never part of the mocked test suite.

usage: live_rzdiff_check.py RZ_DIFF OLDER NEWER OUT_JSON --pin 0.9.1 --archive-sha256 HEX --os NAME
Exits non-zero on any failed assertion; the result JSON is written even on failure when possible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from patchtrace.secondary.rzdiff import probe, run_rzdiff


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('rz_diff', type=Path)
    parser.add_argument('older', type=Path)
    parser.add_argument('newer', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('--pin', required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--os', dest='os_name', required=True)
    args = parser.parse_args()
    result: dict = {'kind': 'live-rzdiff', 'mocked': False, 'os': args.os_name, 'pin': args.pin,
                    'archive_sha256': args.archive_sha256, 'status': 'failed', 'errors': []}
    started = time.monotonic()
    try:
        env = dict(os.environ)
        older, newer = args.older.resolve(), args.newer.resolve()
        result['fixture_sha256'] = {'older': sha256(older), 'newer': sha256(newer)}
        if result['fixture_sha256']['older'] == result['fixture_sha256']['newer']:
            raise AssertionError('fixture pair is identical')
        capability = probe(args.rz_diff, env, threading.Event())
        result['rizin_version'] = capability.version
        if not capability.supported:
            raise AssertionError(f'probe unsupported: {capability.reason}')
        if capability.version != args.pin:
            raise AssertionError(f'version {capability.version} != pin {args.pin}')
        # Flag drift must fail loudly: -h has to mention every flag the adapter freezes in argv().
        helped = subprocess.run([str(args.rz_diff), '-h'], capture_output=True, text=True, timeout=60)
        help_text = helped.stdout + helped.stderr
        result['help_flags'] = {flag: flag in help_text for flag in ('-C', '-j', '-t')}
        if not all(result['help_flags'].values()):
            raise AssertionError(f'rz-diff -h does not mention all frozen flags: {result["help_flags"]}')
        match_set = run_rzdiff(capability, older, newer, result['fixture_sha256']['older'],
                               result['fixture_sha256']['newer'], env=env, cancel=threading.Event(),
                               timeout_seconds=300)
        result['match_count'] = len(match_set.matches)
        result['output_sha256'] = match_set.file_sha256
        if not match_set.matches:
            raise AssertionError('rz-diff produced zero function matches')
        if (match_set.older_sha256, match_set.newer_sha256) != (result['fixture_sha256']['older'],
                                                                result['fixture_sha256']['newer']):
            raise AssertionError('match set hashes do not round-trip')
        result['status'] = 'passed'
    except Exception as exc:  # noqa: BLE001 - recorded, then signalled through the exit code
        result['errors'].append(f'{type(exc).__name__}: {exc}')
    result['duration_seconds'] = round(time.monotonic() - started, 2)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding='utf-8')
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
