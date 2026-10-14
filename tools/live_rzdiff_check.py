"""Live rz-diff acceptance (SPEC-28 §11). Runs the REAL pinned rizin; never part of the mocked test suite.

usage: live_rzdiff_check.py RZ_DIFF OLDER NEWER OUT_JSON --pin 0.9.1 --archive-sha256 HEX --os NAME
Exits non-zero on any failed assertion; the result JSON is written even on failure when possible.
It drives rz-diff through the production path: the shared `engine_env` allow-list, the registry adapter and
`scheduler.run_engines` (not a hand-built environment or a direct `run_rzdiff` call).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
from pathlib import Path

from patchtrace.jobs import run_process
from patchtrace.secondary.engine_env import engine_env
from patchtrace.secondary.registry import build_registry
from patchtrace.secondary.scheduler import ProjectRef, run_engines

FROZEN_FLAGS = ('-C', '-j', '-t')
_OPTION = re.compile(r'^\s*(-[A-Za-z0-9])(?![A-Za-z0-9-])', re.MULTILINE)


def help_options(text: str) -> set[str]:
    """Options declared at the start of a help line (`  -C   ...`), not any substring of the text."""
    return set(_OPTION.findall(text))


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
        env = engine_env(os.environ, 'rz-diff')
        older, newer = args.older.resolve(), args.newer.resolve()
        result['fixture_sha256'] = {'older': sha256(older), 'newer': sha256(newer)}
        if result['fixture_sha256']['older'] == result['fixture_sha256']['newer']:
            raise AssertionError('fixture pair is identical')
        registry = build_registry(rz_diff=str(args.rz_diff.resolve()))
        capability = registry['rz-diff'].probe(env, threading.Event())
        result['rizin_version'] = capability.version
        if not capability.supported:
            raise AssertionError(f'probe unsupported: {capability.reason}')
        if capability.version != args.pin:
            raise AssertionError(f'version {capability.version} != pin {args.pin}')
        # Flag drift must fail loudly: -h has to declare every flag the adapter freezes in argv().
        with tempfile.TemporaryDirectory(prefix='patchtrace-rzhelp-') as cwd:
            helped = run_process([capability.path, '-h'], cwd=Path(cwd), env=env, cancel=threading.Event(),
                                 timeout_seconds=60, log_limit=256 * 1024)
        declared = help_options(helped.log_tail)
        result['help_flags'] = {flag: flag in declared for flag in FROZEN_FLAGS}
        if not all(result['help_flags'].values()):
            raise AssertionError(f'rz-diff -h does not declare all frozen flags: {result["help_flags"]}')
        project = ProjectRef(older, newer, result['fixture_sha256']['older'], result['fixture_sha256']['newer'])
        (outcome,) = run_engines(project, ['rz-diff'], cancel=threading.Event(), env=env, registry=registry,
                                 per_engine_timeout={'rz-diff': 300.0})
        result['engine_run'] = {'status': outcome.run.status, 'error_code': outcome.run.error_code,
                                'argv_digest': outcome.run.argv_digest}
        if outcome.run.status != 'ok' or outcome.match_set is None:
            raise AssertionError(f'run_engines status {outcome.run.status} ({outcome.run.error_code})')
        match_set = outcome.match_set
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
