"""Single-use locked-test runner (spec §2.1): refuses a second run for one preregistration SHA.

The receipt is written (exclusive create) BEFORE evaluation, so a crashed run still counts as the one look.
"""
from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from pathlib import Path

from .common import canonical_json


class LockedTestError(RuntimeError):
    pass


def lock_path(corpus_dir: Path, prereg_sha: str) -> Path:
    if not re.fullmatch(r'[0-9a-f]{64}', prereg_sha):
        raise LockedTestError('preregistration SHA-256 required')
    return Path(corpus_dir) / f'locked-test-{prereg_sha}.lock'


def run_locked_test(corpus_dir: Path, prereg_sha: str, evaluate: Callable[[], dict], *,
                    now: Callable[[], str] | None = None) -> dict:
    path = lock_path(corpus_dir, prereg_sha)
    stamp = (now or (lambda: dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')))()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, 'xb') as handle:
            handle.write(canonical_json({'prereg_sha256': prereg_sha, 'started': stamp}) + b'\n')
    except FileExistsError:
        raise LockedTestError(f'locked-test already run for preregistration {prereg_sha[:12]}') from None
    result = evaluate()
    return {'receipt': str(path), 'started': stamp, 'result': result}
