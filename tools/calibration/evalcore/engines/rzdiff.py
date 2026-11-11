"""rz-diff through the production secondary adapter (`registry.build_registry` + `scheduler.run_engines`: pinned-rizin
argv, bounded output, allow-listed environment). The engine images come from the private store, never from the corpus."""
from __future__ import annotations

import os
import shutil
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

from patchtrace.jobs import run_process
from patchtrace.secondary.engine_env import engine_env
from patchtrace.secondary.registry import build_registry
from patchtrace.secondary.scheduler import ProjectRef, run_engines

from ...tier_r import contracts as C
from .common import blocked, failed, from_match_set


def image_path(store: Path, side: C.ImageSide, symbols: str) -> tuple[Path, str]:
    sha = side.sha256 if symbols == 'hidden' else side.debug_sha256
    return Path(store) / 'images' / sha / side.file_name, sha


class RzDiffProvider:
    """rz-diff through `build_registry` + `run_engines` (the production adapter, pinned-rizin argv, bounded output)."""
    engine = 'rz-diff'

    def __init__(self, store: Path, *, executable: str | None = None, environ: Mapping[str, str] | None = None,
                 runner: Callable = run_process, deadline: float = 1800.0, run: Callable = run_engines):
        self.store, self.executable, self.runner, self.deadline, self.run = Path(store), executable, runner, deadline, run
        self.environ = os.environ if environ is None else environ

    def __call__(self, labels, symbols):
        exe = self.executable or shutil.which('rz-diff', path=self.environ.get('PATH'))
        if not exe:
            return blocked(self.engine, 'rz-diff executable not found (install the pinned rizin or pass --rz-diff)')
        (older, osha), (newer, nsha) = (image_path(self.store, s, symbols) for s in (labels.older, labels.newer))
        missing = [p.name for p in (older, newer) if not p.is_file()]
        if missing:
            return blocked(self.engine, f'engine image(s) not in the store: {", ".join(missing)}')
        outcomes = self.run(ProjectRef(older, newer, osha, nsha), ['rz-diff'], cancel=threading.Event(),
                            env=engine_env(self.environ, 'rz-diff'), registry=build_registry(rz_diff=exe),
                            runner=self.runner, per_engine_timeout={'rz-diff': self.deadline})
        outcome = outcomes[0]
        if outcome.match_set is not None:
            return from_match_set(self.engine, outcome.match_set, labels.older.image_base)
        message = outcome.error.message if outcome.error else outcome.run.status
        if outcome.run.status == 'unsupported':
            return blocked(self.engine, message)
        return failed(self.engine, f'{outcome.run.status}: {message}')
