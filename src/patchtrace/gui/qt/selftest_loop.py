"""Bounded Qt self-test lifecycle and exclusive scratch ownership, never normal application flow."""
from __future__ import annotations

import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer

CHILD = 'KB-Δ-調査'


def _identity(path: Path) -> tuple[int, int]:
    observed = path.lstat()
    if not stat.S_ISDIR(observed.st_mode):
        raise RuntimeError('Desktop self-test workspace ownership changed; files retained')
    return observed.st_dev, observed.st_ino


class Workspace:
    """Record the parent and exclusively claimed child; supplied parents are never removed."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.path = self.root / CHILD
        self._root_identity = _identity(self.root)
        self._child_identity: tuple[int, int] | None = None
        self._attempted = False
        self.retain = False

    def claim(self) -> Path:
        self.check()
        self._attempted = True
        try:
            self.path.mkdir()
        except FileExistsError as error:
            self.retain = True
            raise RuntimeError('Desktop self-test child already exists; unowned files retained') from error
        self._child_identity = _identity(self.path)
        return self.path

    def check(self) -> None:
        try:
            valid = _identity(self.root) == self._root_identity
            if self._attempted:
                valid = valid and self._child_identity is not None and _identity(self.path) == self._child_identity
        except OSError:
            valid = False
        if not valid or self.retain:
            raise RuntimeError('Desktop self-test workspace ownership changed or cleanup incomplete; files retained')

    def remove(self) -> None:
        self.check()
        # Only the explicit entry owns this temporary parent. Refuse unrelated top-level additions too.
        expected = {self.path} if self._child_identity is not None else set()
        if set(self.root.iterdir()) != expected:
            raise RuntimeError('Desktop self-test workspace contains unowned paths; files retained')
        # Windows cannot remove immutable project copies until their permissions are restored.
        for path in self.root.rglob('*'):
            if not path.is_symlink() and path.is_file():
                path.chmod(0o600)
        self.check()
        shutil.rmtree(self.root)


@contextmanager
def temporary_workspace(*, directory: Path | None = None):
    """Clean only an exclusively created, still-owned root after the caller releases its resources.

    Identity checks cover observed replacement in a cooperative filesystem. They do not provide
    an atomic transaction against arbitrary same-user namespace changes during recursive removal.
    """
    workspace = Workspace(Path(tempfile.mkdtemp(prefix='patchtrace-self-test-', dir=directory)))
    failure = None
    try:
        yield workspace
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            workspace.remove()
        except BaseException as cleanup:
            if failure is None:
                raise
            failure.add_note(f'Desktop self-test cleanup also failed: {type(cleanup).__name__}; files retained')


@dataclass(frozen=True)
class Wait:
    ready: Callable[[], bool]
    description: str
    timeout: float = 10


class _Runner(QObject):
    """One continuation per timer turn lets normal queued signals and deletion events run."""

    def __init__(self, app, steps, timeout):
        super().__init__()
        self.app, self.steps = app, steps
        self.wait: Wait | None = None
        self.deadline = 0.0
        self.overall_deadline = time.monotonic() + timeout
        self.result = None
        self.error: BaseException | None = None
        self.done = False
        self.timer = QTimer(self)
        self.timer.setInterval(2)
        self.timer.timeout.connect(self.advance)

    def finish(self, error: BaseException | None = None) -> None:
        self.error = error
        try:
            self.steps.close()
        except BaseException as cleanup:
            if self.error is None:
                self.error = cleanup
            else:
                self.error.add_note(f'Desktop self-test cleanup also failed: {type(cleanup).__name__}')
        self.done = True

    def advance(self) -> None:
        if self.done:
            self.timer.stop()
            self.app.exit(1 if self.error else 0)
            return
        try:
            now = time.monotonic()
            if now >= self.overall_deadline:
                raise RuntimeError('Desktop self-test overall deadline exceeded')
            if self.wait is not None:
                if now >= self.deadline:
                    raise RuntimeError('Desktop self-test timed out: ' + self.wait.description)
                if not self.wait.ready():
                    return
            self.wait = next(self.steps)
            if self.wait is not None:
                self.deadline = time.monotonic() + self.wait.timeout
        except StopIteration as completed:
            self.result = completed.value
            self.finish()
        except BaseException as error:
            # Qt callback exceptions otherwise get printed and swallowed instead of failing the entry.
            self.finish(error)


def run_steps(app, steps: Generator, *, timeout: float = 45) -> dict:
    if QThread.currentThread() != app.thread() or app.thread().loopLevel() != 0:
        raise RuntimeError('Desktop self-test requires the GUI thread before its event loop starts')
    runner = _Runner(app, steps, timeout)
    quit_on_close = app.quitOnLastWindowClosed()
    app.setQuitOnLastWindowClosed(False)
    try:
        runner.timer.start()
        app.exec()
        if not runner.done:
            runner.finish(RuntimeError('Desktop self-test event loop exited before completion'))
        if runner.error is not None:
            raise runner.error
        return runner.result
    finally:
        runner.timer.stop()
        if not runner.done:
            runner.finish(sys.exception())
        app.setQuitOnLastWindowClosed(quit_on_close)
        runner.deleteLater()
