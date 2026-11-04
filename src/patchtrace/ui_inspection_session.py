"""The main window's preliminary file inspection on the host TaskRunner (SPEC-26 D; GUI plan 8.5, F-gui-3).

Responsibility: hold the one current :class:`ProjectInspection`, start it for the window's identity key (root,
project, both artifact hashes), supersede it when the key changes, and close every result that is not or no longer
held, so no verified artifact reader stays open. The window keeps its key, status signal and log; this module decides
only which result is current. Used on the GUI thread; the worker runs the pure ``inspect_project_artifacts``."""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from functools import partial
from pathlib import Path

from .artifact_inspection import ProjectInspection, inspect_project_artifacts
from .gui.qt.tasks import CancelToken, TaskCancelled, TaskFailure, TaskRunner
from .models import Artifact
from .ui_inspection import side_summary

CHANNEL = 'inspection'
COMPLETE = 'File inspection complete · '
FAILED = 'File inspection failed: '


def _inspect(project_id: str, artifacts: tuple[Artifact, ...], root: Path, token: CancelToken,
             report: Callable) -> ProjectInspection:
    """Worker body: bounded read-only inspection; a result nobody will receive is closed here, not leaked."""
    try:
        result = inspect_project_artifacts(project_id, artifacts, root, token.is_set)
    except Exception:
        logging.getLogger(__name__).warning('File inspection failed', exc_info=True)
        raise
    if token.is_set():
        result.close()
        raise TaskCancelled
    return result


def _close(result: ProjectInspection) -> None:
    result.close()


class InspectionSession:
    def __init__(self, tasks: TaskRunner, key: Callable[[], object], *, on_status: Callable[[str], None],
                 on_ready: Callable[[], None], log: Callable[[str], None], channel: str = CHANNEL) -> None:
        """``key()`` is the window's current identity key (None: nothing to inspect); ``on_status`` gets the Files
        status line, ``on_ready()`` runs after a new result became current and ``log`` gets each failure line."""
        self._tasks, self._key, self._channel = tasks, key, channel
        self._on_status, self._on_ready, self._log = on_status, on_ready, log
        self._result: ProjectInspection | None = None
        self._result_key: object = None
        self._error: tuple[object, str] | None = None     # (key, exception class) of the last failed inspection
        self._running_key: object = None

    def current(self) -> ProjectInspection | None:
        if self._result is not None and self._result_key == self._key():
            return self._result
        return None

    def failure(self) -> str | None:
        """The exception class of the current key's failed inspection, else None."""
        if self._error is not None and self._error[0] == self._key():
            return self._error[1]
        return None

    def start(self, project_id: str, artifacts: Iterable[Artifact], root: Path) -> bool:
        """Start unless there is no key, the result for it is held, it is already running or the runner is shut
        down. Another key supersedes the running inspection; its result is closed and never shown."""
        key = self._key()
        if key is None or self._tasks.closed or (self._result is not None and self._result_key == key):
            return False
        if self._running_key == key and self._tasks.busy(self._channel):
            return False
        self._running_key = key
        self._tasks.submit(self._channel, partial(_inspect, project_id, tuple(artifacts), Path(root)),
                           partial(self._ready, key), partial(self._failed, key), on_discard=_close)
        return True

    def clear(self) -> None:
        """Close the held result and forget the last failure."""
        result, self._result, self._result_key, self._error = self._result, None, None, None
        if result is not None:
            result.close()

    def stop(self) -> None:
        """Cancel the running inspection (its result is closed when it arrives) and close the held one."""
        self._tasks.cancel(self._channel)
        self._running_key = None
        self.clear()

    def _ready(self, key: object, result: ProjectInspection) -> None:
        self._running_key = None
        if key != self._key():
            result.close()
            return
        self.clear()
        self._result, self._result_key = result, key
        self._on_status(COMPLETE + side_summary(result))
        self._on_ready()

    def _failed(self, key: object, failure: TaskFailure) -> None:
        self._running_key = None
        if key != self._key():
            return  # a superseded inspection must not overwrite the current project's status (audit #116 P3)
        self._error = (key, failure.exception_class)
        self._on_status(FAILED + failure.exception_class)
        self._log(FAILED + failure.exception_class)


__all__ = ['CHANNEL', 'COMPLETE', 'FAILED', 'InspectionSession']
