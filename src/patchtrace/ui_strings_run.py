"""GUI-side run control for the Strings dock (WB3 s8): one background `run_strings` task per window.

Pure Python over the host's `TaskRunner` (no widgets): `start` submits the Qt-free run on the `strings.run` channel.
On the GUI thread (SQLite and the project lock live there) a current outcome is stale-checked against the open
project, persisted, then handed to `on_outcome`. Cancel reports `cancelled` at once (the worker's token stops the
tool); a project switch drops the result silently.
"""
from __future__ import annotations

from collections.abc import Callable

from .gui.qt.tasks import CancelToken, TaskFailure, TaskRunner
from .intelligence.tools.store import ToolStore
from .jobs import run_process
from .strings.run_service import StringsRunOutcome, StringsRunRequest, is_stale, persist, run_strings

CHANNEL = 'strings.run'
CANCELLED = StringsRunOutcome('cancelled', (), 'PT-STR-CANCEL', 'Extraction cancelled. Earlier results are unchanged.')


class StringsRunController:
    def __init__(self, tasks: TaskRunner, on_outcome: Callable[[StringsRunOutcome], None],
                 current: Callable[[], tuple[str, int]], store: Callable[[], ToolStore], *,
                 runner_fn: Callable = run_process) -> None:
        """`current()` is the open project's (id, revision); `store()` makes its `ToolStore`; both GUI thread."""
        self._tasks, self._on_outcome, self._runner_fn = tasks, on_outcome, runner_fn
        self._current, self._store = current, store
        self._request: StringsRunRequest | None = None
        self._generation = 0
        self._token: CancelToken | None = None

    @property
    def running(self) -> bool:
        return self._token is not None

    def start(self, request: StringsRunRequest) -> bool:
        if self._token is not None:
            return False
        self._generation += 1
        self._request = request
        generation, runner_fn = self._generation, self._runner_fn
        self._token = self._tasks.submit(
            CHANNEL, lambda token, _report: run_strings(request, token, runner_fn=runner_fn),
            on_result=lambda outcome: self._deliver(generation, outcome),
            on_error=lambda failure: self._deliver(generation, _unexpected(failure)))
        return True

    def cancel(self) -> None:
        if self._token is None:
            return
        self._tasks.cancel(CHANNEL)
        self._deliver(self._generation, CANCELLED)

    def project_changed(self) -> None:
        """The open project was replaced: stop the tool and never show its result."""
        if self._token is not None:
            self._tasks.cancel(CHANNEL)
        self._generation += 1
        self._token = None

    def _deliver(self, generation: int, outcome: StringsRunOutcome) -> None:
        if generation != self._generation or self._token is None:
            return
        self._token = None
        self._on_outcome(self._settle(outcome))

    def _settle(self, outcome: StringsRunOutcome) -> StringsRunOutcome:
        request = self._request
        if request is None or (outcome.state == 'cancelled' and not outcome.jobs):
            return outcome
        if is_stale(request, *self._current()):
            return StringsRunOutcome('stale', (), 'PT-STR-STALE', 'The project changed after these strings were '
                                     'requested.')
        try:
            persist(outcome, self._store())
        except Exception:  # noqa: BLE001 - the tables are still shown; storing is best effort
            return StringsRunOutcome('failed', (), 'PT-STR-SOURCE', 'The string results could not be stored.')
        return outcome


def _unexpected(failure: TaskFailure) -> StringsRunOutcome:
    return StringsRunOutcome('failed', (), 'PT-STR-SOURCE',
                             f'String extraction stopped unexpectedly ({failure.exception_class}).')
