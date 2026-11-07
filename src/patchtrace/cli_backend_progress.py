"""Bounded CLI stage deferral: observations never invoke a potentially blocking writer."""
from __future__ import annotations

from collections import deque
from collections.abc import Callable

from .models import JobEvent

_STAGE_LIMIT = 64
_OMITTED_LIMIT = (1 << 63) - 1


class CliBackendProgress:
    """One adapter per comparison; flush fixed stage events on the next non-observation event.

    The backend emits only analysis-progress/analysis-stage while supervising its child, then
    analysis-stopped after supervision returns. Writer calls therefore happen outside supervision.
    Terminal output may block normally; no writer thread, queue drain, or lock is needed here.
    """

    def __init__(self, write_event: Callable[[JobEvent], None]):
        self._write = write_event
        self._stages: deque[JobEvent] = deque(maxlen=_STAGE_LIMIT)
        self._omitted = 0

    def __call__(self, event: JobEvent) -> None:
        if event.stage == 'analysis-progress':
            return
        if event.stage == 'analysis-stage':
            if len(self._stages) == _STAGE_LIMIT:
                self._omitted = min(self._omitted + 1, _OMITTED_LIMIT)
            self._stages.append(event)
            return
        if self._omitted:
            count = (f'at least {self._omitted}' if self._omitted == _OMITTED_LIMIT else str(self._omitted))
            self._omitted = 0
            self._write(JobEvent(run_id=event.run_id, stage='analysis-stage',
                                 message=f'Omitted {count} earlier analysis-stage observations.'))
        while self._stages:
            self._write(self._stages.popleft())
        self._write(event)
