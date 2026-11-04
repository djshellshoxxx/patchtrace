"""Audit #116 P3: a failure from a superseded inspection must not touch the current project's Files status."""
from types import SimpleNamespace

from patchtrace.gui.qt.tasks import TaskFailure
from patchtrace.ui_inspection_session import InspectionSession


def test_stale_failure_is_ignored():
    emitted, logged = [], []
    session = InspectionSession(SimpleNamespace(), lambda: 'new', on_status=emitted.append, on_ready=lambda: None,
                                log=logged.append)
    session._failed('old', TaskFailure('boom'))
    assert emitted == [] and logged == [] and session.failure() is None
