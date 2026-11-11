"""Audit #116 P3: a failure from a superseded inspection must not touch the current project's Files status."""
from types import SimpleNamespace

import pytest

from patchtrace.ui import MainWindow


def test_stale_failure_is_ignored():
    emitted, logged = [], []
    stub = SimpleNamespace(_project_inspection_key=lambda: 'new', _inspection_error=None,
                           inspection_status=SimpleNamespace(emit=emitted.append),
                           logs=SimpleNamespace(appendPlainText=logged.append))
    MainWindow._inspection_failed(stub, 'boom', 'old')
    assert emitted == [] and logged == [] and stub._inspection_error is None


def test_stale_failure_preserves_current_error():
    emitted, logged = [], []
    current = ('new', 'current failure')
    stub = SimpleNamespace(_project_inspection_key=lambda: 'new', _inspection_error=current,
                           inspection_status=SimpleNamespace(emit=emitted.append),
                           logs=SimpleNamespace(appendPlainText=logged.append))
    MainWindow._inspection_failed(stub, 'old failure', 'old')
    assert stub._inspection_error == current and emitted == [] and logged == []


@pytest.mark.parametrize('key', ['new', None])
def test_current_and_unkeyed_failures_still_report(key):
    emitted, logged = [], []
    stub = SimpleNamespace(_project_inspection_key=lambda: 'new', _inspection_error=None,
                           inspection_status=SimpleNamespace(emit=emitted.append),
                           logs=SimpleNamespace(appendPlainText=logged.append))
    MainWindow._inspection_failed(stub, 'boom', key)
    assert stub._inspection_error == ('new', 'boom')
    assert emitted == logged == ['File inspection failed: boom']
