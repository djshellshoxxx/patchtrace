"""Audit #116 P3: a failure from a superseded inspection must not touch the current project's Files status."""
from types import SimpleNamespace

from patchtrace.ui import MainWindow


def test_stale_failure_is_ignored():
    emitted, logged = [], []
    stub = SimpleNamespace(_project_inspection_key=lambda: 'new', _inspection_error=None,
                           inspection_status=SimpleNamespace(emit=emitted.append),
                           logs=SimpleNamespace(appendPlainText=logged.append))
    MainWindow._inspection_failed(stub, 'boom', 'old')
    assert emitted == [] and logged == [] and stub._inspection_error is None
