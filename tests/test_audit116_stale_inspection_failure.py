"""Audit #116 P3: a failure from a superseded inspection must not touch the current project's Files status."""
from types import SimpleNamespace

import pytest

from patchtrace.ui import MainWindow


@pytest.mark.xfail(strict=True, reason='audit116#5: MainWindow._inspection_failed does not compare the failure '
                   'key with the current project key; owner GUI worker (ui.py is frozen)')
def test_stale_failure_is_ignored():
    emitted, logged = [], []
    stub = SimpleNamespace(_project_inspection_key=lambda: 'new', _inspection_error=None,
                           inspection_status=SimpleNamespace(emit=emitted.append),
                           logs=SimpleNamespace(appendPlainText=logged.append))
    MainWindow._inspection_failed(stub, 'boom', 'old')
    assert emitted == [] and logged == [] and stub._inspection_error is None
