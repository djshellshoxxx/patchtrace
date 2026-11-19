"""A stored FLOSS result remains bound to its actual artifact after a real orientation swap.

Only committed synthetic PE bytes and an authored fake FLOSS program are used.
"""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest
from test_ui_strings_run import make_project
from test_ui_strings_source import scan, start, store_floss, table_texts

from patchtrace.strings.cli import compute
from patchtrace.strings.contracts import StringsError
from patchtrace.strings.qt_panel import load_strings


def _args(source):
    return SimpleNamespace(source=source, anchors=None, min_length=4)


def _hashes(service):
    return {a.side: a.sha256 for a in service.project.artifacts}


def test_auto_does_not_use_pre_swap_floss_for_the_other_artifact(tmp_path):
    with make_project(tmp_path, 'floss-static') as service:
        store_floss(tmp_path, service, 'older', 'newer')
        before = compute(_args('auto'), service, threading.Event())
        assert set(before.sources.values()) == {'floss'}
        service.swap_orientation()
        expected = _hashes(service)
        after = compute(_args('auto'), service, threading.Event())
        assert {side: table.basis.artifact_sha256 for side, table in after.tables.items()} == expected
        assert set(after.sources.values()) == {'builtin-scan'}
        service.swap_orientation()
        restored = compute(_args('auto'), service, threading.Event())
        assert set(restored.sources.values()) == {'floss'}


def test_explicit_floss_refuses_pre_swap_records(tmp_path):
    with make_project(tmp_path, 'floss-static') as service:
        store_floss(tmp_path, service, 'older', 'newer')
        service.swap_orientation()
        with pytest.raises(StringsError, match='no stored FLOSS evidence'):
            compute(_args('floss'), service, threading.Event())


def test_dock_auto_uses_current_artifacts_after_orientation_swap(qtbot, tmp_path):
    with make_project(tmp_path, 'floss-static') as service:
        store_floss(tmp_path, service, 'older', 'newer')
        service.swap_orientation()
        controller = start(qtbot, service)
        scan(qtbot, controller)
        assert controller.view.kind == 'ready'
        assert all(row.source == 'Built-in scan' for row in controller.loaded.rows)


@pytest.mark.parametrize('change', ['missing', 'replaced'])
def test_stored_floss_does_not_hide_artifact_failure_and_keeps_prior_result(qtbot, tmp_path, change):
    mutate = False

    def loader(request, token, report):
        assert request.older_floss is not None and request.newer_floss is not None
        if mutate:
            request.older.chmod(0o600)  # authored copied fixture; allow replacement on Windows too
            request.older.unlink()
            if change == 'replaced':
                request.older.write_bytes(b'authored replacement; never executed')
        return load_strings(request, token, report)

    with make_project(tmp_path, 'floss-static') as service:
        store_floss(tmp_path, service, 'older', 'newer')
        controller = start(qtbot, service, loader=loader)
        scan(qtbot, controller)
        previous, rows = controller.loaded, table_texts(controller)
        assert controller.view.kind == 'ready' and rows
        mutate = True
        scan(qtbot, controller)
        assert controller.view.kind == 'error'
        assert controller.error[0] == 'PT-STR-INPUT', controller.error
        assert controller.loaded is previous and table_texts(controller) == rows
