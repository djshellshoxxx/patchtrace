"""Current refusal and detached-state controls for the recovered Strings chooser."""
from __future__ import annotations

import threading

import pytest
from test_strings_view_model import change
from test_ui_strings_panel import SAMPLE, loaded_of, settle, start, status

from patchtrace.strings import copy
from patchtrace.strings.contracts import StringsError


def test_refused_source_request_cancels_pending_result_and_retains_prior_view(qtbot):
    controller, *_ = start(qtbot)
    earlier = controller.loaded
    assert earlier is SAMPLE
    entered, release = threading.Event(), threading.Event()
    pending = loaded_of(change('a later pending result'))

    def loader(*_):
        entered.set()
        assert release.wait(5)
        return pending

    controller.loader = loader
    controller.scan()
    qtbot.waitUntil(entered.is_set)
    try:
        combo = controller.panel.source
        combo.setCurrentIndex(combo.findData('floss'))
        controller.scan()
        assert controller.progress is None
        assert status(controller) == copy.STATES['floss-not-stored'].format(side='older')
    finally:
        release.set()
        settle(qtbot, controller)
    assert controller.loaded is earlier


def test_stored_floss_cannot_hide_changed_artifact_bytes(qtbot, tmp_path):
    from test_ui_strings_run import make_project
    from test_ui_strings_source import start as start_project
    from test_ui_strings_source import store_floss

    from patchtrace.strings.qt_panel import load_strings

    service = make_project(tmp_path, 'floss-static')
    try:
        store_floss(tmp_path, service, 'older', 'newer')
        requests = []

        def loader(request, *_):
            requests.append(request)
            return SAMPLE

        controller = start_project(qtbot, service, loader=loader)
        controller.scan()
        settle(qtbot, controller)
        request = requests[0]
        request.older.unlink()
        request.older.write_bytes(b'changed after source capture')
        with pytest.raises(StringsError, match='artifact cannot be read'):
            load_strings(request, threading.Event(), lambda *_: None)
    finally:
        service.close()


def test_pre_cancelled_worker_does_not_inspect_an_artifact(monkeypatch):
    from patchtrace.strings import pairing
    from patchtrace.strings.qt_panel import Request, load_strings

    def inspect(*_):
        raise AssertionError('cancelled request opened an artifact')

    monkeypatch.setattr(pairing, 'inspect_image', inspect)
    token = threading.Event()
    token.set()
    with pytest.raises(StringsError) as raised:
        load_strings(Request(None, None, None, 'a' * 64, 'b' * 64), token, lambda *_: None)
    assert raised.value.code == 'PT-STR-CANCEL'
