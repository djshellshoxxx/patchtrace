"""Read-only independent Strings qualification at f8f169f6; authored values/PEs only."""
from __future__ import annotations

import json
import subprocess
import threading

import pytest
from PySide6.QtCore import QSettings
from qt_support import join_gui_threads  # noqa: F401
from test_intel_tools_snapshot import publish_tool
from test_strings_composition import request_for, service  # noqa: F401
from test_strings_view_model import change
from test_ui_strings_composition import anchor_file, choose
from test_ui_strings_panel import loaded_of, start

from patchtrace import cli
from patchtrace.gui.qt.tasks import TaskFailure
from patchtrace.intelligence.tools.snapshot import capture_tool_sources
from patchtrace.service import ProjectService
from patchtrace.strings import compose
from patchtrace.strings.qt_panel import load_strings


@pytest.mark.parametrize('completion', ['pending', 'failed'])
def test_displayed_row_cannot_use_replacement_offsets_before_model_arrives(qtbot, monkeypatch, completion):
    original = change('independent same value')
    old = loaded_of(original)
    replacement = loaded_of(original.model_copy(update={
        'newer': original.newer.model_copy(update={'offsets': (0x950,)})}))
    controller, nav, _shell, _port = start(qtbot, loader=lambda *_: old)
    assert controller._select(original.id)
    old_row = controller.current_row()
    assert old_row.newer == '0x640'
    pending = []
    submit = controller.tasks.submit

    def defer(channel, fn, on_result, *args, **kwargs):
        if channel == 'strings-view':
            pending.append((fn, on_result, args[0]))
            return None
        return submit(channel, fn, on_result, *args, **kwargs)

    monkeypatch.setattr(controller.tasks, 'submit', defer)
    choose(controller, 'builtin')  # newly supported explicit input change
    controller.loader = lambda *_: replacement
    controller.scan()
    qtbot.waitUntil(lambda: bool(pending), timeout=5000)
    if completion == 'failed':
        pending[0][2](TaskFailure('AuthoredViewFailure'))
    assert controller.current_row() is old_row
    controller.open_hex()
    assert nav.offsets in ([], [('newer', 0x640)]), (
        'the displayed 0x640 row navigated using replacement comparison offsets', nav.offsets)


@pytest.mark.parametrize('choice', ['auto', 'floss', 'builtin'])
def test_real_cli_and_default_mainwindow_have_identical_comparison(qtbot, service, tmp_path, capsys,
                                                                monkeypatch, choice):
    from patchtrace.ui import MainWindow
    for side in ('older', 'newer'):
        publish_tool(service, side, label=f'independent {side} string')
    anchors = anchor_file(tmp_path)
    root = service.root
    service.close()

    def forbidden(*_args, **_kwargs):
        pytest.fail('ordinary Strings comparison launched a subprocess')

    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    code = cli.main(['strings', 'delta', str(root), '--source', choice, '--anchors', str(anchors), '--json'])
    output, _err = capsys.readouterr()
    assert code == 0
    document = json.loads(output)
    expected = document['result']
    expected.pop('sources')
    owner = ProjectService.open(root)
    window = MainWindow(owner, QSettings(str(tmp_path / 'review.ini'), QSettings.Format.IniFormat),
                        tmp_path / 'profiles')
    qtbot.addWidget(window)
    window.show()
    try:
        window.panels.show_panel('strings')
        controller = window.panels.controller('strings')
        assert controller is not None and controller.loaded is None
        choose(controller, choice)
        controller.anchor_dialog = lambda _parent: str(anchors)
        controller.choose_anchors()
        assert controller.loaded is None
        controller.panel.buttons['scan'].click()
        qtbot.waitUntil(lambda: controller.loaded is not None and not window.panels.tasks.busy(), timeout=10000)
        assert controller.loaded.delta.model_dump(mode='json') == expected
    finally:
        window.close()


def test_captured_tool_values_remain_usable_after_owner_is_closed(service, monkeypatch):
    for side in ('older', 'newer'):
        publish_tool(service, side, label=f'closed owner {side} string')
    sources = capture_tool_sources(service, engines=('floss',))
    request = request_for(service, source_choice='floss', tool_sources=sources)
    service.close()

    def forbidden(*_args, **_kwargs):
        pytest.fail('frozen source selection reopened a store')

    monkeypatch.setattr(ProjectService, 'open', forbidden)
    assert compose.stored_sources('floss', sources)['older'] is not None
    loaded = load_strings(request, threading.Event(), lambda *_: None)
    assert loaded.rows and all('FLOSS' in row.source for row in loaded.rows)
