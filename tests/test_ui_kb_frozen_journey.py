"""Run the packaged F8 control through actual desktop controllers and persisted data."""
from __future__ import annotations

import os
import socket

from patchtrace.gui.qt.kb_selftest import run_journey


def test_packaged_offline_kb_journey(qtbot, qapp, tmp_path, monkeypatch):
    def no_network(*_args, **_kwargs):
        raise AssertionError('The offline self-test attempted a network connection')
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    before = os.environ.get('LOCALAPPDATA')
    result = run_journey(qapp, tmp_path)
    assert result['matches'] == 4 and result['candidate_leads'] >= 4
    assert result['stale_after_reopen'] is True and result['synthetic'] is True
    assert os.environ.get('LOCALAPPDATA') == before
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.kbcorrelation.adapters.panel_snapshot import capture, load_snapshot
    from patchtrace.kbcorrelation.panel_qt import load_report
    from patchtrace.service import ProjectService
    root = tmp_path / 'KB-Δ-調査'
    workspace, project = root / 'app-data' / 'PatchTrace' / 'kb', root / 'comparison-ε'
    standalone = load_report(workspace, str(project), CancelToken())
    service = ProjectService.open(project)
    try:
        captured = load_snapshot(capture(service), workspace, CancelToken())
    finally:
        service.close()
    assert standalone == captured
