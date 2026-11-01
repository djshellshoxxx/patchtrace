"""The default KB loader must read the current GUI-owned project without a second writer."""
from __future__ import annotations

from PySide6.QtCore import QSettings

from patchtrace.enrichment.pipeline import publish, run
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def test_default_kb_panel_reads_ranked_gui_owned_project(qtbot, tmp_path, monkeypatch):
    service = ProjectService.sample(tmp_path / 'project')
    publish(EnrichmentStore(service.store), service.project, run(service.project))
    window = MainWindow(service=service,
                        settings=QSettings(str(tmp_path / 'settings.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    try:
        def no_second_open(*_args, **_kwargs):
            raise AssertionError('The worker reopened the GUI-owned project')
        monkeypatch.setattr(ProjectService, 'open', no_second_open)
        window.panels.show_panel('kb')
        controller = window.panels.controller('kb')
        controller.workspace = tmp_path / 'empty-workspace'
        controller.project_changed(controller.port.key())
        qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=10000)
        assert controller.model is not None, controller.panel.state_view.status_label().full_text()
        assert controller.model.report.state == 'no-advisory'
        assert controller.model.lead_count == len(service.project.matches)
    finally:
        window.close()


def test_captured_rows_are_detached_and_current_run_guard_is_preserved(tmp_path):
    from patchtrace.gui.qt.tasks import CancelToken
    from patchtrace.kbcorrelation.adapters.panel_snapshot import capture, load_snapshot
    service = ProjectService.sample(tmp_path / 'project')
    try:
        publish(EnrichmentStore(service.store), service.project, run(service.project))
        snapshot = capture(service)
        previous = load_snapshot(snapshot, tmp_path / 'empty-workspace', CancelToken())
        service.swap_orientation()
        current = capture(service)
    finally:
        service.close()
    # Decoding the capture needs no live project connection, even after mutation and close.
    repeated = load_snapshot(snapshot, tmp_path / 'empty-workspace', CancelToken())
    assert repeated == previous
    assert repeated.unattributed
    stale = load_snapshot(current, tmp_path / 'empty-workspace', CancelToken())
    assert not stale.unattributed and not stale.groups
