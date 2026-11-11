# ruff: noqa: F811 - the main_window fixture is imported for its name, as in test_gui_host.py
"""Stress: thirty rapid project switches on the real main window, with docks open and hidden (GUI plan 8.2, 8.5).

Each switch goes through `MainWindow.set_service`, which closes the previous service. The test checks that the host
ends on the project it was last given, that a repeated switch to the same service closes nothing, and that the
dock state agrees with Qt throughout."""
from __future__ import annotations

from PySide6.QtWidgets import QApplication
from qt_support import join_gui_threads, main_window, settings  # noqa: F401

from patchtrace.service import ProjectService

SWITCHES = 30


def open_docks(window, panel_ids) -> None:
    for panel_id in panel_ids:
        window.panels.show_panel(panel_id)
    QApplication.processEvents()


def test_thirty_rapid_switches_end_on_the_last_project_with_docks_open_and_hidden(qtbot, main_window, tmp_path):
    window, host = main_window, main_window.panels
    window.show()
    qtbot.waitExposed(window)
    roots = [tmp_path / 'first', tmp_path / 'second']
    for root in roots:
        ProjectService.sample(root).close()
    shown = [pid for pid, panel in host.panels.items() if panel.dock is not None][:3]
    for index in range(SWITCHES):
        target = roots[index % 2]
        window.set_service(ProjectService.open(target))
        if index % 3 == 0:
            open_docks(window, shown)
        elif index % 3 == 1:
            for panel_id in shown:
                host.panels[panel_id].dock.hide()
        QApplication.processEvents()
        assert window.service.root == target.resolve()
        assert host.port.key().root == str(target.resolve())
        assert window.panels.port.project().id == window.service.project.id
    qtbot.waitUntil(lambda: not [pid for pid in shown if host.panels[pid].active != host.panels[pid].dock.isVisible()])


def test_switching_to_the_same_service_again_closes_nothing(qtbot, main_window, tmp_path):
    window = main_window
    window.show()
    qtbot.waitExposed(window)
    root = tmp_path / 'same'
    ProjectService.sample(root).close()
    service = ProjectService.open(root)
    window.set_service(service)
    for _ in range(10):
        window.set_service(window.service)
        QApplication.processEvents()
    assert window.service is service
    window.save_project()  # raises if the store was closed under the host
    assert window.service.project is not None


def test_a_switch_between_two_projects_replaces_the_service_and_its_root(qtbot, main_window, tmp_path):
    window = main_window
    window.show()
    qtbot.waitExposed(window)
    for name in ('a', 'b'):
        ProjectService.sample(tmp_path / name).close()
    first = ProjectService.open(tmp_path / 'a')
    window.set_service(first)
    window.set_service(ProjectService.open(tmp_path / 'b'))
    assert window.service is not first
    assert window.service.root == (tmp_path / 'b').resolve()
