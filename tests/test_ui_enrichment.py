"""Desktop wiring for Phase 2 ranking: worker run, owner-thread publish, ordering, signal navigation."""
from __future__ import annotations

import pytest
from PySide6.QtCore import QSettings, Qt

from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    view = MainWindow(service, QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    view.show()
    yield view
    if view.worker:
        view.cancel_job()
        qtbot.waitUntil(lambda: view.worker is None, timeout=5000)


def test_rank_changes_orders_matches_and_navigates_to_signal(window, qtbot, tmp_path):
    assert window.rank_action.isEnabled()
    window.rank_action.trigger()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    assert window._ranking, window.logs.toPlainText()
    assert window.order.currentIndex() == 1
    top = window.navigator.item(0)
    best = min(window._ranking.values(), key=lambda e: e.rank)
    assert top.data(Qt.ItemDataRole.UserRole) == best.match_id
    assert top.text().startswith(f'[{best.score:>3}]')
    window.navigator.setCurrentItem(top)
    signals = [window.signal_list.item(i) for i in range(window.signal_list.count())
               if window.signal_list.item(i).data(Qt.ItemDataRole.UserRole)]
    assert signals and signals[0].text().startswith('BND')
    window.signal_list.setCurrentItem(signals[0])
    assert window.views['newer'].textCursor().hasSelection()


def test_stored_ranking_reloads_and_goes_stale_after_rematch(window, qtbot):
    window.rank_action.trigger()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    root = window.service.root
    window.service.close()
    window.service = None
    window.set_service(ProjectService.open(root))
    assert window._ranking
    project = window.service.project
    match = next(m for m in project.matches if m.older and m.newer)
    window.service._commit(project.model_copy(update={'matches': [
        m.model_copy(update={'manual': True}) if m.id == match.id else m for m in project.matches]}))
    window.refresh()
    assert not window._ranking
    assert 'stale' in window._ranking_note
