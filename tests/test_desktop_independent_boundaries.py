"""Independent authored controls for desktop e8692010; not native assistive technology."""
from dataclasses import replace

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QMainWindow, QTabBar
from qt_support import join_gui_threads  # noqa: F401
from test_signal_location_navigation import _item, _window

from patchtrace.enrichment import identity, pipeline, views
from patchtrace.enrichment.contracts import SourceLocation
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.gui.qt.docks import name_tab_bars
from patchtrace.gui.tips import register_gui_tips
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def test_stored_signal_cannot_borrow_a_valid_location_from_another_pairing(tmp_path, qtbot, monkeypatch):
    window, signal_id, _location, _errors, _revealed = _window(tmp_path, qtbot, monkeypatch)
    selected = window.current_match().id
    result = pipeline.run(window.project)
    foreign = next(function for match in result.views.matches if match.match_id != selected
                   for function in match.newer if function.code)
    location = SourceLocation(side=foreign.side, artifact_id=foreign.artifact_id, run_id=foreign.run_id,
                              function_id=foreign.id, representation='decompiled', start_line=1, end_line=1,
                              excerpt_sha256=identity.excerpt_sha256(foreign.code[:1]), address=foreign.address)
    assert views.validate_location(window.project, location).id == foreign.id
    signal_sets = []
    for item in result.signal_sets:
        if item.match_id == selected:
            item = item.model_copy(update={'signals': tuple(signal.model_copy(update={'locations': (location,)})
                                                            if signal.signal_id == signal_id else signal
                                                            for signal in item.signals)})
        signal_sets.append(item)
    pipeline.publish(EnrichmentStore(window.service.store), window.project,
                     replace(result, signal_sets=tuple(signal_sets)))
    root = window.service.root
    window.close()
    reopened = MainWindow(ProjectService.open(root),
                          QSettings(str(tmp_path / 'independent.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(reopened)
    reopened.show()
    errors = []
    monkeypatch.setattr(reopened, 'show_error', errors.append)
    try:
        target = next(reopened.navigator.item(index) for index in range(reopened.navigator.count())
                      if reopened.navigator.item(index).data(Qt.ItemDataRole.UserRole) == selected)
        reopened.navigator.setCurrentItem(target)
        assert reopened.current_match().id == selected
        assert foreign.id not in {function.id for function in reopened.current_match().older + reopened.current_match().newer}
        reopened.mode.setCurrentIndex(1)
        before = {side: (pane.textCursor().position(), pane.textCursor().anchor())
                  for side, pane in reopened.views.items()}
        reopened.jump_signal(_item(reopened, signal_id))
        assert reopened.mode.currentIndex() == 1, 'foreign pairing changed representation before refusal'
        assert before == {side: (pane.textCursor().position(), pane.textCursor().anchor())
                          for side, pane in reopened.views.items()}
        assert errors and 'PT-ENRICH-OWNERSHIP' in errors[0]
    finally:
        reopened.close()


def test_dock_identity_is_per_window_and_keeps_surviving_bars_stable(qtbot):
    register_gui_tips()
    left, right = QMainWindow(), QMainWindow()
    for window in (left, right):
        qtbot.addWidget(window)
    first, second = QTabBar(left), QTabBar(left)
    other = QTabBar(right)
    name_tab_bars(left)
    name_tab_bars(right)
    assert first.accessibleIdentifier() == other.accessibleIdentifier()
    second_identity = (second.objectName(), second.accessibleIdentifier(), second.accessibleName())
    first.setParent(None)
    first.deleteLater()
    new = QTabBar(left)
    name_tab_bars(left)
    assert (second.objectName(), second.accessibleIdentifier(), second.accessibleName()) == second_identity
    assert new.accessibleIdentifier() != second.accessibleIdentifier()
    assert new.accessibleName() != second.accessibleName()
