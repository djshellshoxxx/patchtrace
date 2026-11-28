"""P2-NAV-1: real stored/reopened signal actions must validate live source ownership.

Malformed locations are authored derived rows, not claimed detector output. The
ordinary store checksum is retained so these controls reach the desktop boundary.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
from PySide6.QtCore import QSettings, Qt

from patchtrace.enrichment import identity, pipeline, views
from patchtrace.enrichment.contracts import SourceLocation
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow


def _rows(service):
    return service.store.connection.execute('SELECT * FROM enrichment_entries ORDER BY id').fetchall()


def _item(window, signal_id):
    # Display-mode changes rebuild the list and destroy its previous C++ items.
    return next(window.signal_list.item(i) for i in range(window.signal_list.count())
                if window.signal_list.item(i).data(Qt.ItemDataRole.UserRole) == signal_id)


def _window(tmp_path, qtbot, monkeypatch, field=None, *, zero_address=False, representation='decompiled'):
    service = ProjectService.sample(tmp_path / 'authored-project')
    if zero_address:
        project = service.project
        matches = [match.model_copy(update={'newer': [
            function.model_copy(update={'address': '0x0'}) for function in match.newer]})
                   for match in project.matches]
        service._commit(project.model_copy(update={'matches': matches}))
    if representation != 'decompiled':
        project = service.project.model_copy(deep=True)
        matches = [match.model_copy(update={side: [
            function.model_copy(update={'assembly': 'mov eax, 1\nret\n'})
            for function in getattr(match, side)] for side in ('older', 'newer')})
            for match in project.matches]
        candidate = project.model_copy(update={'matches': matches})
        service._invalidate(candidate)
        service._commit(candidate)
    result = pipeline.run(service.project)
    signal_set = next(item for item in result.signal_sets
                      if any(signal.locations[0].side == 'newer' for signal in item.signals))
    signal = next(item for item in signal_set.signals if item.locations[0].side == 'newer')
    location = signal.locations[0]
    if representation != 'decompiled':
        function = views.validate_location(service.project, location)
        assert function.assembly and function.code and function.assembly[0] != function.code[0]
        location = SourceLocation.model_validate(location.model_dump() | {
            'representation': representation, 'start_line': 1, 'end_line': 1,
            'excerpt_sha256': identity.excerpt_sha256(function.assembly[:1]),
        })
        assert views.validate_location(service.project, location).id == function.id
    changes = {
        'function_id': 'authored-foreign-function',
        'artifact_id': 'authored-foreign-artifact',
        'run_id': 'authored-foreign-run',
        'side': 'older',
        'address': location.address + 1,
        'excerpt_sha256': '0' * 64,
        'end_line': 20_001,
    }
    if field is not None:
        location = SourceLocation.model_validate(location.model_dump() | {field: changes[field]})
    if field is not None or representation != 'decompiled':
        signal = signal.model_copy(update={'locations': (location,) + signal.locations[1:]})
        signal_set = signal_set.model_copy(update={'signals': tuple(
            signal if item.signal_id == signal.signal_id else item for item in signal_set.signals)})
        result = replace(result, signal_sets=tuple(
            signal_set if item.pairing_id == signal_set.pairing_id else item for item in result.signal_sets))
    pipeline.publish(EnrichmentStore(service.store), service.project, result)
    root = service.root
    service.close()
    window = MainWindow(ProjectService.open(root),
                        QSettings(str(tmp_path / 'settings.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(window)
    window.show()
    target = next(window.navigator.item(i) for i in range(window.navigator.count())
                  if window.navigator.item(i).data(Qt.ItemDataRole.UserRole) == signal_set.match_id)
    window.navigator.setCurrentItem(target)
    errors, revealed = [], []
    real_reveal = window.reveal_lines

    def reveal(*args):
        revealed.append(args)
        return real_reveal(*args)

    monkeypatch.setattr(window, 'show_error', errors.append)
    monkeypatch.setattr(window, 'reveal_lines', reveal)
    return window, signal.signal_id, location, errors, revealed


@pytest.mark.parametrize('field,code', [
    ('function_id', 'PT-ENRICH-OWNERSHIP'),
    ('artifact_id', 'PT-ENRICH-OWNERSHIP'),
    ('run_id', 'PT-ENRICH-OWNERSHIP'),
    ('side', 'PT-ENRICH-OWNERSHIP'),
    ('address', 'PT-ENRICH-OWNERSHIP'),
    ('excerpt_sha256', 'PT-ENRICH-STALE'),
    ('end_line', 'PT-ENRICH-STALE'),
])
def test_invalid_stored_location_refuses_before_mode_or_cursor_change(tmp_path, qtbot, monkeypatch, field, code):
    window, signal_id, _location, errors, revealed = _window(tmp_path, qtbot, monkeypatch, field)
    try:
        window.mode.setCurrentIndex(1)
        before_project = window.project.model_dump_json()
        before_ranking = window._ranking_result.model_dump_json()
        before_rows = _rows(window.service)
        before_cursors = {side: (pane.textCursor().position(), pane.textCursor().anchor())
                          for side, pane in window.views.items()}
        window.jump_signal(_item(window, signal_id))
        assert not revealed
        assert window.mode.currentIndex() == 1
        assert {side: (pane.textCursor().position(), pane.textCursor().anchor())
                for side, pane in window.views.items()} == before_cursors
        assert len(errors) == 1 and code in errors[0] and len(errors[0]) <= 300
        assert window.project.model_dump_json() == before_project
        assert window._ranking_result.model_dump_json() == before_ranking
        assert _rows(window.service) == before_rows
    finally:
        window.close()


@pytest.mark.parametrize('mode,zero_address', [(0, False), (1, False), (1, True)])
def test_valid_signal_keeps_actual_navigation_and_zero_address(tmp_path, qtbot, monkeypatch, mode, zero_address):
    window, signal_id, location, errors, revealed = _window(tmp_path, qtbot, monkeypatch, zero_address=zero_address)
    try:
        window.mode.setCurrentIndex(mode)
        before_rows = _rows(window.service)
        window.jump_signal(_item(window, signal_id))
        assert not errors
        assert revealed == [(location.function_id, location.start_line, location.end_line)]
        assert window.mode.currentIndex() == 0
        assert window.views[location.side].textCursor().hasSelection()
        assert _rows(window.service) == before_rows
        if zero_address:
            assert location.address == 0
    finally:
        window.close()


@pytest.mark.parametrize('representation', ['assembly', 'metadata'])
@pytest.mark.parametrize('mode', [0, 1])
def test_other_representation_refuses_without_substituting_text(tmp_path, qtbot, monkeypatch, representation, mode):
    window, signal_id, location, errors, revealed = _window(
        tmp_path, qtbot, monkeypatch, representation=representation)
    try:
        assert views.validate_location(window.project, location).id == location.function_id
        window.mode.setCurrentIndex(mode)
        before_project = window.project.model_dump_json()
        before_ranking = window._ranking_result.model_dump_json()
        before_rows = _rows(window.service)
        before_cursors = {side: (pane.textCursor().position(), pane.textCursor().anchor())
                          for side, pane in window.views.items()}
        window.jump_signal(_item(window, signal_id))
        assert not revealed
        assert window.mode.currentIndex() == mode
        assert {side: (pane.textCursor().position(), pane.textCursor().anchor())
                for side, pane in window.views.items()} == before_cursors
        assert len(errors) == 1 and 'PT-ENRICH-INPUT' in errors[0] and len(errors[0]) <= 300
        assert 'decompiled' in errors[0]
        assert window.project.model_dump_json() == before_project
        assert window._ranking_result.model_dump_json() == before_ranking
        assert _rows(window.service) == before_rows
    finally:
        window.close()


def test_repeat_activation_rechecks_live_excerpt_after_project_change(tmp_path, qtbot, monkeypatch):
    window, signal_id, location, errors, revealed = _window(tmp_path, qtbot, monkeypatch)
    try:
        window.jump_signal(_item(window, signal_id))
        assert revealed and not errors
        project = window.project.model_copy(deep=True)
        matches = []
        for match in project.matches:
            newer = [function.model_copy(update={'code': function.code + '\n// appended'})
                     if function.id == location.function_id else function for function in match.newer]
            if any(function.id == location.function_id for function in newer):
                newer = [function.model_copy(update={'code': function.code.replace('buffer == NULL', 'buffer != NULL')})
                         if function.id == location.function_id else function for function in newer]
            matches.append(match.model_copy(update={'newer': newer}))
        candidate = project.model_copy(update={'matches': matches})
        window.service._invalidate(candidate)
        window.service._commit(candidate)
        revealed.clear()
        before_rows = _rows(window.service)
        window.jump_signal(_item(window, signal_id))
        assert not revealed
        assert len(errors) == 1 and 'PT-ENRICH-STALE' in errors[0]
        assert _rows(window.service) == before_rows
    finally:
        window.close()
