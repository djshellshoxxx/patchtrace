"""Audit #116: navigating away cannot silently discard an edited profile."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import ProfileStore
from patchtrace.ui import ProfilesPanel


@pytest.fixture
def panel(qtbot, tmp_path):
    store = ProfileStore(tmp_path / 'profiles')
    store.save(profiles.build({'name': 'alpha', 'snapshot_max_age_days': 7}))
    store.save(profiles.build({'name': 'beta', 'snapshot_max_age_days': 15}))
    widget = ProfilesPanel(tmp_path / 'profiles', selected='alpha')
    qtbot.addWidget(widget)
    return widget


def choose(panel, name):
    row = next(index for index in range(panel.list.count())
               if panel.list.item(index).data(Qt.ItemDataRole.UserRole) == name)
    panel.list.setCurrentRow(row)


def answer(monkeypatch, button):
    asked = []

    def execute(box):
        asked.append(box.text())
        return button

    monkeypatch.setattr(QMessageBox, 'exec', execute)
    return asked


def test_cancel_selection_preserves_edit_and_previous_selection(panel, monkeypatch):
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Cancel)
    choose(panel, 'beta')
    assert asked and 'alpha' in asked[0]
    assert panel.selected_name() == 'alpha'
    assert panel.max_age.value() == 30 and panel.is_dirty()
    assert panel.store.get('alpha').snapshot_max_age_days == 7


def test_save_selection_commits_then_moves_to_requested_profile(panel, monkeypatch):
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Save)
    choose(panel, 'beta')
    assert len(asked) == 1
    assert panel.store.get('alpha').snapshot_max_age_days == 30
    assert panel.selected_name() == 'beta' and panel.max_age.value() == 15
    assert not panel.is_dirty()


def test_save_with_rename_preserves_requested_destination(panel, monkeypatch):
    panel.name.setText('renamed')
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Save)
    choose(panel, 'beta')
    assert len(asked) == 1
    assert panel.store.names() == ['beta', 'renamed']
    assert panel.store.get('renamed').snapshot_max_age_days == 30
    assert panel.selected_name() == 'beta'


def test_discard_selection_is_explicit_and_keeps_saved_bytes(panel, monkeypatch):
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Discard)
    choose(panel, 'beta')
    assert len(asked) == 1
    assert panel.selected_name() == 'beta' and not panel.is_dirty()
    assert panel.store.get('alpha').snapshot_max_age_days == 7


@pytest.mark.parametrize('failure', ['invalid', 'storage'])
def test_failed_navigation_save_keeps_draft_and_selection(panel, monkeypatch, failure):
    panel.max_age.setValue(30)
    if failure == 'invalid':
        panel.feature_ids.setText('not a feature ID')
    else:
        def fail(*args, **kwargs):
            raise OSError('authored write failure')
        monkeypatch.setattr(panel.store, 'save', fail)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Save)
    choose(panel, 'beta')
    assert len(asked) == 1
    assert panel.selected_name() == 'alpha'
    assert panel.max_age.value() == 30 and panel.is_dirty()
    assert 'Not saved' in panel.error.text()
    assert panel.store.get('alpha').snapshot_max_age_days == 7


@pytest.mark.parametrize('action', ['new_profile', 'duplicate_profile'])
def test_cancel_creation_navigation_keeps_current_draft(panel, monkeypatch, action):
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, QMessageBox.StandardButton.Cancel)
    getattr(panel, action)()
    assert len(asked) == 1
    assert panel.store.names() == ['alpha', 'beta']
    assert panel.selected_name() == 'alpha' and panel.max_age.value() == 30


def test_unchanged_selection_does_not_prompt(panel, monkeypatch):
    asked = answer(monkeypatch, QMessageBox.StandardButton.Cancel)
    choose(panel, 'beta')
    assert asked == []
    assert panel.selected_name() == 'beta' and panel.max_age.value() == 15


@pytest.mark.parametrize('action', ['new_profile', 'duplicate_profile'])
@pytest.mark.parametrize('choice', [QMessageBox.StandardButton.Save, QMessageBox.StandardButton.Discard],
                         ids=['save', 'discard'])
def test_creation_resolves_draft_before_selecting_the_new_profile(panel, monkeypatch, action, choice):
    panel.max_age.setValue(30)
    asked = answer(monkeypatch, choice)
    getattr(panel, action)()
    assert len(asked) == 1
    saved_age = 30 if choice == QMessageBox.StandardButton.Save else 7
    assert panel.store.get('alpha').snapshot_max_age_days == saved_age
    selected = panel.store.get(panel.selected_name())
    assert selected.name not in {'default', 'alpha', 'beta'}
    expected_age = profiles.DEFAULT_PROFILE.snapshot_max_age_days if action == 'new_profile' else saved_age
    assert selected.snapshot_max_age_days == panel.max_age.value() == expected_age
    assert not panel.is_dirty()


@pytest.mark.parametrize('dirty', [False, True])
@pytest.mark.parametrize('failure', ['missing', 'malformed'])
def test_unavailable_destination_preserves_editor_and_selection(panel, monkeypatch, dirty, failure):
    if dirty:
        panel.max_age.setValue(30)
    if failure == 'missing':
        panel.store.delete('beta')
    else:
        (panel.store.directory / 'beta.json').write_text('{broken', encoding='utf-8')
    asked = answer(monkeypatch, QMessageBox.StandardButton.Discard)
    choose(panel, 'beta')
    assert len(asked) == int(dirty)
    assert panel.selected_name() == panel.name.text() == 'alpha'
    assert panel.max_age.value() == (30 if dirty else 7)
    assert panel.is_dirty() == dirty
    assert panel.error.text()
    assert panel.store.get('alpha').snapshot_max_age_days == 7
