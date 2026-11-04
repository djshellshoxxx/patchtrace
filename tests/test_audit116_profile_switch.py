"""Audit #116 P2: switching profiles must not silently discard unsaved edits to the current one."""
from __future__ import annotations

from patchtrace.enrichment.profiles import ProfileStore
from patchtrace.ui import ProfilesPanel


def _two_profiles(qtbot, tmp_path):
    panel = ProfilesPanel(tmp_path / 'profiles')
    qtbot.addWidget(panel)
    panel.new_button.click()
    panel.name.setText('alpha')
    assert panel.save_profile()
    panel.new_button.click()
    panel.name.setText('beta')
    assert panel.save_profile()
    return panel


def _row(panel, name):
    return next(i for i in range(panel.list.count()) if panel.list.item(i).text().startswith(name))


def test_declining_the_prompt_keeps_the_selection_and_the_edits(qtbot, tmp_path, monkeypatch):
    panel = _two_profiles(qtbot, tmp_path)
    panel.list.setCurrentRow(_row(panel, 'alpha'))
    panel.max_age.setValue(panel.max_age.value() + 3)
    edited = panel.max_age.value()
    asked = []
    monkeypatch.setattr(panel, 'confirm_save', lambda name: asked.append(name) or False)
    panel.list.setCurrentRow(_row(panel, 'beta'))
    assert asked == ['alpha']
    assert panel.selected_name() == 'alpha' and panel.max_age.value() == edited and panel.is_dirty()
    assert ProfileStore(tmp_path / 'profiles').get('alpha').snapshot_max_age_days != edited


def test_accepting_the_prompt_saves_then_moves_once(qtbot, tmp_path, monkeypatch):
    panel = _two_profiles(qtbot, tmp_path)
    panel.list.setCurrentRow(_row(panel, 'alpha'))
    panel.max_age.setValue(panel.max_age.value() + 3)
    edited = panel.max_age.value()
    asked = []
    monkeypatch.setattr(panel, 'confirm_save', lambda name: asked.append(name) or True)
    panel.list.setCurrentRow(_row(panel, 'beta'))
    assert asked == ['alpha']  # asked once, not again while the list reloads after the save
    assert panel.selected_name() == 'beta' and not panel.is_dirty()
    assert ProfileStore(tmp_path / 'profiles').get('alpha').snapshot_max_age_days == edited


def test_a_failed_save_stays_on_the_edited_profile(qtbot, tmp_path, monkeypatch):
    panel = _two_profiles(qtbot, tmp_path)
    panel.list.setCurrentRow(_row(panel, 'alpha'))
    for check in panel.enabled.values():
        check.setChecked(False)  # invalid: no detector enabled
    monkeypatch.setattr(panel, 'confirm_save', lambda name: True)
    panel.list.setCurrentRow(_row(panel, 'beta'))
    assert panel.selected_name() == 'alpha' and 'Not saved' in panel.error.text()


def test_a_clean_switch_does_not_ask(qtbot, tmp_path, monkeypatch):
    panel = _two_profiles(qtbot, tmp_path)
    monkeypatch.setattr(panel, 'confirm_save', lambda name: (_ for _ in ()).throw(AssertionError('asked')))
    panel.list.setCurrentRow(_row(panel, 'alpha'))
    panel.list.setCurrentRow(_row(panel, 'beta'))
    assert panel.selected_name() == 'beta'
