"""Independent navigation review: modal-time file changes and failed creation.

Run against the reviewed worktree with an explicit absolute pytest pythonpath.
No target binary, network service, or native desktop acceptance is involved.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox

from patchtrace import ui
from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import ProfileStore


@pytest.fixture
def panel(qtbot, tmp_path):
    assert Path(ui.__file__).resolve() == Path(os.environ['PATCHTRACE_REVIEW_SOURCE']) / 'patchtrace/ui.py'
    store = ProfileStore(tmp_path / 'profiles')
    store.save(profiles.build({'name': 'alpha', 'snapshot_max_age_days': 7}))
    store.save(profiles.build({'name': 'beta', 'snapshot_max_age_days': 15}))
    widget = ui.ProfilesPanel(store.directory, selected='alpha')
    qtbot.addWidget(widget)
    return widget


def choose(panel, name):
    item = next(panel.list.item(i) for i in range(panel.list.count())
                if panel.list.item(i).data(Qt.ItemDataRole.UserRole) == name)
    panel.list.setCurrentItem(item)


@pytest.mark.parametrize('rename', [False, True])
@pytest.mark.parametrize('failure', ['missing', 'malformed'])
def test_save_with_modal_time_destination_loss_keeps_committed_profile(panel, monkeypatch, rename, failure):
    panel.max_age.setValue(30)
    if rename:
        panel.name.setText('renamed')

    def answer(_box):
        if failure == 'missing':
            panel.store.delete('beta')
        else:
            (panel.store.directory / 'beta.json').write_text('{broken', encoding='utf-8')
        return QMessageBox.StandardButton.Save

    monkeypatch.setattr(QMessageBox, 'exec', answer)
    choose(panel, 'beta')
    name = 'renamed' if rename else 'alpha'
    assert panel.selected_name() == panel.name.text() == name
    assert panel.store.get(name).snapshot_max_age_days == panel.max_age.value() == 30
    assert not panel.is_dirty()
    assert 'no longer available' in panel.error.text()


@pytest.mark.parametrize('action', ['new_profile', 'duplicate_profile'])
def test_failed_creation_after_discard_keeps_uncommitted_editor(panel, monkeypatch, action):
    panel.max_age.setValue(30)
    monkeypatch.setattr(QMessageBox, 'exec', lambda _box: QMessageBox.StandardButton.Discard)

    def refuse(*args, **kwargs):
        raise OSError('authored create failure')

    monkeypatch.setattr(panel.store, 'save', refuse)
    getattr(panel, action)()
    assert panel.selected_name() == panel.name.text() == 'alpha'
    assert panel.max_age.value() == 30 and panel.is_dirty()
    assert panel.store.get('alpha').snapshot_max_age_days == 7
    assert panel.store.names() == ['alpha', 'beta']
    assert 'authored create failure' in panel.error.text()
