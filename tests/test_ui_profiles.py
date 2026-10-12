"""SPEC-07 §12 desktop profiles: Setup tab, selection, ranking/load by profile, export agreement."""
from __future__ import annotations

import json

import pytest
from PySide6.QtCore import QSettings, QTimer
from PySide6.QtWidgets import QDialog

from patchtrace import cli
from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import ProfileStore, profile_digest
from patchtrace.service import ProjectService
from patchtrace.ui import PROFILE_SETTING, MainWindow, ProfilesPanel, SetupDialog, profiles_dir

CUSTOM = {'name': 'triage', 'weights': {'BND': 60, 'INT': 22, 'OVF': 28, 'VAL': 20, 'ERR': 0,
                                        'SIZE': 24, 'WIL': 12, 'SCRUB': 34},
          'enabled': ['BND', 'INT', 'OVF', 'VAL', 'SIZE', 'WIL', 'SCRUB'], 'snapshot_max_age_days': 7}


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


@pytest.fixture
def window(qtbot, tmp_path, settings):
    service = ProjectService.sample(tmp_path / 'sample')
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    if view.worker:
        view.cancel_job()
        qtbot.waitUntil(lambda: view.worker is None, timeout=5000)


def test_profiles_dir_derives_from_settings_file(settings, tmp_path):
    assert profiles_dir(settings) == tmp_path / 'profiles'


def test_panel_create_edit_duplicate_delete(qtbot, tmp_path, monkeypatch):
    panel = ProfilesPanel(tmp_path / 'profiles')
    qtbot.addWidget(panel)
    assert panel.selected_name() == 'default' and not panel.save_button.isEnabled()
    assert not panel.delete_button.isEnabled()
    panel.new_button.click()
    assert panel.selected_name() == 'profile' and panel.save_button.isEnabled()
    panel.name.setText('triage')
    panel.weights['BND'].setValue(60)
    panel.enabled['ERR'].setChecked(False)
    panel.feature_ids.setText('5, 7')
    assert panel.save_profile()
    stored = ProfileStore(tmp_path / 'profiles').get('triage')
    assert stored.weights['BND'] == 60 and 'ERR' not in stored.enabled and stored.feature_ids == (5, 7)
    assert ProfileStore(tmp_path / 'profiles').names() == ['triage']  # renamed, not copied
    panel.duplicate_button.click()
    assert panel.selected_name() == 'triage copy'
    monkeypatch.setattr(panel, 'confirm_delete', lambda name: True)
    panel.delete_button.click()
    assert ProfileStore(tmp_path / 'profiles').names() == ['triage'] and panel.selected_name() == 'default'


def test_panel_inline_validation(qtbot, tmp_path):
    panel = ProfilesPanel(tmp_path / 'profiles')
    qtbot.addWidget(panel)
    panel.new_button.click()
    for check in panel.enabled.values():
        check.setChecked(False)
    assert not panel.save_profile()
    assert 'Not saved' in panel.error.text() and 'detector' in panel.error.text()
    panel.enabled['BND'].setChecked(True)
    panel.feature_ids.setText('1, x')
    assert not panel.save_profile() and 'feature' in panel.error.text()
    panel.feature_ids.setText('')
    panel.cache_dir.setText('relative')
    assert not panel.save_profile() and 'absolute' in panel.error.text()
    panel.cache_dir.setText('')
    panel.name.setText('default')
    assert not panel.save_profile() and 'read-only' in panel.error.text()
    assert ProfileStore(tmp_path / 'profiles').get('profile').enabled != ('BND',)


def test_setup_dialog_saves_only_selected_name(window, qtbot, tmp_path, settings):
    store = ProfileStore(profiles_dir(settings))
    store.save(profiles.build(CUSTOM))

    def pick():
        dialog = next(w for w in window.findChildren(SetupDialog) if w.isVisible())
        dialog.tabs.setCurrentWidget(dialog.profiles)
        dialog.profiles.reload('triage')
        dialog.done(QDialog.DialogCode.Accepted)
    QTimer.singleShot(0, pick)
    window.setup()
    assert settings.value(PROFILE_SETTING) == 'triage'
    profile_keys = [k for k in settings.allKeys() if 'profile' in k.lower() or 'weight' in k.lower()]
    assert profile_keys == [PROFILE_SETTING]
    assert window.profile_label.isVisible() and window.profile_label.text() == 'Profile: triage'


def test_non_default_profile_gui_cli_report_agree(window, qtbot, tmp_path, settings, capsys, monkeypatch):
    from patchtrace.reports import export_project
    directory = profiles_dir(settings)
    profile = profiles.build(CUSTOM)
    ProfileStore(directory).save(profile)
    settings.setValue(PROFILE_SETTING, 'triage')
    window.rank_action.trigger()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    assert window._ranking, window.logs.toPlainText()
    gui = {k: v.score for k, v in window._ranking.items()}
    assert window.profile_label.isVisible()
    # The default view must not show the profile's rows.
    settings.setValue(PROFILE_SETTING, 'default')
    window._load_enrichment()
    assert not window._ranking and not window.profile_label.isVisible()
    settings.setValue(PROFILE_SETTING, 'triage')
    window._load_enrichment()
    assert {k: v.score for k, v in window._ranking.items()} == gui
    enrichment = window._enrichment_export()
    out = tmp_path / 'r.json'
    export_project(window.project, 'json', out, enrichment=enrichment)
    report = json.loads(out.read_text())['change_ranking']
    assert report['profile'] == {'name': 'triage', 'digest': profile_digest(profile)}
    md = tmp_path / 'r.md'
    export_project(window.project, 'md', md, enrichment=enrichment)
    assert f'Profile: triage (digest {profile_digest(profile)})' in md.read_text()
    monkeypatch.setattr(profiles, 'default_profiles_dir', lambda: directory)
    root = window.service.root
    window.service.close()  # projects are single-writer; release the desktop's lock for the CLI
    window.service = None
    code = cli.main(['rank', str(root), '--json', '--dry-run', '--profile', 'triage'])
    out_text, err = capsys.readouterr()
    assert code == 0, err
    doc = json.loads(out_text)
    cli_scores = {e['match_id']: e['score'] for e in doc['result']['entries']}
    assert cli_scores == gui == {e['match_id']: e['score'] for e in report['entries']}
    assert doc['result']['config_digest'] == report['config_digest']
    assert doc['result']['profile'] == report['profile']


def test_default_export_records_default_profile(window, qtbot):
    window.rank_action.trigger()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    assert window._enrichment_export()['profile'] == {'name': 'default',
                                                      'digest': profile_digest(profiles.DEFAULT_PROFILE)}
    assert not window.profile_label.isVisible()


def test_missing_selected_profile_falls_back_to_default(window, settings):
    settings.setValue(PROFILE_SETTING, 'gone')
    profile, warning = window.analysis_profile()
    assert profile.is_default and 'gone' in warning


def test_export_rejects_malformed_profile(window, qtbot, tmp_path):
    from patchtrace.reports import ExportError, export_project
    window.rank_action.trigger()
    qtbot.waitUntil(lambda: window.worker is None, timeout=10000)
    enrichment = window._enrichment_export()
    enrichment['profile'] = {'name': '<script>', 'digest': 'x'}
    with pytest.raises(ExportError, match='profile'):
        export_project(window.project, 'json', tmp_path / 'x.json', enrichment=enrichment)


def _select(window, profile):
    from patchtrace.enrichment.profiles import ProfileStore
    ProfileStore(window.profile_directory).save(profile)
    window.settings.setValue('analysis/profile', profile.name)


def test_backend_config_symbol_consent_and_cache_dir_from_profile(window, tmp_path):
    from patchtrace.enrichment.profiles import AnalysisProfile
    window.settings.setValue('backend/allow_symbol_downloads', False)
    assert window.backend_config().allow_symbol_downloads is False and window.backend_config().cache_dir == ''
    window.settings.setValue('backend/allow_symbol_downloads', True)
    assert window.backend_config().allow_symbol_downloads is True  # default profile: checkbox decides
    _select(window, AnalysisProfile(name='narrow', symbol_policy='disabled', cache_dir=str(tmp_path / 'c')))
    config = window.backend_config()
    assert config.allow_symbol_downloads is False and config.cache_dir == str(tmp_path / 'c')
    window.settings.setValue('backend/allow_symbol_downloads', False)
    _select(window, AnalysisProfile(name='wide', symbol_policy='online'))
    assert window.backend_config().allow_symbol_downloads is False  # profile alone never enables network


def test_cached_run_is_labelled_in_match_tooltip(window):
    project = window.service.project
    run = next(r for r in project.runs if r.raw_sha256)
    origin = {'key': 'a' * 64, 'created': '2026-10-12T00:00:00+00:00'}
    window.service._commit(project.model_copy(update={'runs': [
        r.model_copy(update={'settings': {**r.settings, 'cache_origin': origin}}) if r.id == run.id else r
        for r in project.runs]}))
    window.refresh()
    tips = [window.navigator.item(i).toolTip() for i in range(window.navigator.count())]
    assert any('reused from cache' in t and 'aaaaaaaaaaaa' in t for t in tips)
