"""Default primary-child isolation; authored sentinels and a fake engine only."""
from __future__ import annotations

import os
import sys

import pytest
from PySide6.QtCore import QSettings
from test_network_consent_symbols import runtime  # noqa: F401

from patchtrace import backend, ui
from patchtrace.backend import BackendConfig
from patchtrace.runtime_discovery import RuntimeCandidates
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, SetupDialog

SECRETS = ('GH_TOKEN', 'GITHUB_TOKEN', 'NVD_API_KEY', 'OPENAI_API_KEY', 'AWS_SECRET_ACCESS_KEY')
PROXIES = ('HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE')
INJECTION = ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'PYTHONPATH', 'PYTHONHOME', 'LD_PRELOAD')


@pytest.fixture
def parent_environment(tmp_path, monkeypatch):
    # Supply only harmless authored values: the fake engine records its environment.
    base = {name: 'AUTHORED_ENV_REVIEW_SENTINEL' for name in (*SECRETS, *PROXIES, *INJECTION)}
    base.update(PATH=os.defpath, HOME=str(tmp_path), QT_QPA_PLATFORM='offscreen',
                CUSTOM_PRIMARY_MARKER='authored-compatible-extension')
    if os.name == 'nt':
        base['SystemRoot'] = os.environ['SystemRoot']
        base['TEMP'] = base['TMP'] = str(tmp_path)
    monkeypatch.setattr(backend.os, 'environ', base)
    return base


def test_primary_backend_configuration_defaults_to_allowlist(tmp_path):
    assert BackendConfig(sys.executable, str(tmp_path)).restrict_env is True


@pytest.mark.parametrize('mode', ['off', 'local', 'online'])
def test_default_environment_keeps_only_the_consented_network_settings(tmp_path, parent_environment, mode):
    config = BackendConfig(sys.executable, str(tmp_path), symbol_mode=mode,
                           allow_symbol_downloads=mode == 'online')
    child = backend._environment(config, tmp_path / 'settings')
    assert not set(SECRETS + INJECTION) & child.keys()
    assert set(PROXIES) & child.keys() == (set(PROXIES) if mode == 'online' else set())
    assert child['GHIDRA_INSTALL_DIR'] == str(tmp_path.resolve())
    assert child['XDG_CONFIG_HOME'] == str(tmp_path / 'settings')
    assert child['PYTHONNOUSERSITE'] == '1'
    assert 'CUSTOM_PRIMARY_MARKER' not in child


@pytest.mark.parametrize('online', [False, True])
def test_actual_fake_engine_child_obeys_the_default_without_explicit_restrict_flag(
        runtime, parent_environment, online):
    _run, child = runtime.run(runtime.config(allow_symbol_downloads=online))
    assert not set(SECRETS + INJECTION) & child['env'].keys()
    assert set(PROXIES) & child['env'].keys() == (set(PROXIES) if online else set())
    assert ('--no-symbols' in child['argv']) is not online
    assert child['settings_entries'] == []


@pytest.fixture
def window(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(ui, 'discover_local_runtimes', lambda: RuntimeCandidates((), ()))
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'primary-defaults.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    yield view
    view.close()


def test_fresh_desktop_configuration_uses_restriction_without_writing_settings(window):
    assert not window.settings.contains('backend/restrict_env')
    assert window.backend_config().restrict_env is True
    assert not window.settings.contains('backend/restrict_env')


def test_fresh_setup_dialog_uses_the_same_default_without_writing_settings(window, qtbot):
    dialog = SetupDialog(window.settings, window)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog._discovery is None, timeout=5000)
    assert dialog.restrict_env.isChecked()
    assert dialog.config().restrict_env is True
    assert not window.settings.contains('backend/restrict_env')
    dialog.close()


@pytest.mark.parametrize('chosen', [False, True])
def test_saved_explicit_desktop_choice_remains_authoritative(window, qtbot, chosen):
    window.settings.setValue('backend/restrict_env', chosen)
    dialog = SetupDialog(window.settings, window)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog._discovery is None, timeout=5000)
    assert dialog.restrict_env.isChecked() is chosen
    assert dialog.config().restrict_env is chosen
    assert window.backend_config().restrict_env is chosen
    assert window.settings.value('backend/restrict_env', type=bool) is chosen
    dialog.close()


def test_named_passthrough_keeps_only_the_selected_compatible_extension(tmp_path, parent_environment):
    config = BackendConfig(sys.executable, str(tmp_path), env_passthrough=('CUSTOM_PRIMARY_MARKER',))
    child = backend._environment(config)
    assert child['CUSTOM_PRIMARY_MARKER'] == 'authored-compatible-extension'
    assert not set(SECRETS + PROXIES + INJECTION) & child.keys()


def test_explicit_external_compatibility_opt_out_is_preserved(tmp_path, parent_environment):
    config = BackendConfig(sys.executable, str(tmp_path), restrict_env=False)
    assert backend._environment(config)['CUSTOM_PRIMARY_MARKER'] == 'authored-compatible-extension'


def test_explicit_inherit_override_remains_external_only(tmp_path, parent_environment):
    parent_environment['PATCHTRACE_CHILD_ENV'] = 'inherit'
    external = BackendConfig(sys.executable, str(tmp_path))
    assert backend._environment(external)['CUSTOM_PRIMARY_MARKER'] == 'authored-compatible-extension'
    bundled = BackendConfig(sys.executable, str(tmp_path), bundle=True, java_home=str(tmp_path / 'jdk'))
    assert 'CUSTOM_PRIMARY_MARKER' not in backend._environment(bundled)
