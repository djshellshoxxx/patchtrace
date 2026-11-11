"""Ghidriff symbol-server consent (SPEC-42 row 9, gap F1): lookups are off by default, and PatchTrace opens no socket
for a comparison whatever the setting.

The Ghidriff child is a process, so the guard (tests/network_guard.py) cannot see its sockets: what a child can do
is bounded by what PatchTrace hands it, which is what these tests observe (argv, environment, per-run Ghidra
settings). Whether Ghidriff honours `--no-symbols` on the wire is not testable here (SPEC-42 E5, native run)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from network_guard import network_guard_fixture  # noqa: F401
from PySide6.QtCore import QSettings

from patchtrace import backend
from patchtrace.backend import BackendConfig, run_comparison
from patchtrace.models import Artifact, ComparisonProject
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow, SetupDialog

PROXY_AND_CA = {'HTTPS_PROXY': 'http://proxy.invalid:3128', 'HTTP_PROXY': 'http://proxy.invalid:3128',
                'NO_PROXY': 'localhost', 'SSL_CERT_FILE': '/etc/ssl/corp.pem', 'SSL_CERT_DIR': '/etc/ssl/corp',
                'REQUESTS_CA_BUNDLE': '/etc/ssl/corp.pem'}
SESSION_SECRETS = {'GITHUB_TOKEN': 'ghp_' + 'A1b2C3d4' * 5, 'NVD_API_KEY': 'nvd-session-key-1234',
                   'OPENAI_API_KEY': 'sk-session-key-abcdef123456'}
CHILD = '''\
import json, os, pathlib, sys
raw = os.environ.get('XDG_CONFIG_HOME')
home = pathlib.Path(raw) if raw else None
pathlib.Path({side!r}).write_text(json.dumps({{
    'argv': sys.argv[1:], 'env': dict(os.environ), 'settings_dir': raw,
    'settings_entries': sorted(p.name for p in home.iterdir()) if home and home.is_dir() else None}}),
    encoding='utf-8')
out = pathlib.Path(sys.argv[sys.argv.index('--output-path') + 1])
(out / 'json').mkdir(parents=True)
(out / 'json' / 'old-new.ghidriff.json').write_text(
    json.dumps({{'functions': {{'added': [], 'deleted': [], 'modified': []}}}}), encoding='utf-8')
'''


class Runtime:
    """A fake Ghidra install and an in-tree `ghidriff` that records what PatchTrace hands its child."""

    def __init__(self, root: Path):
        self.root = root
        self.side = root / 'child-report' / 'child.json'
        self.side.parent.mkdir()
        self.ghidra = root / 'ghidra'
        (self.ghidra / 'Ghidra').mkdir(parents=True)
        (self.ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4')
        package = self.ghidra / 'ghidriff'
        package.mkdir()
        (package / '__init__.py').write_text('')
        (package / '__main__.py').write_text(CHILD.format(side=str(self.side)), encoding='utf-8', newline='\n')
        artifacts = []
        for side, content in (('older', b'old-static-data'), ('newer', b'new-static-data')):
            (root / f'{side}.bin').write_bytes(content)
            artifacts.append(Artifact(side=side, name=f'{side}.bin', size=len(content),
                                      sha256=hashlib.sha256(content).hexdigest(), relative_path=f'{side}.bin'))
        self.project = ComparisonProject(name='consent-fixture', artifacts=artifacts)

    def config(self, **overrides) -> BackendConfig:
        return BackendConfig(str(Path(sys.executable).resolve()), str(self.ghidra), **overrides)

    def run(self, config: BackendConfig):
        self.side.unlink(missing_ok=True)
        _path, run = run_comparison(config, self.project, self.root, threading.Event(), lambda _event: None)
        assert run.status == 'completed', run.error
        return run, json.loads(self.side.read_text(encoding='utf-8'))


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: {
        'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': 'fake-test-only', 'available': True})
    view = Runtime(tmp_path)
    real_run = backend.run_process

    def run_fake(argv, **kwargs):
        index = argv.index('-m')
        script = view.ghidra / 'ghidriff' / '__main__.py'
        return real_run([*argv[:index], str(script), *argv[index + 2:]], **kwargs)

    # Record the child environment without depending on cwd module injection.
    monkeypatch.setattr(backend, 'run_process', run_fake)
    return view


def test_a_default_comparison_disables_symbol_lookup_and_opens_no_socket(runtime, network_guard):
    config = runtime.config()
    assert config.allow_symbol_downloads is False
    run, child = runtime.run(config)
    assert '--no-symbols' in child['argv']
    assert run.settings['allow_symbol_downloads'] is False and run.settings['symbol_policy'] == 'disabled'
    assert network_guard.attempts == []


def test_consent_removes_the_flag_and_even_then_patchtrace_opens_no_socket(runtime, network_guard):
    run, child = runtime.run(runtime.config(allow_symbol_downloads=True))
    assert '--no-symbols' not in child['argv']
    assert run.settings['allow_symbol_downloads'] is True and run.settings['symbol_policy'] == 'online'
    assert network_guard.attempts == []  # the lookup, if any, is Ghidriff's: PatchTrace only lifts the flag


@pytest.mark.parametrize('consent', [False, True], ids=['no-consent', 'consent'])
def test_a_restricted_child_gets_proxy_and_ca_variables_only_with_consent(runtime, monkeypatch, network_guard,
                                                                        consent):
    for name, value in {**PROXY_AND_CA, **SESSION_SECRETS}.items():
        monkeypatch.setenv(name, value)
    _run, child = runtime.run(runtime.config(allow_symbol_downloads=consent, restrict_env=True))
    seen = {name.upper() for name in child['env']}
    assert set(PROXY_AND_CA) & seen == (set(PROXY_AND_CA) if consent else set())
    assert not set(SESSION_SECRETS) & seen  # tokens never reach the child, with or without consent
    assert network_guard.attempts == []


def test_every_run_gets_its_own_empty_ghidra_settings_directory(runtime, tmp_path, monkeypatch):
    # A symbol server saved in the analyst's own Ghidra preferences must not apply to a run with lookups off.
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path / 'analyst-ghidra-preferences'))
    (tmp_path / 'analyst-ghidra-preferences').mkdir()
    (tmp_path / 'analyst-ghidra-preferences' / 'symbol-server.xml').write_text('<server/>')
    first = runtime.run(runtime.config())[1]
    second = runtime.run(runtime.config())[1]
    assert first['settings_entries'] == [] and second['settings_entries'] == []
    assert first['settings_dir'] != second['settings_dir']
    assert not Path(first['settings_dir']).is_relative_to(tmp_path / 'analyst-ghidra-preferences')
    assert not Path(first['settings_dir']).is_relative_to(runtime.root)


def test_the_setup_diagnosis_reports_lookups_as_disabled_unless_enabled(runtime, network_guard):
    off = backend.diagnose(runtime.config())
    on = backend.diagnose(runtime.config(allow_symbol_downloads=True))
    assert 'Ghidriff symbol-server lookup: disabled (local/offline option)' in off
    assert 'Ghidriff symbol-server lookup: enabled by analyst' in on
    assert network_guard.attempts == []


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    view = MainWindow(service, QSettings(str(tmp_path / 'fresh.ini'), QSettings.Format.IniFormat))
    qtbot.addWidget(view)
    yield view
    view.close()


def test_fresh_settings_mean_lookups_are_off_in_the_window_and_the_setup_dialog(window, network_guard):
    assert 'backend/allow_symbol_downloads' not in window.settings.allKeys()
    assert window.backend_config().allow_symbol_downloads is False
    dialog = SetupDialog(window.settings, window)
    assert not dialog.allow_symbol_downloads.isChecked()
    assert 'may access the Internet' in dialog.allow_symbol_downloads.text()
    assert not dialog.config().allow_symbol_downloads
    assert network_guard.attempts == []
