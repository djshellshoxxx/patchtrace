"""BUNDLE B7 offscreen UI: Setup prefill/label, Verify worker (progress, cancel), backend_config fallback.

Hermetic: tiny synthetic bundle; the blocking verify worker is a test double where a cancel must be observed.
"""
from __future__ import annotations

import os
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog
from test_backend_bundle import make_bundle

from patchtrace import backend, ui, ui_bundle_setup
from patchtrace.backend_bundle import BundleCancelled, find_bundled_runtime
from patchtrace.runtime_discovery import discover_local_runtimes
from patchtrace.service import ProjectService
from patchtrace.tooltips import tooltip
from patchtrace.ui import MainWindow, SetupDialog

HOST = 'windows' if os.name == 'nt' else 'linux'
PROBE = {'python': '3.12.0', 'ghidriff': 'fake-test-only', 'pyghidra': '3.0.2', 'available': True}


@pytest.fixture
def exe(tmp_path):
    directory = tmp_path / 'App Dir é'
    directory.mkdir()
    make_bundle(directory, HOST)
    return directory


@pytest.fixture
def window(qtbot, tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_STATE_HOME', str(tmp_path / 'state'))
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'localappdata'))
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    view.close()


def with_bundle(monkeypatch, exe):
    """Setup discovery sees only the synthetic bundle next to a fake executable."""
    monkeypatch.setattr(ui, 'discover_local_runtimes',
                        lambda: discover_local_runtimes({'PATCHTRACE_BUNDLE_DIR': str(exe)}))


def open_setup(qtbot, window):
    dialog = SetupDialog(window.settings, window)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: dialog._discovery is None, timeout=5000)
    return dialog


def wait_idle(qtbot, dialog):
    qtbot.waitUntil(lambda: dialog.bundle._thread is None and not ui_bundle_setup._THREADS, timeout=5000)


# ---- prefill, label, names ------------------------------------------------------------------

def test_prefills_empty_fields_and_labels_bundle(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    dialog = open_setup(qtbot, window)
    ref = find_bundled_runtime(exe, host=HOST)
    assert dialog.python.text() == str(ref.python) and dialog.ghidra.text() == str(ref.ghidra)
    assert dialog.java_home.text() == str(ref.java_home)
    assert dialog.bundle.status.text() == 'Bundled runtime: ok (fast check)'
    assert dialog.bundle.status.isReadOnly() and dialog.bundle.row.isVisibleTo(dialog)
    assert dialog.bundle.verify_button.isEnabled() and not dialog.bundle.cancel_button.isEnabled()
    assert (f'Bundled analysis runtime found next to PatchTrace ({ref.runtime_id}). '
            'Run Diagnose dependencies to verify it.') in dialog.diagnostics.toPlainText()


def test_widget_ids_tooltips_and_accessible_names(qtbot, window):
    dialog = SetupDialog(window.settings, window)
    qtbot.addWidget(dialog)
    bundle = dialog.bundle
    for widget, tip_id, name in ((bundle.status, 'setup.backend.bundle', 'Bundled runtime status'),
                                 (bundle.verify_button, 'setup.backend.verify', 'Verify bundle files'),
                                 (bundle.cancel_button, 'setup.backend.verify_cancel',
                                  'Cancel bundle verification')):
        assert widget.objectName() == tip_id and widget.accessibleName() == name
        assert widget.toolTip() == tooltip(tip_id) and widget.accessibleDescription() and not widget.accessibleDescription().startswith('What:')


def test_hidden_without_a_bundle(qtbot, window, monkeypatch):
    monkeypatch.setattr(ui, 'discover_local_runtimes', lambda: discover_local_runtimes({}))
    dialog = open_setup(qtbot, window)
    assert not dialog.bundle.row.isVisibleTo(dialog) and dialog.python.text() == ''


def test_saved_paths_are_retained_and_only_empty_fields_filled(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    window.settings.setValue('backend/python', '/my/python')
    dialog = open_setup(qtbot, window)
    ref = find_bundled_runtime(exe, host=HOST)
    assert dialog.python.text() == '/my/python' and dialog.ghidra.text() == str(ref.ghidra)
    assert window.settings.value('backend/ghidra', '') == ''  # nothing is saved by discovery


@pytest.mark.parametrize('damage, code', [('extra', 'PT-BUNDLE-EXTRA'), ('manifest', 'PT-BUNDLE-MANIFEST')])
def test_problem_label_and_no_prefill(qtbot, window, exe, monkeypatch, damage, code):
    if damage == 'extra':
        (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    else:
        (exe / 'backend' / 'manifest.json').write_text('{oops', encoding='utf-8')
    with_bundle(monkeypatch, exe)
    dialog = open_setup(qtbot, window)
    assert dialog.bundle.status.text() == f'Bundled runtime problem: {code} - extract the complete ZIP again'
    assert dialog.python.text() == '' and dialog.ghidra.text() == '' and dialog.java_home.text() == ''
    assert dialog.bundle.row.isVisibleTo(dialog)
    assert code in dialog.diagnostics.toPlainText() and not dialog.bundle.verify_button.isEnabled()


# ---- Verify worker --------------------------------------------------------------------------

def test_verify_full_success_and_hash_failure(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    dialog = open_setup(qtbot, window)
    dialog.bundle.verify_button.click()
    assert dialog.bundle._thread is not None and not dialog.bundle.verify_button.isEnabled()
    wait_idle(qtbot, dialog)
    assert 'full verification ok (5 files' in dialog.diagnostics.toPlainText()
    assert dialog.bundle.status.text() == 'Bundled runtime: ok (fast check)'
    assert dialog.bundle.verify_button.isEnabled() and dialog._busy_kind is None
    (exe / 'backend' / 'payload' / 'ghidra/docs/a.txt').write_bytes(b'9876543210')  # same size, other bytes
    dialog.bundle.verify_button.click()
    wait_idle(qtbot, dialog)
    assert dialog.bundle.status.text() == 'Bundled runtime problem: PT-BUNDLE-HASH - extract the complete ZIP again'
    assert 'PT-BUNDLE-HASH: ghidra/docs/a.txt' in dialog.diagnostics.toPlainText()


def blocking_verify(started, release=None):
    def fake(ref, *, mode, cancel, event, work_dir):
        assert mode == 'full' and not str(work_dir).startswith(str(ref.root))
        event('Verifying 41,230 files... 38%')
        started.set()
        while not cancel.is_set():
            if release is not None and release.is_set():
                return type('R', (), {'ok': True, 'checked': 1, 'bytes': 1, 'problems': ()})()
            cancel.wait(0.01)
        raise BundleCancelled()
    return fake


def test_verify_progress_and_cancel_leave_settings_unchanged(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    started = threading.Event()
    monkeypatch.setattr(ui_bundle_setup, 'verify_bundle', blocking_verify(started))
    dialog = open_setup(qtbot, window)
    before = (dialog.python.text(), dialog.ghidra.text(), dialog.java_home.text(), window.settings.allKeys())
    dialog.bundle.verify_button.click()
    qtbot.waitUntil(started.is_set, timeout=5000)
    qtbot.waitUntil(lambda: dialog.diagnostics.toPlainText() == 'Verifying 41,230 files... 38%', timeout=5000)
    assert dialog.bundle.cancel_button.isEnabled() and not dialog.check.isEnabled()
    assert not dialog.install.isEnabled()
    dialog.bundle.cancel_button.click()
    wait_idle(qtbot, dialog)
    assert dialog.diagnostics.toPlainText() == 'Bundle verification cancelled. Settings are unchanged.'
    assert (dialog.python.text(), dialog.ghidra.text(), dialog.java_home.text(),
            window.settings.allKeys()) == before
    assert dialog.check.isEnabled() and dialog.install.isEnabled() and dialog.bundle.verify_button.isEnabled()
    assert not dialog.bundle.cancel_button.isEnabled()


def test_second_verify_is_ignored_while_running(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    started, release = threading.Event(), threading.Event()
    monkeypatch.setattr(ui_bundle_setup, 'verify_bundle', blocking_verify(started, release))
    dialog = open_setup(qtbot, window)
    dialog.bundle.verify()
    qtbot.waitUntil(started.is_set, timeout=5000)
    first = dialog.bundle._thread
    dialog.bundle.verify()
    assert dialog.bundle._thread is first
    release.set()
    wait_idle(qtbot, dialog)


def test_closing_the_dialog_cancels_a_running_verification(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    started = threading.Event()
    monkeypatch.setattr(ui_bundle_setup, 'verify_bundle', blocking_verify(started))
    dialog = open_setup(qtbot, window)
    dialog.bundle.verify()
    qtbot.waitUntil(started.is_set, timeout=5000)
    dialog.reject()
    assert dialog.result() == QDialog.DialogCode.Rejected
    qtbot.waitUntil(lambda: not ui_bundle_setup._THREADS, timeout=5000)


def test_verify_disabled_while_diagnosing(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    release = threading.Event()
    monkeypatch.setattr(ui, 'diagnose', lambda config: release.wait(5) and ['done'])
    dialog = open_setup(qtbot, window)
    try:
        dialog.check.click()
        assert not dialog.bundle.verify_button.isEnabled()
        dialog.bundle.verify()  # guarded: no second worker
        assert dialog.bundle._thread is None
    finally:
        release.set()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    assert dialog.bundle.verify_button.isEnabled()


def test_diagnose_button_uses_bundle_mode_and_real_line(qtbot, window, exe, monkeypatch):
    with_bundle(monkeypatch, exe)
    monkeypatch.setenv('PATCHTRACE_BUNDLE_DIR', str(exe))
    monkeypatch.setattr(backend, '_probe_backend', lambda *_: PROBE)
    monkeypatch.setattr(backend, '_java_version', lambda *_: '21.0.2')
    ref = find_bundled_runtime(exe, host=HOST)
    ref.python.chmod(0o755)
    dialog = open_setup(qtbot, window)
    dialog.check.click()
    qtbot.waitUntil(lambda: dialog.worker is None, timeout=5000)
    assert f'Bundled runtime {ref.runtime_id}: fast check ok' in dialog.diagnostics.toPlainText()


# ---- MainWindow.backend_config / run ---------------------------------------------------------

def test_backend_config_falls_back_to_bundle_on_first_launch(window, exe, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_BUNDLE_DIR', str(exe))
    ref = find_bundled_runtime(exe, host=HOST)
    config = window.backend_config()
    assert config.bundle and config.restrict_env
    assert config.python_executable == str(ref.python) and config.java_home == str(ref.java_home)
    assert not str(config.cache_dir)  # raw-output reuse stays profile opt-in
    assert window.settings.value('backend/python', '') == ''  # fallback never writes settings
    window.settings.setValue('backend/python', '/saved/python')
    window.settings.setValue('backend/ghidra', '/saved/ghidra')
    saved = window.backend_config()
    assert not saved.bundle and saved.python_executable == '/saved/python'


def test_backend_config_unchanged_without_bundle(window, monkeypatch):
    monkeypatch.delenv('PATCHTRACE_BUNDLE_DIR', raising=False)
    config = window.backend_config()
    assert not config.bundle and config.python_executable == '' and config.ghidra_dir == ''


def test_run_is_blocked_by_a_failing_fast_check(qtbot, window, exe, monkeypatch):
    monkeypatch.setenv('PATCHTRACE_BUNDLE_DIR', str(exe))
    (exe / 'backend' / 'payload' / 'surprise.txt').write_bytes(b'x')
    monkeypatch.setattr(ui, 'run_comparison', lambda *a: pytest.fail('analysis must not start'))
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    window.run_analysis()
    qtbot.waitUntil(lambda: window.worker is None, timeout=5000)
    assert errors and errors[0].startswith('PT-BUNDLE-EXTRA') and 'extract the complete ZIP again' in errors[0]
