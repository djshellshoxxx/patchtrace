"""Track G offscreen Qt tests (multi-engine-evidence-panel.md section 16): the BinDiff setup panel and
controller, their integration in the C6 Engines tab, threads, accessibility and the C6 regression baseline.

Evidence labels: BinDiff is the FAKE launcher (tests/fake_bindiff.py) or an injected prober (mocked).
BinExport validation runs the REAL C3 `accept_binexport` worker on the committed SYNTHETIC fixtures where a test
says so. The end-to-end run uses a fake C3 acceptor because the fake `bindiff` reads text stand-ins, not
protobuf. Nothing here is live-compatibility evidence.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from fake_bindiff import launcher_names, make_fake_bindiff, write_fake_binexport
from PySide6.QtCore import QCoreApplication, QEvent, QSettings, QThread, QTimer
from PySide6.QtGui import QAccessible
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget
from shiboken6 import isValid
from test_evidence_view import build
from test_tooltips import controls
from test_ui_engine_setup_service import MD5_OLDER, NEW_SHA, NEWER, OLD_SHA, OLDER, fake_acceptor_factory

from patchtrace import cli, ui_engine_setup, ui_evidence
from patchtrace.secondary import bindiff_probe, cli_bindiff
from patchtrace.secondary import evidence_panel_service as svc
from patchtrace.secondary.contracts import Capability
from patchtrace.secondary.registry import BINDIFF_UNSUPPORTED
from patchtrace.service import ProjectService
from patchtrace.ui import MainWindow
from patchtrace.ui_engine_setup import BinDiffSetupController, BinDiffSetupPanel
from patchtrace.ui_evidence import EvidencePanel

PINNED = svc.PINNED_BINDIFF_VERSION


def live_workers() -> list:
    return [t for registry in (ui_engine_setup._LIVE_THREADS, ui_evidence._LIVE_THREADS) for t in list(registry)
            if ui_engine_setup.thread_alive(t)]


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """Probe cache and launcher names per test; every worker must be joined after each test."""
    bindiff_probe.clear_probe_cache()
    monkeypatch.setattr(bindiff_probe, 'EXECUTABLE_NAMES', bindiff_probe.EXECUTABLE_NAMES | launcher_names())
    monkeypatch.delenv('PATCHTRACE_BINDIFF', raising=False)
    yield
    for thread in live_workers():
        thread.cancel.set()
        assert thread.wait(10000), 'worker still running after the test'
    QApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    bindiff_probe.clear_probe_cache()


@pytest.fixture
def settings(tmp_path):
    return QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)


def usable_view(path: str, version: str = PINNED, major: int = 8) -> svc.BinDiffProbeView:
    cap = Capability(engine='bindiff', supported=True, version=version, path=path or '/x/bindiff',
                     supports_json=False)
    return svc.probe_view(path, bindiff_probe.ProbeReport(cap, None, major, major > 8))


def usable_prober(path, cancel):
    return usable_view(path)


class Host:
    """The section embedded as a host would: toggle in a row, section below, both parented."""

    def __init__(self, qtbot, settings, **kw):
        self.widget = QWidget()
        layout = QVBoxLayout(self.widget)
        self.panel = BinDiffSetupPanel(settings)
        layout.addWidget(self.panel.toggle_button)
        layout.addWidget(self.panel)
        self.panel.attach()
        kw.setdefault('discoverer', lambda: ())
        self.controller = BinDiffSetupController(self.panel, settings=settings, **kw)
        qtbot.addWidget(self.widget)

    def open_project(self, identity=('p1', OLD_SHA, NEW_SHA)) -> Host:
        self.panel.set_state(has_project=True, locked=False)
        self.controller.set_project(identity)
        return self


@pytest.fixture
def make_host(qtbot, settings):
    made = []

    def factory(**kw) -> Host:
        host = Host(qtbot, settings, **kw)
        made.append(host)
        return host
    yield factory
    for host in made:
        host.controller.shutdown()


def wait_idle(qtbot, timeout=10000):
    qtbot.waitUntil(lambda: not live_workers(), timeout=timeout)
    QApplication.processEvents()


# ---- section, probe, discovery ---------------------------------------------------------------------------


def test_section_hidden_until_toggled_and_remembered(make_host, settings):
    host = make_host()
    panel = host.panel
    assert panel.isHidden() and not panel.toggle_button.isChecked()
    assert not panel.toggle_button.isEnabled() and not panel.path.isEnabled()  # E0: no project, all disabled
    host.open_project()
    assert panel.toggle_button.isEnabled()
    panel.toggle_button.click()
    assert not panel.isHidden() and settings.value(ui_engine_setup.SETTING_OPEN) in (True, 'true')
    again = make_host()
    assert again.panel.toggle_button.isChecked() and not again.panel.isHidden()
    panel.toggle_button.click()
    assert panel.isHidden()


def test_probe_states_and_capability(make_host, tmp_path, qtbot, settings):
    host = make_host().open_project()
    panel, controller = host.panel, host.controller
    assert panel.probe_status.text() == svc.PROBE_TEXT['empty'] and not panel.probe_button.isEnabled()
    exe = make_fake_bindiff(tmp_path / 'bd')
    panel.set_executable(str(exe))
    assert panel.probe_status.text() == svc.PROBE_TEXT['unchecked'] and controller.capability() is None
    panel.probe_button.click()
    assert panel.probe_status.text() == svc.PROBE_TEXT['probing'] and not panel.probe_button.isEnabled()
    qtbot.waitUntil(lambda: panel.probe_status.text().startswith('Usable: BinDiff 8'), timeout=20000)
    assert panel.probe_status.text().endswith('the BinDiff 8 build PatchTrace was tested with.')
    cap = controller.capability()
    assert not cap.supported and 'choose and validate both .BinExport files' in cap.reason
    assert settings.value(ui_engine_setup.SETTING_PATH) == str(exe)  # saved only after a usable probe
    panel.set_executable(str(exe) + 'x')  # edited: the probe no longer applies
    assert panel.probe_status.text() == svc.PROBE_TEXT['unchecked'] and controller.capability() is None
    old = make_fake_bindiff(tmp_path / 'old', version='BinDiff 7 (@1)')
    panel.set_executable(str(old))
    panel.probe_button.click()
    qtbot.waitUntil(lambda: panel.probe_status.text().startswith('Not usable'), timeout=20000)
    assert panel.probe_status.text() == 'Not usable: BinDiff 7 (@1) is older than the supported version 8.'
    assert not controller.capability().supported and settings.value(ui_engine_setup.SETTING_PATH) == str(exe)
    restored = make_host()
    assert restored.panel.executable() == str(exe)  # the configured path comes back; it is not re-run


def test_discovery_prefills_one_and_runs_nothing(make_host, qtbot, tmp_path):
    probes = []
    one = str(tmp_path / 'bin' / 'bindiff')
    host = make_host(discoverer=lambda: (one,), prober=lambda path, cancel: probes.append(path)).open_project()
    host.panel.toggle_button.click()
    qtbot.waitUntil(lambda: host.panel.executable() == one, timeout=5000)
    assert host.panel.probe_status.text() == svc.PROBE_TEXT['found-one']
    wait_idle(qtbot)
    assert probes == [] and host.controller.capability() is None  # discovered is not configured


def test_discovery_lists_several(make_host, qtbot, tmp_path):
    paths = (str(tmp_path / 'a' / 'bindiff'), str(tmp_path / 'b' / 'bindiff'))
    host = make_host(discoverer=lambda: paths).open_project()
    host.panel.toggle_button.click()
    qtbot.waitUntil(lambda: host.panel.path.count() == 2, timeout=5000)
    assert host.panel.executable() == ''
    assert host.panel.probe_status.text() == svc.PROBE_TEXT['found-many'].format(n=2)


def test_discovery_never_uses_path(make_host, qtbot, tmp_path, monkeypatch):
    from patchtrace.runtime_discovery import discover_local_runtimes
    on_path = tmp_path / 'onpath'
    make_fake_bindiff(on_path)
    home = tmp_path / 'home'
    home.mkdir()
    env = {'PATH': str(on_path), 'HOME': str(home)}
    monkeypatch.setattr(ui_engine_setup, 'discover_local_runtimes',
                        lambda: discover_local_runtimes(environ=env, bindiff_system_paths=()))
    host = make_host(discoverer=ui_engine_setup.discover_bindiff).open_project()
    host.panel.toggle_button.click()
    qtbot.waitUntil(lambda: host.controller.discovery_started, timeout=5000)
    wait_idle(qtbot)
    assert host.panel.executable() == '' and host.panel.path.count() == 0
    assert host.panel.probe_status.text() == svc.PROBE_TEXT['empty']


# ---- validation ------------------------------------------------------------------------------------------


def test_validation_real_c3_flow(make_host, qtbot):
    host = make_host(prober=usable_prober).open_project()
    panel, controller = host.panel, host.controller
    assert panel.validation_status.text() == svc.VALIDATION_TEXT['idle']
    panel.validate_button.click()
    assert panel.validation_status.text() == svc.VALIDATION_TEXT['missing']
    panel.older.setText(str(OLDER))
    panel.newer.setText(str(NEWER))
    panel.validate_button.click()
    assert not panel.progress.isHidden() and panel.cancel_button.isEnabled() and not panel.validate_button.isEnabled()
    qtbot.waitUntil(lambda: controller.validation is not None, timeout=60000)
    assert panel.validation_status.text().splitlines() == [
        svc.VALIDATION_TEXT['ok'],
        'Older: 3 functions, architecture x86-64, executable id SHA-256, matches the older file.',
        'Newer: 4 functions, architecture x86-64, executable id SHA-256, matches the newer file.']
    assert panel.progress.isHidden() and not panel.cancel_button.isEnabled()
    panel.show_details.setChecked(True)
    assert not panel.details.isHidden() and 'Binding recorded with a run: sha256' in panel.details.toPlainText()
    assert controller.capability() is None and controller.run_setup() is None  # BinDiff itself not probed yet
    panel.set_executable('/x/bindiff')
    panel.probe_button.click()
    qtbot.waitUntil(lambda: controller.current_probe() is not None, timeout=5000)
    assert controller.capability().supported
    assert controller.run_setup() == svc.BinDiffSetup('/x/bindiff', OLDER, NEWER, False)


def test_validation_real_c3_swapped_message(make_host, qtbot):
    host = make_host().open_project()
    panel = host.panel
    panel.older.setText(str(NEWER))
    panel.newer.setText(str(OLDER))
    panel.validate_button.click()
    qtbot.waitUntil(lambda: host.controller.validation is not None, timeout=60000)
    assert panel.validation_status.text() == ('Not accepted: The two .BinExport files are swapped: the file chosen '
                                              'as older was exported from the newer file (or the reverse). Swap '
                                              'them and validate again.')
    panel.show_details.setChecked(True)
    assert 'Kind: binexport-orientation' in panel.details.toPlainText()


def test_unbound_override_real_c3(make_host, qtbot):
    host = make_host(prober=usable_prober).open_project()
    panel, controller = host.panel, host.controller
    panel.older.setText(str(MD5_OLDER))
    panel.newer.setText(str(NEWER))
    panel.validate_button.click()
    qtbot.waitUntil(lambda: controller.validation is not None, timeout=60000)
    text = panel.validation_status.text()
    assert text.startswith('Not accepted: The older .BinExport records only an MD5 hash')
    assert 'tick the confirmation below' in text
    assert not panel.warning.isHidden() and 'Warning:' in panel.warning.text()
    panel.accept_box.setChecked(True)
    assert controller.validation is None and panel.validation_status.text() == svc.VALIDATION_TEXT['idle']
    panel.validate_button.click()
    qtbot.waitUntil(lambda: controller.validation is not None, timeout=60000)
    assert controller.validation.binding == 'asserted:older=md5,newer=sha256'
    assert panel.validation_status.text().splitlines()[0] == svc.VALIDATION_TEXT['ok-asserted']
    panel.set_executable('/x/bindiff')
    panel.probe_button.click()
    qtbot.waitUntil(lambda: controller.current_probe() is not None, timeout=5000)
    assert controller.run_setup() == svc.BinDiffSetup('/x/bindiff', MD5_OLDER, NEWER, True)
    panel.older.setText(str(OLDER))  # another file: the confirmation does not carry over
    assert not panel.accept_box.isChecked() and controller.run_setup() is None
    panel.older.setText(str(MD5_OLDER))
    panel.accept_box.setChecked(True)
    controller.set_project(('p2', OLD_SHA, NEW_SHA))  # another project: inputs and confirmation reset
    assert panel.older_path() == '' and not panel.accept_box.isChecked()


def test_progress_texts_and_cancel(make_host, qtbot):
    ran_off_gui = []

    def validator(request, cancel, progress=None):
        ran_off_gui.append(QThread.currentThread() is not QApplication.instance().thread())
        progress('older')
        progress('newer')
        while not cancel.is_set():
            time.sleep(0.01)
        return svc.BinExportValidation('cancelled', request.key)
    host = make_host(validator=validator).open_project()
    panel = host.panel
    panel.older.setText('o.BinExport')
    panel.newer.setText('n.BinExport')
    panel.validate_button.click()
    qtbot.waitUntil(lambda: 'step 2 of 2' in panel.validation_status.text(), timeout=5000)
    assert panel.validation_status.text() == svc.VALIDATION_TEXT['step'].format(side='newer', n=2)
    panel.cancel_button.click()
    assert panel.validation_status.text() == svc.VALIDATION_TEXT['cancelled']
    assert panel.validate_button.isEnabled() and panel.progress.isHidden() and not panel.cancel_button.isEnabled()
    wait_idle(qtbot)
    assert ran_off_gui == [True] and host.controller.validation is None


def test_project_switch_drops_late_validation(make_host, qtbot):
    gate = threading.Event()

    def validator(request, cancel, progress=None):
        gate.wait(5)
        return svc.BinExportValidation('ok', request.key, binding='sha256')
    host = make_host(validator=validator).open_project()
    panel = host.panel
    panel.older.setText(str(OLDER))
    panel.newer.setText(str(NEWER))
    panel.validate_button.click()
    host.controller.set_project(('p2', OLD_SHA, NEW_SHA))
    assert panel.older_path() == '' and panel.validation_status.text() == svc.VALIDATION_TEXT['idle']
    gate.set()
    wait_idle(qtbot)
    assert host.controller.validation is None and panel.validation_status.text() == svc.VALIDATION_TEXT['idle']


def test_gui_thread_heartbeat_during_real_validation(make_host, qtbot):
    host = make_host().open_project()
    host.panel.older.setText(str(OLDER))
    host.panel.newer.setText(str(NEWER))
    ticks = []
    timer = QTimer()
    timer.setInterval(20)
    timer.timeout.connect(lambda: ticks.append(time.perf_counter()))
    timer.start()
    started = time.perf_counter()
    host.controller.start_validation()
    slot = time.perf_counter() - started
    qtbot.waitUntil(lambda: host.controller.validation is not None, timeout=60000)
    timer.stop()
    gaps = [b - a for a, b in zip(ticks, ticks[1:], strict=False)]
    assert host.controller.validation.status == 'ok'
    assert slot < 0.25, slot  # the slot only starts a worker (5x slack over 50 ms)
    assert len(ticks) >= 5 and max(gaps) < 0.5, (len(ticks), max(gaps, default=0))


def test_slots_fast_and_call_ceilings(make_host, qtbot):
    calls = {'probe': 0, 'validate': 0}

    def prober(path, cancel):
        calls['probe'] += 1
        time.sleep(0.4)
        return usable_view(path)

    def validator(request, cancel, progress=None):
        calls['validate'] += 1
        time.sleep(0.4)
        return svc.BinExportValidation('ok', request.key, binding='sha256')
    host = make_host(prober=prober, validator=validator).open_project()
    changed = []
    host.controller.changed.connect(lambda: changed.append(1))
    panel = host.panel
    panel.set_executable('/x/bindiff')
    panel.older.setText('o.BinExport')
    panel.newer.setText('n.BinExport')
    started = time.perf_counter()
    panel.probe_button.click()
    probe_slot = time.perf_counter() - started
    started = time.perf_counter()
    panel.validate_button.click()
    validate_slot = time.perf_counter() - started
    assert probe_slot < 0.25 and validate_slot < 0.25, (probe_slot, validate_slot)
    qtbot.waitUntil(lambda: host.controller.run_setup() is not None, timeout=10000)
    assert calls == {'probe': 1, 'validate': 1}
    assert 1 <= len(changed) <= 3, changed  # only real capability/run-setup changes are announced


def test_shutdown_cancels_and_joins(make_host, qtbot):
    def prober(path, cancel):
        while not cancel.is_set():
            time.sleep(0.01)
        return usable_view(path)

    def validator(request, cancel, progress=None):
        while not cancel.is_set():
            time.sleep(0.01)
        return svc.BinExportValidation('cancelled', request.key)
    host = make_host(prober=prober, validator=validator).open_project()
    panel = host.panel
    panel.set_executable('/x/bindiff')
    panel.older.setText('o.BinExport')
    panel.newer.setText('n.BinExport')
    panel.probe_button.click()
    panel.validate_button.click()
    threads = [t for t, _ in host.controller.threads]
    assert len(threads) == 2
    started = time.perf_counter()
    host.controller.shutdown()
    assert time.perf_counter() - started < 5
    assert all(not t.isRunning() for t in threads if isValid(t)) and host.controller.threads == []


def test_worker_never_touches_widgets(make_host, qtbot, monkeypatch):
    app_thread = QApplication.instance().thread()
    violations, places = [], []
    original_init = QWidget.__init__

    def guarded(self, *args, **kwargs):
        if QThread.currentThread() is not app_thread:
            violations.append(type(self).__name__)
        original_init(self, *args, **kwargs)
    monkeypatch.setattr(QWidget, '__init__', guarded)

    def where(result):
        places.append(QThread.currentThread() is not app_thread)
        return result
    host = make_host(prober=lambda path, cancel: where(usable_view(path)),
                     validator=lambda request, cancel, progress=None: where(
                         svc.BinExportValidation('ok', request.key, binding='sha256')),
                     discoverer=lambda: where(())).open_project()
    host.panel.toggle_button.click()
    qtbot.waitUntil(lambda: host.controller.discovery_started, timeout=5000)  # discovery only fills an empty field
    host.panel.set_executable('/x/bindiff')
    host.panel.older.setText('o.BinExport')
    host.panel.newer.setText('n.BinExport')
    host.panel.probe_button.click()
    host.panel.validate_button.click()
    qtbot.waitUntil(lambda: host.controller.run_setup() is not None, timeout=10000)
    wait_idle(qtbot)
    assert places == [True, True, True] and violations == []


def test_hostile_strings_render_plain(make_host, qtbot):
    hostile = '<img src=x onerror=1>‮\x1b[31m'

    def prober(path, cancel):
        cap = Capability(engine='bindiff', supported=True, version='9 ' + hostile, path='/x/bindiff',
                         supports_json=False)
        return svc.probe_view(path, bindiff_probe.ProbeReport(cap, None, 9, True))
    host = make_host(prober=prober).open_project()
    panel = host.panel
    panel.set_executable('/x/bindiff')
    panel.probe_button.click()
    qtbot.waitUntil(lambda: host.controller.current_probe() is not None, timeout=5000)
    status = panel.probe_status.text()
    assert '<img src=x onerror=1>' in status and '‮' not in status and '\x1b' not in status
    for label in (panel.probe_status, panel.validation_status, panel.warning, panel.help):
        assert label.textFormat() == ui_engine_setup.Qt.TextFormat.PlainText


def test_hostile_architecture_name_plain(make_host, qtbot, tmp_path):
    hostile = '<b>arm</b>‮'

    def factory(private_dir):
        accept = fake_acceptor_factory(private_dir)

        def hostile_accept(*args, **kwargs):
            accepted = accept(*args, **kwargs)
            summary = SimpleNamespace(**{**vars(accepted.summary), 'architecture_name': hostile})
            return SimpleNamespace(snapshot_path=accepted.snapshot_path, summary=summary)
        return hostile_accept
    older = write_fake_binexport(tmp_path / 'o.BinExport', OLD_SHA)
    newer = write_fake_binexport(tmp_path / 'n.BinExport', NEW_SHA)
    host = make_host(validator=lambda request, cancel, progress=None: svc.validate_binexports(
        request, cancel, acceptor_factory=factory)).open_project()
    host.panel.older.setText(str(older))
    host.panel.newer.setText(str(newer))
    host.panel.validate_button.click()
    qtbot.waitUntil(lambda: host.controller.validation is not None, timeout=10000)
    text = host.panel.validation_status.text()
    assert 'architecture <b>arm</b>,' in text and '‮' not in text


# ---- tooltips, accessibility, keyboard, source rules ------------------------------------------------------


def test_accessible_names_descriptions_and_announcing_status(make_host):
    host = make_host().open_project()
    panel = host.panel
    found = controls(panel) + [panel.toggle_button]
    assert len(found) >= 13
    for widget in found:
        assert widget.accessibleName() and widget.accessibleDescription(), widget.objectName()
    assert panel.accessibleName() == 'BinDiff run setup'
    for label in (panel.probe_status, panel.validation_status):
        assert label.accessibleName() == ''  # empty: QLabel.setText announces the new text itself
        assert QAccessible.queryAccessibleInterface(label).text(QAccessible.Text.Name) == label.text()
    assert set(ui_engine_setup.ACCESSIBLE_NAMES.values()) >= {w.accessibleName() for w in found}


def test_keyboard_order_in_engines_tab(qtbot, settings):
    evidence = EvidencePanel(settings)
    qtbot.addWidget(evidence)
    setup = evidence.bindiff_setup
    expected = [evidence.import_button, setup.toggle_button, *setup.focus_chain(), evidence.engine_log,
                evidence.copy_details_button]
    order, widget = [], evidence.import_button
    for _ in range(400):
        if widget in expected and widget not in order:
            order.append(widget)
        widget = widget.nextInFocusChain()
        if widget is evidence.import_button:
            break
    assert order == expected


def test_forbidden_apis_absent_in_setup_module():
    import ast
    source = Path(ui_engine_setup.__file__).read_text(encoding='utf-8')
    for banned in ('setHtml', 'setMarkdown', 'RichText', '.terminate(', 'shutil.which', 'subprocess',
                   'os.environ', 'diagnostics', 'QSortFilterProxyModel'):
        assert banned not in source, banned
    tasks = [node.args[0] for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
             and getattr(node.func, 'id', '') == 'TaskThread']
    assert len(tasks) == 3 and all(isinstance(task, ast.Lambda) for task in tasks)
    for task in tasks:  # worker tasks capture plain values and callables, never the controller or a widget
        assert 'self' not in {n.id for n in ast.walk(task) if isinstance(n, ast.Name)}


def test_default_discoverer_reads_runtime_discovery_only(monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(ui_engine_setup, 'discover_local_runtimes',
                        lambda: seen.append(1) or SimpleNamespace(bindiff_executables=(tmp_path / 'bindiff',)))
    assert ui_engine_setup.discover_bindiff() == (str(tmp_path / 'bindiff'),) and seen == [1]


# ---- integration in the C6 dock ------------------------------------------------------------------------


PRE_EXISTING = ('tabs', 'filter', 'search', 'hide_agreed', 'show_index_box', 'copy_button', 'refresh_button',
                'engines_label', 'status', 'stale_banner', 'partial_banner', 'state_label', 'loading_bar',
                'retry_button', 'copy_error_button', 'open_engines_button', 'table', 'detail', 'goto_button',
                'engine_table', 'parallel', 'timeout', 'run_button', 'cancel_button', 'probe_button',
                'import_button', 'run_progress', 'run_status', 'preview', 'engine_log', 'copy_details_button',
                'footer')


def describe(widget) -> tuple:
    parts = [type(widget).__name__, widget.objectName(), widget.isEnabled(), widget.isHidden(), widget.toolTip(),
             widget.accessibleName(), widget.accessibleDescription()]
    for getter in ('text', 'toPlainText', 'currentText', 'value', 'isChecked', 'count'):
        method = getattr(widget, getter, None)
        if callable(method):
            try:
                parts.append((getter, method()))
            except TypeError:
                pass
    return tuple(parts)


def fingerprint(panel) -> list:
    rows = [describe(getattr(panel, name)) for name in PRE_EXISTING]
    rows += [describe(box) for box in panel.engine_checks.values()]
    rows.append(tuple(panel.tabs.tabText(i) for i in range(panel.tabs.count())))
    rows.append(tuple((r.engine, r.state, r.detail) for r in panel.engine_model.rows))
    return rows


DEFAULT_CAPS = {
    'rz-diff': Capability(engine='rz-diff', supported=True, version='0.9.1', path='/x/rz-diff', supports_json=True),
    'bindiff': Capability(engine='bindiff', supported=False, version=None, path='', supports_json=False,
                          reason=BINDIFF_UNSUPPORTED)}


def test_unconfigured_panel_matches_c6_baseline(qtbot, tmp_path):
    """Flag/regression (spec 16.1): unconfigured, the dock is the C6 dock plus one hidden section and its toggle."""
    current = EvidencePanel(QSettings(str(tmp_path / 'a.ini'), QSettings.Format.IniFormat))
    baseline = EvidencePanel(QSettings(str(tmp_path / 'b.ini'), QSettings.Format.IniFormat), bindiff_setup=False)
    for panel in (current, baseline):
        qtbot.addWidget(panel)
    assert baseline.bindiff_setup is None and current.bindiff_setup.isHidden()
    states = [
        lambda p: p.set_project(False),                                  # E0
        lambda p: (p.set_project(True), p.set_view_model(build(sets=()))),  # E1
        lambda p: p.set_loading(True),                                   # E2 over a shown state
        lambda p: p.set_view_model(build()),                             # E3
        lambda p: p.set_capabilities(DEFAULT_CAPS),
        lambda p: p.engine_checks['rz-diff'].setChecked(True),
        lambda p: p.set_run_blocked(None),
        lambda p: p.set_stale('the project changed after these results were loaded'),  # E6
        lambda p: p.set_run_active(True, ('rz-diff',)),
        lambda p: p.set_run_active(False),
        lambda p: p.set_failed('PT-EVIDENCE-ASSEMBLY: x'),                # E5
    ]
    for step in states:
        step(current)
        step(baseline)
        assert fingerprint(current) == fingerprint(baseline)
    extra = {w.objectName() for w in controls(current)} - {w.objectName() for w in controls(baseline)}
    assert extra == {name for name in extra if name.startswith('engine_setup.')} and len(extra) == 13
    assert {w.objectName() for w in controls(baseline)} <= {w.objectName() for w in controls(current)}


@pytest.fixture
def window(qtbot, tmp_path, settings):
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    qtbot.addWidget(view)
    view.evidence.auto_probe = False
    yield view
    view.evidence.shutdown()
    if view.service:
        view.service.close()
        view.service = None


def open_dock(window, qtbot):
    window.show()
    window.evidence.action.trigger()
    qtbot.waitUntil(lambda: window.evidence.panel.vm.state != 'no-project' and not window.evidence.panel.loading,
                    timeout=10000)


def test_unconfigured_controller_keeps_c6_flow(window, qtbot):
    controller = window.evidence
    controller.probe = lambda cancel: dict(DEFAULT_CAPS)
    open_dock(window, qtbot)
    controller.start_probe()
    qtbot.waitUntil(lambda: controller.probe_thread is None, timeout=5000)
    assert controller.capabilities == DEFAULT_CAPS and controller.bindiff.capability() is None
    rows = {r.engine: r for r in controller.panel.engine_model.rows}
    assert rows['bindiff'].state == 'unsupported' and rows['bindiff'].detail == BINDIFF_UNSUPPORTED
    assert not controller.panel.engine_checks['bindiff'].isEnabled()
    captured = []
    controller.run_execute = lambda request, cancel, **kw: captured.append(request) or ()
    controller.panel.engine_checks['rz-diff'].setChecked(True)
    controller.update_controls()
    assert svc.RUN_PREVIEW_BINDIFF not in controller.panel.preview.text()
    controller.panel.run_button.click()
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=10000)
    assert captured and captured[0].bindiff is None and captured[0].bindiff_raw_dir is None


def engine_runs(service) -> list:
    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.secondary.runs import RUN_KIND, EngineRun
    return [EngineRun.model_validate_json(json.dumps(entry.body))
            for entry in EnrichmentStore(service.store).entries(RUN_KIND)]


def test_gui_bindiff_run_matches_cli_provenance(window, qtbot, tmp_path, monkeypatch):
    """End to end through the C6 run flow with a fake BinDiff and the explicit unbound confirmation; the stored
    EngineRun provenance equals what `secondary run --engine bindiff --accept-unbound-binexport` records."""
    monkeypatch.setattr(cli_bindiff, 'c3_acceptor', fake_acceptor_factory)  # mocked C3 for text stand-ins
    exe = make_fake_bindiff(tmp_path / 'bd')
    older = write_fake_binexport(tmp_path / 'older.BinExport', '1' * 32)  # MD5-sized id: needs confirmation
    newer = write_fake_binexport(tmp_path / 'newer.BinExport', NEW_SHA)
    controller = window.evidence
    controller.probe = lambda cancel: dict(DEFAULT_CAPS)
    open_dock(window, qtbot)
    setup = controller.panel.bindiff_setup
    setup.toggle_button.click()
    assert not setup.isHidden()
    setup.set_executable(str(exe))
    setup.probe_button.click()
    qtbot.waitUntil(lambda: setup.probe_status.text().startswith('Usable'), timeout=20000)
    setup.older.setText(str(older))
    setup.newer.setText(str(newer))
    setup.accept_box.setChecked(True)
    setup.validate_button.click()
    qtbot.waitUntil(lambda: controller.bindiff.validation is not None, timeout=20000)
    assert controller.bindiff.validation.status == 'ok', controller.bindiff.validation.message
    box = controller.panel.engine_checks['bindiff']
    assert box.isEnabled() and controller.capabilities['bindiff'].supported
    box.setChecked(True)
    controller.update_controls()
    assert svc.RUN_PREVIEW_BINDIFF in controller.panel.preview.text()
    on_gui = []
    original = svc.persist_outcome

    def spy(service, request, view):
        on_gui.append(QThread.currentThread() is QApplication.instance().thread())
        return original(service, request, view)
    monkeypatch.setattr(svc, 'persist_outcome', spy)
    controller.panel.run_button.click()
    assert setup.older.isEnabled() is False  # inputs locked while engines run
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=60000)
    qtbot.waitUntil(lambda: controller.panel.vm.engine('bindiff').state == 'ready', timeout=20000)
    assert on_gui == [True] and setup.older.isEnabled()
    [gui] = [r for r in engine_runs(window.service) if r.engine == 'bindiff']
    assert gui.status == 'ok' and gui.provenance['binexport_binding'] == 'asserted:older=md5,newer=sha256'
    run = svc.latest_run(window.project)
    assert list((window.service.root / 'runs' / run.id / 'raw' / 'secondary').glob('bindiff-*.BinDiff'))
    other = ProjectService.sample(tmp_path / 'cli')
    root = other.root
    other.close()
    code = cli.main(['secondary', 'run', str(root), '--json', '--engine', 'bindiff', '--bindiff', str(exe),
                     '--older-binexport', str(older), '--newer-binexport', str(newer),
                     '--accept-unbound-binexport'])
    assert code == 0
    reopened = ProjectService.open(root)
    try:
        [from_cli] = [r for r in engine_runs(reopened) if r.engine == 'bindiff']
    finally:
        reopened.close()
    assert from_cli.provenance == gui.provenance


def test_bindiff_checkbox_follows_setup(window, qtbot):
    controller = window.evidence
    controller.probe = lambda cancel: dict(DEFAULT_CAPS)
    controller.bindiff.prober = usable_prober
    controller.bindiff.validator = lambda request, cancel, progress=None: svc.BinExportValidation(
        'ok', request.key, binding='sha256')
    open_dock(window, qtbot)
    controller.start_probe()
    qtbot.waitUntil(lambda: controller.probe_thread is None, timeout=5000)
    setup, box = controller.panel.bindiff_setup, controller.panel.engine_checks['bindiff']
    setup.set_executable('/x/bindiff')
    setup.probe_button.click()
    qtbot.waitUntil(lambda: controller.bindiff.current_probe() is not None, timeout=5000)
    rows = {r.engine: r for r in controller.panel.engine_model.rows}
    assert not box.isEnabled() and 'choose and validate both .BinExport files' in rows['bindiff'].detail
    setup.older.setText(str(OLDER))
    setup.newer.setText(str(NEWER))
    setup.validate_button.click()
    qtbot.waitUntil(box.isEnabled, timeout=5000)
    box.setChecked(True)
    controller.update_controls()
    assert svc.RUN_PREVIEW_BINDIFF in controller.panel.preview.text()
    setup.newer.setText(str(NEWER) + '.other')  # an edit invalidates the validation: BinDiff is not runnable
    assert not box.isEnabled() and not box.isChecked()
    assert svc.RUN_PREVIEW_BINDIFF not in controller.panel.preview.text()


def test_cancel_gui_bindiff_run(window, qtbot, tmp_path, monkeypatch):
    """The C6 Cancel button stops a running BinDiff: process tree killed, nothing stored (fake BinDiff)."""
    from fake_bindiff import spy_calls

    from patchtrace.enrichment.storage import EnrichmentStore
    from patchtrace.secondary.store import current_sets
    monkeypatch.setattr(cli_bindiff, 'c3_acceptor', fake_acceptor_factory)
    exe = make_fake_bindiff(tmp_path / 'bd', 'hang')
    older = write_fake_binexport(tmp_path / 'older.BinExport', OLD_SHA)
    newer = write_fake_binexport(tmp_path / 'newer.BinExport', NEW_SHA)
    controller = window.evidence
    controller.probe = lambda cancel: dict(DEFAULT_CAPS)
    open_dock(window, qtbot)
    setup = controller.panel.bindiff_setup
    setup.set_executable(str(exe))
    setup.probe_button.click()
    qtbot.waitUntil(lambda: controller.bindiff.current_probe() is not None, timeout=20000)
    setup.older.setText(str(older))
    setup.newer.setText(str(newer))
    setup.validate_button.click()
    qtbot.waitUntil(controller.panel.engine_checks['bindiff'].isEnabled, timeout=20000)
    controller.panel.engine_checks['bindiff'].setChecked(True)
    controller.panel.run_button.click()
    qtbot.waitUntil(lambda: any('--nologo' in c['argv'] and len(c['argv']) > 2 for c in spy_calls(tmp_path / 'bd')),
                    timeout=30000)
    controller.panel.cancel_button.click()
    qtbot.waitUntil(lambda: controller.run_thread is None, timeout=30000)
    assert controller.outcomes['bindiff'].status == 'cancelled'
    assert [m.engine for _, m in current_sets(EnrichmentStore(window.service.store))] == []
    assert not list(window.service.root.rglob('bindiff-*.BinDiff'))


def test_dock_deleted_while_setup_worker_runs(qtbot, tmp_path, settings):
    """C6 teardown matrix for the setup worker: the unparented thread survives the dock; its late result is
    dropped without touching the deleted section (pytest-qt fails the test if a slot raises)."""
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    view.evidence.auto_probe = False
    controller = view.evidence.bindiff
    gate = threading.Event()

    def validator(request, cancel, progress=None):
        gate.wait(5)
        return svc.BinExportValidation('ok', request.key, binding='sha256')
    controller.validator = validator
    setup = view.evidence.panel.bindiff_setup
    setup.older.setText('o.BinExport')
    setup.newer.setText('n.BinExport')
    setup.validate_button.click()
    [thread] = [t for t, _ in controller.threads]
    assert thread.parent() is None
    view.evidence.dock.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gate.set()
    assert thread.wait(5000)
    qtbot.wait(50)  # deliver the queued result
    assert controller.validation is None
    view.evidence.shutdown()
    view.service.close()
    view.service = None
    view.deleteLater()


def test_window_close_joins_setup_workers(qtbot, tmp_path, settings):
    view = MainWindow(ProjectService.sample(tmp_path / 's'), settings, tmp_path / 'profiles')
    view.evidence.auto_probe = False
    controller = view.evidence.bindiff

    def validator(request, cancel, progress=None):
        while not cancel.is_set():
            time.sleep(0.01)
        return svc.BinExportValidation('cancelled', request.key)
    controller.validator = validator
    view.show()
    view.evidence.action.trigger()
    setup = view.evidence.panel.bindiff_setup
    setup.older.setText('o.BinExport')
    setup.newer.setText('n.BinExport')
    setup.validate_button.click()
    [thread] = [t for t, _ in controller.threads]
    view.close()  # closeEvent -> EvidenceController.shutdown -> BinDiffSetupController.shutdown (cancel + join)
    assert not ui_engine_setup.thread_alive(thread) and controller.threads == []
    view.deleteLater()
