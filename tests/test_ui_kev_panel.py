# ruff: noqa: F811
"""KEV-K3 dock: states, consent, hostile text, names, anchors and threads (offscreen Qt).

Docs: docs/specs/program-e/KEV-integration-plan.md s8. The controller is driven through the fake panel ports of
leads_support over a real catalog folder and a fake network; no test opens a socket."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from kev_helpers import FIXTURES, NOW, SYNTHETIC, document, entry, render, socket_guard
from leads_support import FakeNav, FakeProject, FakeShell
from PySide6.QtWidgets import QApplication
from qt_support import (  # noqa: F401
    a11y_audit,
    join_gui_threads,
    top_level_windows,
)

from patchtrace import ui_kev_model as pm
from patchtrace.gui import registry
from patchtrace.gui.anchors import NavResult
from patchtrace.gui.qt.tasks import TaskFailure, TaskRunner
from patchtrace.kev.contracts import KevError, plan_for
from patchtrace.kev.panel import PANEL
from patchtrace.kev.service import KevService
from patchtrace.panel_manifest import MANIFEST
from patchtrace.ui_kev import NAV_FAILURE, KevController

no_sockets = pytest.fixture(autouse=True, scope='module')(socket_guard)

LISTED, ABSENT = 'CVE-2099-10010', 'CVE-2099-99999'
MIRROR = plan_for('cisa-github')
CHECKING = 'Checking the downloaded file...'


class Response:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self.status, self.headers = 200, {'Content-Type': 'text/plain; charset=utf-8'}

    def read1(self, size: int) -> bytes:
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self) -> None: ...


def opener_of(routes: dict, calls: list):
    def opener(url, headers, timeout):
        calls.append(url)
        answer = routes.get(url)
        if isinstance(answer, threading.Event):
            answer.wait(5)
            answer = routes['body']
        if answer is None:
            raise OSError('no route')
        return Response(answer)
    return opener


class Shell(FakeShell):
    def __init__(self, tasks) -> None:
        super().__init__(tasks)
        self.picked = None

    def choose_file(self, title, file_filter=''):
        return self.picked


def catalog_file(tmp_path, name='in.json', **first):
    path = tmp_path / name
    path.write_bytes(render(document([entry(1, **first), entry(2)])))
    return path


def start(qtbot, tmp_path, *, install=True, now=NOW, network=True, routes=None, project=None, show=True):
    calls: list = []
    service = KevService(tmp_path / 'kev', now=lambda: now, opener=opener_of(routes or {}, calls),
                         sleep=lambda seconds, cancel: None)
    if install:
        service.import_file(FIXTURES / SYNTHETIC)
    project = project or FakeProject()
    nav, shell = FakeNav(), Shell(TaskRunner(reraise=True))
    ctx = SimpleNamespace(spec=PANEL, project=project, mutate=SimpleNamespace(), nav=nav, shell=shell, tasks=shell.tasks)
    controller = KevController(ctx, service=service, network_allowed=lambda: network)
    qtbot.addWidget(controller.panel)
    controller.panel.resize(1000, 700)
    if show:
        controller.panel.show()
    controller.project_changed(project.key())
    settle(qtbot, controller)
    return controller, nav, shell, calls


def settle(qtbot, controller) -> None:
    qtbot.waitUntil(lambda: not controller.tasks.busy() and not controller.operation, timeout=5000)
    QApplication.processEvents()


def look(qtbot, controller, text) -> None:
    controller.panel.lookup_box.setText(text)
    controller.panel.lookup_requested.emit(text)
    settle(qtbot, controller)


def state(controller) -> tuple[str, str]:
    view = controller.panel.state
    return view.kind, view.model.text


def rows(controller) -> list[tuple[str, ...]]:
    model = controller.panel.table.table_model
    return [model.texts_at(i) for i in range(model.rowCount())]


def audit(widget) -> list[str]:
    return [p for p in a11y_audit(widget) if p != 'QHeaderView#?: not keyboard focusable']


# ---- the declaration ---------------------------------------------------------------------------------------------

def test_the_spec_agrees_with_its_slot_and_lints_clean():
    loaded = registry.load_manifest([e for e in MANIFEST if e.id == 'kev'])
    assert loaded.specs['kev'] is PANEL and not loaded.errors and not loaded.forbidden
    assert [f for f in registry.lint(MANIFEST, loaded).findings if f.panel == 'kev'] == []


def test_loading_the_spec_imports_no_qt():
    code = 'import sys, patchtrace.kev.panel; sys.exit(any(n.startswith(("PySide6", "patchtrace.ui")) for n in sys.modules))'
    import patchtrace
    env = {**os.environ, 'PYTHONPATH': str(Path(patchtrace.__file__).parents[1])}
    assert subprocess.run([sys.executable, '-c', code], check=False, env=env).returncode == 0


# ---- states ------------------------------------------------------------------------------------------------------

def test_k0_without_a_catalog_offers_update_and_import(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, install=False)
    kind, text = state(controller)
    assert kind == 'idle' and text.startswith('No KEV catalog is loaded. PatchTrace works without it.')
    buttons = controller.panel.buttons
    assert buttons['update'].isEnabled() and buttons['import'].isEnabled() and not buttons['changes'].isEnabled()


def test_k8_network_off_blocks_only_update(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, install=False, network=False)
    assert state(controller)[0] == 'blocked' and 'switched off' in state(controller)[1]
    assert not controller.panel.buttons['update'].isEnabled() and controller.panel.buttons['import'].isEnabled()


def test_network_off_with_a_catalog_keeps_lookups_and_shows_a_notice(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, network=False)
    look(qtbot, controller, LISTED)
    assert state(controller) == ('ready', '') and rows(controller)[0][1] == 'Listed'
    assert controller.panel.notices.current.key == 'kev.network'


def test_k4_ready_shows_the_catalog_line_and_asks_for_ids(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    assert controller.panel.status.full_text().startswith('KEV catalog ')
    assert state(controller) == ('idle', 'Type or paste CVE IDs above, or open a KB or CVE view that passes its CVEs here.')


def test_lookup_rows_keep_input_order_and_absence_is_not_a_negative(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, f'{ABSENT}, {LISTED} nonsense {LISTED}')
    assert [r[0] for r in rows(controller)] == [ABSENT, LISTED, 'nonsense']
    assert rows(controller)[0][1:] == ('Not listed', 'Not supplied', 'Not supplied', 'Not supplied')
    assert rows(controller)[2][:2] == ('nonsense', 'Invalid CVE ID')


def test_filter_and_sort_change_only_the_view(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, f'{ABSENT} {LISTED}')
    panel = controller.panel
    panel.sort.setCurrentIndex(panel.sort.findData('kev-first'))
    settle(qtbot, controller)
    assert [r[0] for r in rows(controller)] == [LISTED, ABSENT]
    panel.filter.setCurrentIndex(panel.filter.findData('listed-ransomware'))
    settle(qtbot, controller)
    assert rows(controller) == [] or all(r[1].startswith('Listed') for r in rows(controller))
    panel.filter.setCurrentIndex(panel.filter.findData('no-catalog-or-invalid'))
    settle(qtbot, controller)
    assert state(controller) == ('idle', 'No CVEs match the selected KEV status filter.')
    assert controller.ids == (ABSENT, LISTED)


def test_k5_aging_is_a_notice_beside_a_ready_table(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, now=NOW + timedelta(days=8))
    look(qtbot, controller, LISTED)
    assert state(controller)[0] == 'ready'
    assert controller.panel.notices.current.text.startswith('This catalog is ')


def test_k6_stale_keeps_results_and_offers_refresh(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, now=NOW + timedelta(days=30))
    look(qtbot, controller, LISTED)
    kind, text = state(controller)
    assert kind == 'stale' and 'may have been added since' in text
    assert rows(controller) and controller.panel.state.action_button('refresh').isVisibleTo(controller.panel)


def test_future_release_asks_to_check_the_clock(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, now=datetime(2099, 2, 1, tzinfo=UTC))
    assert state(controller)[0] == 'stale' and 'in the future' in state(controller)[1]


def test_import_failure_is_a_closed_reason_and_keeps_the_catalog(qtbot, tmp_path):
    controller, _, shell, _ = start(qtbot, tmp_path)
    bad = tmp_path / 'bad.json'
    bad.write_text('{"not": "kev"}', encoding='utf-8')
    shell.picked = bad
    controller.panel.buttons['import'].click()
    settle(qtbot, controller)
    kind, text = state(controller)
    assert kind == 'error' and text.startswith('Could not update the KEV catalog: ') and 'is still in use.' in text
    assert str(tmp_path) not in text and 'Traceback' not in text
    assert controller.panel.state.action_button('retry').isVisibleTo(controller.panel)


def test_import_of_an_older_release_keeps_the_newer_and_says_so(qtbot, tmp_path):
    controller, _, shell, _ = start(qtbot, tmp_path)
    shell.picked = catalog_file(tmp_path)
    controller.panel.buttons['import'].click()
    settle(qtbot, controller)
    kind, text = state(controller)
    assert kind == 'partial' and 'is older than the one in use' in text


def test_cancelled_import_choice_changes_nothing(qtbot, tmp_path):
    controller, _, shell, _ = start(qtbot, tmp_path)
    shell.picked = None
    controller.panel.buttons['import'].click()
    assert state(controller)[0] == 'idle' and controller.operation == ''


# ---- consent and the one network operation -----------------------------------------------------------------------

def test_update_shows_the_exact_request_and_sends_nothing_before_download(qtbot, tmp_path):
    controller, _, _, calls = start(qtbot, tmp_path)
    controller.panel.buttons['update'].click()
    assert controller.panel.consent.isVisibleTo(controller.panel)
    assert f'GET {MIRROR.url}' in controller.panel.consent_text.full_text()
    controller.panel.buttons['cancel_consent'].click()
    assert not controller.panel.consent.isVisibleTo(controller.panel) and calls == []


def test_changing_the_source_changes_the_request_the_consent_covers(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    controller.panel.buttons['update'].click()
    controller.panel.sources['cisa-site'].setChecked(True)
    assert plan_for('cisa-site').url in controller.panel.consent_text.full_text()
    assert controller.plan.source == 'cisa-site'


def test_download_sends_only_the_consented_url_then_loads_the_new_catalog(qtbot, tmp_path):
    body = render(document([entry(1), entry(2)], dateReleased='2099-03-02T00:00:00Z', catalogVersion='2099.03.02'))
    controller, _, _, calls = start(qtbot, tmp_path, install=False, routes={MIRROR.url: body})
    controller.panel.buttons['update'].click()
    assert calls == []
    controller.panel.buttons['download'].click()
    settle(qtbot, controller)
    assert calls == [MIRROR.url] and 'CVE-2098-00001' not in ''.join(calls)
    assert controller.panel.status.full_text().startswith('KEV catalog 2099.03.02')


def test_cancelling_a_download_says_so_and_installs_nothing(qtbot, tmp_path):
    gate = threading.Event()
    body = render(document([entry(1), entry(2)], dateReleased='2099-03-02T00:00:00Z', catalogVersion='2099.03.02'))
    controller, _, _, calls = start(qtbot, tmp_path, install=False, routes={MIRROR.url: gate, 'body': body})
    controller.panel.buttons['update'].click()
    controller.panel.buttons['download'].click()
    qtbot.waitUntil(lambda: bool(calls), timeout=5000)
    assert state(controller)[0] == 'loading' or state(controller)[0] == 'refreshing'
    assert controller.panel.progress_row.isVisibleTo(controller.panel)
    controller.panel.cancel_op.click()
    gate.set()
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    assert state(controller) == ('cancelled', 'Cancelled. Earlier results are unchanged.')
    assert controller.service().store.load_current() is None


def test_a_failed_download_reopens_consent_on_retry(qtbot, tmp_path):
    controller, _, _, calls = start(qtbot, tmp_path, install=False, routes={})
    controller.panel.buttons['update'].click()
    controller.panel.buttons['download'].click()
    settle(qtbot, controller)
    assert state(controller)[0] == 'error' and 'the connection failed or timed out' in state(controller)[1]
    controller.panel.state.action_button('retry').click()
    assert controller.panel.consent.isVisibleTo(controller.panel)
    assert len(calls) <= 3                       # the plan's bounded retries, no extra request from the click


# ---- selection, copy, go to ---------------------------------------------------------------------------------------

def select(qtbot, controller, cve):
    table = controller.panel.table
    row = next(i for i, r in enumerate(rows(controller)) if r[0] == cve)
    table.selectRow(row)
    QApplication.processEvents()


def test_selecting_a_row_fills_the_detail_with_exact_wording_and_provenance(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, f'{LISTED} {ABSENT}')
    select(qtbot, controller, LISTED)
    detail = controller.panel.detail.toPlainText()
    assert 'What this means' in detail and 'SHA-256' in detail
    select(qtbot, controller, ABSENT)
    assert 'not evidence that the CVE is unexploited' in controller.panel.detail.toPlainText()


def test_copy_puts_the_lookup_with_its_caveat_on_the_clipboard(qtbot, tmp_path):
    controller, _, shell, _ = start(qtbot, tmp_path)
    look(qtbot, controller, ABSENT)
    select(qtbot, controller, ABSENT)
    controller.panel.buttons['copy'].click()
    assert 'does not locate the fix in code' in shell.copied[-1] and ABSENT in shell.copied[-1]
    controller.panel.buttons['copy_url'].click()
    assert shell.copied[-1].startswith('https://www.cisa.gov/')


def test_go_to_navigates_a_cve_anchor_pinned_to_the_project_key(qtbot, tmp_path):
    controller, nav, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, LISTED)
    select(qtbot, controller, LISTED)
    controller.panel.buttons['goto'].click()
    anchor = nav.anchors[-1]
    assert (anchor.kind, anchor.key, anchor.run_id, anchor.revision) == ('cve', LISTED, 'run-1', 1)


@pytest.mark.parametrize('status', ['stale', 'not-found', 'ambiguous', 'blocked'], ids=['stale', 'missing', 'many', 'blocked'])
def test_go_to_failures_say_why_and_navigate_nowhere_else(qtbot, tmp_path, status):
    controller, nav, *_ = start(qtbot, tmp_path)
    nav.navigate = lambda anchor: NavResult(status)
    look(qtbot, controller, LISTED)
    select(qtbot, controller, LISTED)
    controller.panel.buttons['goto'].click()
    assert controller.panel.nav_note.full_text() == NAV_FAILURE[status]


def test_an_invalid_id_cannot_be_opened(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, 'not-a-cve')
    select(qtbot, controller, rows(controller)[0][0])
    assert not controller.panel.buttons['goto'].isEnabled()


def test_show_cves_fills_the_lookup_from_another_view(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    controller.show_cves((LISTED, ABSENT))
    settle(qtbot, controller)
    assert [r[0] for r in rows(controller)] == [LISTED, ABSENT]


def test_pending_lookup_retains_rows_but_cannot_copy_or_navigate_old_selection(qtbot, tmp_path, monkeypatch):
    controller, nav, shell, _ = start(qtbot, tmp_path)
    look(qtbot, controller, LISTED)
    select(qtbot, controller, LISTED)
    gate, started = threading.Event(), threading.Event()
    real = pm.prepare_view

    def delayed(provider, ids, filter_mode, sort_mode, cancel):
        started.set()
        gate.wait(5)
        return real(provider, ids, filter_mode, sort_mode, cancel)

    monkeypatch.setattr(pm, 'prepare_view', delayed)
    try:
        controller.lookup(ABSENT)
        qtbot.waitUntil(started.is_set, timeout=5000)
        assert rows(controller)[0][0] == LISTED  # retained previous results, not the current query
        assert state(controller)[0] == 'refreshing'
        assert controller.panel.detail.toPlainText() == ''
        assert not controller.panel.buttons['copy'].isEnabled()
        assert not controller.panel.buttons['goto'].isEnabled()
        controller.copy()
        controller.go()
        assert shell.copied == [] and nav.anchors == []
    finally:
        gate.set()
    settle(qtbot, controller)
    assert [r[0] for r in rows(controller)] == [ABSENT]
    select(qtbot, controller, ABSENT)
    controller.copy()
    controller.go()
    assert ABSENT in shell.copied[-1] and nav.anchors[-1].key == ABSENT


def test_older_lookup_callbacks_cannot_overwrite_current_rows_or_error(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, LISTED)
    epoch, generation, previous = controller.epoch, controller._rows_generation, controller.view
    look(qtbot, controller, ABSENT)
    current = controller.view
    controller._rows_ready(epoch, generation, previous)
    controller._rows_failed(epoch, generation, TaskFailure('OldQueryError'))
    assert controller.view is current and controller.error is None
    assert [r[0] for r in rows(controller)] == [ABSENT]


def test_show_changes_needs_two_catalogs(qtbot, tmp_path):
    controller, _, shell, _ = start(qtbot, tmp_path)
    assert not controller.panel.buttons['changes'].isEnabled()
    shell.picked = catalog_file(tmp_path, 'older.json')
    controller.panel.buttons['import'].click()
    settle(qtbot, controller)
    assert controller.panel.buttons['changes'].isEnabled()
    controller.panel.buttons['changes'].click()
    qtbot.waitUntil(lambda: controller.panel.changes.isVisibleTo(controller.panel), timeout=5000)
    assert 'since catalog' in controller.panel.changes.toPlainText()


# ---- hostile text, names, windows ---------------------------------------------------------------------------------

HOSTILE = 'Evil‮\x1b[31m<b>bold</b>\nFAKE LINE\x00' + 'x' * 600


def test_hostile_catalog_and_input_text_is_bounded_and_plain(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, install=False)
    path = catalog_file(tmp_path, vendorProject=HOSTILE, vulnerabilityName=HOSTILE, shortDescription=HOSTILE,
                        requiredAction=HOSTILE, notes=HOSTILE)
    controller.service().import_file(path)
    controller.reload()
    settle(qtbot, controller)
    look(qtbot, controller, f'CVE-2098-00001 {HOSTILE}')
    select(qtbot, controller, 'CVE-2098-00001')
    detail = controller.panel.detail.toPlainText()
    assert '‮' not in detail and '\x1b' not in detail and '\x00' not in detail and len(detail) <= 8_000
    for row in rows(controller):
        assert all(len(cell) <= 200 and '‮' not in cell and '\n' not in cell for cell in row)
    for label in (controller.panel.status, controller.panel.state.status_label()):
        assert '\n' not in label.full_text() and len(label.full_text()) <= 700


def test_hostile_id_is_echoed_cleaned_and_short(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, 'CVE-1‮' + 'A' * 500)
    first = rows(controller)[0]
    assert len(first[0]) <= 64 and '‮' not in first[0] and first[1] == 'Invalid CVE ID'


def test_more_than_the_limit_of_ids_is_cut_with_a_notice(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, ' '.join(f'CVE-2099-{n:05d}' for n in range(pm.MAX_INPUT_IDS + 3)))
    assert len(controller.ids) == pm.MAX_INPUT_IDS
    assert controller.panel.notices.current.key == 'kev.truncated'


@pytest.mark.parametrize('case', ['empty', 'ready', 'stale', 'error'], ids=['empty', 'ready', 'stale', 'error'])
def test_every_state_is_accessible(qtbot, tmp_path, case):
    controller, _, shell, _ = start(qtbot, tmp_path, install=case != 'empty',
                                    now=NOW + timedelta(days=30) if case == 'stale' else NOW)
    if case == 'ready':
        look(qtbot, controller, f'{LISTED} {ABSENT}')
    if case == 'error':
        shell.picked = tmp_path / 'missing.json'
        controller.panel.buttons['import'].click()
        settle(qtbot, controller)
    controller.panel.buttons['update'].click()                 # the consent box is part of the audited tree
    assert audit(controller.panel) == []


def test_the_panel_opens_no_window(qtbot, tmp_path):
    before = top_level_windows()
    controller, *_ = start(qtbot, tmp_path)
    controller.panel.buttons['update'].click()
    look(qtbot, controller, LISTED)
    assert [w for w in top_level_windows() if w not in before and w is not controller.panel] == []


def test_the_controls_carry_tooltips_with_what_why_effect(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    for widget in (controller.panel.buttons['update'], controller.panel.table, controller.panel.detail,
                   controller.panel.lookup_box, controller.panel.filter):
        tip = widget.toolTip()
        assert 'What' in tip and 'Why' in tip and 'Effect' in tip, widget.objectName()


# ---- threads ------------------------------------------------------------------------------------------------------

def test_a_late_result_after_a_project_switch_is_dropped(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    look(qtbot, controller, LISTED)
    old_epoch, view = controller.epoch, controller.view
    controller.project_changed(FakeProject(run_id='run-2').key())
    settle(qtbot, controller)
    controller._rows_ready(old_epoch, controller._rows_generation, pm.KevView(view.prepared, 99, 99))
    controller._loaded(old_epoch, controller.snapshot)
    controller._installed(old_epoch, KevError('PT-KEV-STORAGE', 'x'))
    assert controller.view.total == 1 and controller.error is None


def test_a_slow_lookup_of_the_old_project_never_publishes(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    gate, seen = threading.Event(), []
    real = pm.prepare_view

    def slow(provider, ids, filter_mode, sort_mode, cancel):
        seen.append(ids)
        gate.wait(5)
        return real(provider, ids, filter_mode, sort_mode, cancel)
    original, pm.prepare_view = pm.prepare_view, slow
    try:
        controller.panel.lookup_requested.emit(ABSENT)
        qtbot.waitUntil(lambda: bool(seen), timeout=5000)
        controller.project_changed(FakeProject(run_id='run-2').key())
    finally:
        gate.set()
        pm.prepare_view = original
    settle(qtbot, controller)
    assert [r[0] for r in rows(controller)] == [ABSENT]        # only the request made after the switch is shown
    assert controller.view.total == 1


def test_shutdown_cancels_work_and_is_idempotent(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path)
    gate, started = threading.Event(), threading.Event()
    real = pm.prepare_view

    def slow(provider, ids, filter_mode, sort_mode, cancel):
        started.set()
        gate.wait(5)
        return real(provider, ids, filter_mode, sort_mode, cancel)
    original, pm.prepare_view = pm.prepare_view, slow
    try:
        controller.panel.lookup_requested.emit(ABSENT)
        qtbot.waitUntil(started.is_set, timeout=5000)
        controller.shutdown()
        controller.shutdown()
    finally:
        gate.set()
        pm.prepare_view = original
    qtbot.waitUntil(lambda: not controller.tasks.busy(), timeout=5000)
    assert rows(controller) == []
    controller.panel.lookup_requested.emit(LISTED)             # a closed panel starts no new work
    assert not controller.tasks.busy()


def test_the_factory_reads_no_disk_until_the_first_show(qtbot, tmp_path):
    controller, *_ = start(qtbot, tmp_path, show=False)
    controller.shutdown()
    fresh, *_ = start(qtbot, tmp_path / 'other', install=False, show=False)
    assert fresh.snapshot is None and not fresh.loaded_once
