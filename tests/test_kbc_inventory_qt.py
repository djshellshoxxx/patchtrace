"""PW-01 desktop journeys and ownership guards. Offline authored data, no native/live claim."""
from __future__ import annotations

import json
import threading
from functools import partial

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401
from kbc_k3_support import FixedClock
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractButton, QComboBox, QLineEdit, QPlainTextEdit, QSpinBox
from qt_support import join_gui_threads  # noqa: F401
from test_ui_kb_panel import build as panel_build
from test_ui_kb_panel import fixed
from test_ui_kb_panel import report as leads_report

from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.inventory_qt import (
    InventoryDialog,
    InventoryReply,
    execute_inventory,
)
from patchtrace.kbcorrelation.service import Outcome
from patchtrace.kbcorrelation.sources.inventory_fetch import build_plan, render_plan
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
CSV = (b'File name,File version,File size,Architecture\n'
       b'exampledrv.sys,10.0.1.2,1234,x64\n'
       b'armdriver.sys,10.0.1.2,4567,arm64\n')
URL = 'https://download.microsoft.com/download/authored/inventory.csv'
GO = 'https://go.microsoft.com/fwlink/?linkid=123456'
PAGE = 'https://support.microsoft.com/help/5099001'


def settle(qtbot, dialog):
    qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)


def make(qtbot, tmp_path, **kwargs):
    kwargs.setdefault('execute', partial(execute_inventory,
                                        service_factory=lambda path: wiring.build_service(path, clock=FixedClock())))
    dialog = InventoryDialog(workspace=tmp_path / 'ws', **kwargs)
    qtbot.addWidget(dialog)
    dialog.show()
    return dialog


def reply(data, text='Done', *, code=0, status='complete'):
    return InventoryReply(outcome=Outcome(code, status, {'contract': 'kbcorrelation/1', **data}, text),
                          display_text=text + '\n' + json.dumps(data))


def plan_reply(url=URL, redirects=()):
    plan = build_plan(url, redirects=redirects)
    return reply({'plan': plan.as_dict(), 'preview': render_plan(plan)})


def imported(qtbot, tmp_path, dialog):
    path = tmp_path / 'inventory.csv'
    path.write_bytes(CSV)
    dialog.fields['csv'].setText(str(path))
    dialog.fields['kb'].setText('KB5099001')
    dialog.buttons['import'].click()
    settle(qtbot, dialog)
    assert 'retained 2 rows' in dialog.status.full_text()
    dialog.tabs.setCurrentIndex(1)
    dialog.buttons['refresh'].click()
    settle(qtbot, dialog)
    assert dialog.imports.count() == 2
    assert dialog.imports.currentData() is None
    dialog.imports.setCurrentIndex(1)
    dialog.buttons['inspect'].click()
    settle(qtbot, dialog)
    assert dialog.rows.rowCount() == 2


def test_real_offline_import_inspect_filter_and_scoped_selection(qtbot, tmp_path):
    workspace = tmp_path / 'ws'
    with WorkspaceStore(workspace) as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    service = wiring.build_service(workspace, clock=FixedClock())
    search = service.search('KB5099001')
    investigation = search.result['investigation_id']
    scope = next(s['scope_id'] for s in search.result['scopes'] if s['architecture'] == 'amd64')
    with WorkspaceStore(workspace) as ws:
        revision = ws.current_revision(investigation).revision
    dialog = make(qtbot, tmp_path, investigation=investigation, product=scope, expected_revision=revision)
    imported(qtbot, tmp_path, dialog)
    assert dialog._selected_entry() is None and not dialog.buttons['select'].isEnabled()
    assert 'unverified-local-file' in dialog.details.toPlainText()
    dialog.rows.selectRow(1)
    assert not dialog.buttons['select'].isEnabled()  # ARM64 remains visible, not analysis-eligible.
    dialog.combos['filter_architecture'].setCurrentIndex(1)
    dialog.buttons['filter'].click()
    settle(qtbot, dialog)
    assert dialog.rows.rowCount() == 1 and dialog.rows.item(0, 0).text() == 'exampledrv.sys'
    dialog.rows.selectRow(0)
    assert 'logical_record' in dialog.details.toPlainText()
    dialog.assert_scope.setChecked(True)
    assert dialog.buttons['select'].isEnabled()
    dialog.buttons['select'].click()
    settle(qtbot, dialog)
    with WorkspaceStore(workspace) as ws:
        decisions = ws.decisions(investigation)
        updated = ws.current_revision(investigation)
    assert updated.revision == revision + 1 and updated.state == 'COMPONENTS_READY'
    assert [d.op for d in decisions] == ['inventory-select']
    assert dialog.revision.value() == updated.revision
    hints = service.components(investigation, product=None, files=()).result['hints']
    assert hints[0]['tier'] == 'E' and len(hints[0]['inventory_refs']) == 1
    assert 'file-list metadata does not establish binary identity or a CVE fix' in hints[0]['reasons']
    dialog.reject()


def test_empty_list_does_not_create_a_workspace(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path)
    dialog.buttons['refresh'].click()
    settle(qtbot, dialog)
    assert '0 saved inventories' in dialog.status.full_text()
    assert not (tmp_path / 'ws').exists()
    assert dialog.imports.currentData() is None and not dialog.buttons['inspect'].isEnabled()
    dialog.reject()


def test_service_and_workspace_operations_are_owned_by_worker_threads(qtbot, tmp_path, monkeypatch):
    factory_threads, opened, closed = [], [], []
    original_init, original_close = WorkspaceStore.__init__, WorkspaceStore.close

    def init(self, *args, **kwargs):
        opened.append(threading.get_ident())
        original_init(self, *args, **kwargs)

    def close(self):
        closed.append(threading.get_ident())
        original_close(self)

    def factory(path):
        factory_threads.append(threading.get_ident())
        return wiring.build_service(path, clock=FixedClock())

    monkeypatch.setattr(WorkspaceStore, '__init__', init)
    monkeypatch.setattr(WorkspaceStore, 'close', close)
    dialog = make(qtbot, tmp_path, execute=partial(execute_inventory, service_factory=factory))
    imported(qtbot, tmp_path, dialog)
    assert len(factory_threads) == 3 and all(t != threading.get_ident() for t in factory_threads)
    assert opened == closed and opened and all(t != threading.get_ident() for t in opened)
    dialog.reject()


def test_invalid_import_preserves_displayed_rows_and_source(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path)
    imported(qtbot, tmp_path, dialog)
    previous = dialog._shown
    details = dialog.details.toPlainText()
    bad = tmp_path / 'bad.csv'
    bad.write_bytes(b'File name,File version\n"unterminated')
    dialog.fields['csv'].setText(str(bad))
    dialog.buttons['import'].click()
    settle(qtbot, dialog)
    assert dialog._shown is previous and dialog.rows.rowCount() == 2
    assert dialog.details.toPlainText() == details
    assert 'PT-KBC-SOURCE' in dialog.status.full_text()
    dialog.reject()


def test_stale_revision_is_reported_without_changing_existing_selection(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path)
    imported(qtbot, tmp_path, dialog)
    with WorkspaceStore(tmp_path / 'ws') as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    search = service.search('KB5099001')
    inv = search.result['investigation_id']
    scope = next(s['scope_id'] for s in search.result['scopes'] if s['architecture'] == 'amd64')
    dialog.fields['investigation'].setText(inv)
    dialog.fields['target_product'].setText(scope)
    dialog.revision.setValue(1)
    dialog.assert_scope.setChecked(True)
    dialog.rows.selectRow(0)
    dialog.buttons['select'].click()
    settle(qtbot, dialog)
    assert 'PT-KBC-STALE' in dialog.status.full_text()
    assert dialog.rows.rowCount() == 2
    with WorkspaceStore(tmp_path / 'ws') as ws:
        assert not ws.decisions(inv)
    dialog.reject()


@pytest.mark.parametrize('change', ['workspace', 'url', 'kb', 'product', 'redirects', 'kind', 'delimiter'])
def test_every_request_or_context_edit_invalidates_exact_consent(qtbot, tmp_path, change):
    requests = []

    def execute(request, _token):
        requests.append(request)
        return plan_reply()

    dialog = make(qtbot, tmp_path, execute=execute)
    dialog.tabs.setCurrentIndex(2)
    dialog.fields['url'].setText(URL)
    dialog.buttons['plan'].click()
    settle(qtbot, dialog)
    assert not dialog.consent.isChecked() and not dialog.buttons['fetch'].isEnabled()
    dialog.consent.setChecked(True)
    assert dialog.buttons['fetch'].isEnabled()
    if change == 'redirects':
        dialog.redirects.setPlainText(URL + '?changed=1')
    elif change in ('kind', 'delimiter'):
        dialog.combos[change].setCurrentIndex(1)
    else:
        dialog.fields[change].setText('changed')
    assert dialog._plan is None and not dialog.consent.isChecked()
    assert not dialog.buttons['fetch'].isEnabled()
    dialog.buttons['fetch'].click()
    assert [request.operation for request in requests] == ['plan']
    dialog.reject()


def test_real_plan_does_not_fetch_and_consented_fetch_uses_the_displayed_snapshot(qtbot, tmp_path):
    calls = []

    class Service:
        def inventory_plan(self, url, **kwargs):
            plan = build_plan(url, **kwargs)
            calls.append(('plan', plan))
            return Outcome(0, 'complete', {'plan': plan.as_dict(), 'preview': render_plan(plan)}, 'Preview only')

        def fetch_inventory(self, plan, **kwargs):
            calls.append(('fetch', plan, kwargs))
            return Outcome(0, 'complete', {'import_id': 'retained'}, 'Fetched synthetic response')

    dialog = make(qtbot, tmp_path, execute=partial(execute_inventory, service_factory=lambda _: Service()))
    dialog.fields['url'].setText(URL)
    dialog.fields['kb'].setText('5099001')
    dialog.buttons['plan'].click()
    settle(qtbot, dialog)
    displayed = dialog._plan
    assert len(calls) == 1
    dialog.consent.setChecked(True)
    dialog.buttons['fetch'].click()
    settle(qtbot, dialog)
    assert calls[1][0] == 'fetch' and calls[1][1].as_dict() == displayed
    assert calls[1][2]['consent_hosts'] == tuple(displayed['hosts'])
    assert calls[1][2]['consent_plan'] == displayed['plan_sha']
    assert calls[1][2]['context'].kb == 'KB5099001'
    assert not dialog.consent.isChecked() and dialog._plan is None
    assert not dialog.buttons['fetch'].isEnabled()  # consent is consumed once.
    dialog.reject()


def test_redirect_drift_only_offers_new_preview_and_requires_new_consent(qtbot, tmp_path):
    requests = []
    proposed = build_plan(GO, redirects=(URL,))

    def execute(request, _token):
        requests.append(request)
        data = json.loads(request.payload)
        if request.operation == 'fetch':
            return reply({'proposed_plan': proposed.as_dict(), 'preview': render_plan(proposed)},
                         'Request changed; new consent is required.', code=2, status='failed')
        return plan_reply(data['url'], tuple(data['redirects']))

    dialog = make(qtbot, tmp_path, execute=execute)
    dialog.fields['url'].setText(GO)
    dialog.buttons['plan'].click()
    settle(qtbot, dialog)
    dialog.consent.setChecked(True)
    dialog.buttons['fetch'].click()
    settle(qtbot, dialog)
    assert dialog._plan is None and dialog._proposed_plan == proposed.as_dict()
    assert not dialog.buttons['fetch'].isEnabled() and dialog.buttons['revised'].isEnabled()
    dialog.buttons['revised'].click()
    settle(qtbot, dialog)
    assert [r.operation for r in requests] == ['plan', 'fetch', 'plan']
    assert dialog._plan == proposed.as_dict()
    assert not dialog.consent.isChecked() and not dialog.buttons['fetch'].isEnabled()
    dialog.reject()


def test_saved_html_keeps_ssu_rejection_and_never_chooses_first_link(qtbot, tmp_path):
    html = tmp_path / 'support.html'
    html.write_text(f'<p><a href="{GO}">File information for cumulative update</a></p>'
                    f'<p>Servicing stack update <a href="{URL}">File information</a></p>')
    dialog = make(qtbot, tmp_path)
    dialog.fields['html'].setText(str(html))
    dialog.fields['page_url'].setText(PAGE)
    dialog.buttons['links'].click()
    settle(qtbot, dialog)
    assert dialog.candidates.count() == 3 and dialog.candidates.currentData() is None
    assert 'unverified-local-file' in dialog.details.toPlainText()
    assert not dialog.buttons['use_link'].isEnabled() and not dialog.fields['url'].text()
    dialog.candidates.setCurrentIndex(2)
    assert not dialog.buttons['use_link'].isEnabled()
    assert 'servicing-stack' in dialog.details.toPlainText()
    dialog.candidates.setCurrentIndex(1)
    dialog.buttons['use_link'].click()
    assert dialog.fields['url'].text() == GO and dialog._plan is None
    dialog.reject()


@pytest.mark.parametrize('ending', ['cancel', 'edit', 'close', 'project'])
def test_late_results_are_dropped_after_cancel_edit_close_or_project_change(qtbot, tmp_path, ending):
    gate, started, done = threading.Event(), threading.Event(), threading.Event()
    tokens = []

    def execute(request, token):
        tokens.append(token)
        started.set()
        gate.wait(5)
        done.set()
        return reply({'inventories': [{'import_id': 'late', 'context': {}, 'source': {}}], 'total': 1})

    runner = TaskRunner(reraise=True)
    dialog = make(qtbot, tmp_path, tasks=runner, execute=execute)
    dialog.buttons['refresh'].click()
    qtbot.waitUntil(started.is_set)
    if ending == 'cancel':
        dialog.cancel_operation()
    elif ending == 'edit':
        dialog.fields['workspace'].setText(str(tmp_path / 'other'))
    elif ending == 'project':
        dialog.clear_selection_target()
    else:
        dialog.reject()
    assert tokens[0].is_set()
    gate.set()
    qtbot.waitUntil(done.is_set)
    qtbot.wait(20)
    assert dialog.imports.count() == 1 and dialog.imports.currentData() is None
    if ending != 'close':
        dialog.reject()
    runner.shutdown()


def test_hostile_results_remain_plain_text_and_failure_keeps_prior_details(qtbot, tmp_path):
    calls = []

    def execute(request, _token):
        calls.append(request)
        if len(calls) > 1:
            raise RuntimeError('do not display private /path/token')
        return reply({'inventories': [], 'total': 0}, '<b>literal</b> & data \u202e')

    dialog = make(qtbot, tmp_path, execute=execute)
    dialog.buttons['refresh'].click()
    settle(qtbot, dialog)
    assert dialog.status.textFormat() == Qt.TextFormat.PlainText
    assert '<b>literal</b>' in dialog.details.toPlainText() and '\u202e' not in dialog.details.toPlainText()
    prior = dialog.details.toPlainText()
    dialog.buttons['refresh'].click()
    settle(qtbot, dialog)
    assert dialog.details.toPlainText() == prior
    assert 'RuntimeError' in dialog.status.full_text() and '/path/token' not in dialog.status.full_text()
    dialog.reject()


def test_empty_workspace_and_oversized_redirect_preview_are_refused_before_worker(qtbot, tmp_path):
    requests = []
    dialog = make(qtbot, tmp_path, execute=lambda request, token: requests.append(request))
    dialog.fields['workspace'].clear()
    dialog.buttons['refresh'].click()
    assert not requests and 'Choose a local advisory workspace' in dialog.status.full_text()
    dialog.fields['workspace'].setText(str(tmp_path / 'ws'))
    dialog.redirects.setPlainText('\n'.join([URL] * 5))
    dialog.buttons['plan'].click()
    assert not requests and 'at most four' in dialog.status.full_text()
    assert len(dialog.redirects.toPlainText().splitlines()) == 5  # no silent first-URL truncation.
    dialog.redirects.setPlainText('x' * 16385)
    dialog.buttons['plan'].click()
    assert not requests
    dialog.reject()


def test_keyboard_and_accessible_controls_have_labels_and_tips(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path)
    for control in [*dialog.fields.values(), *dialog.buttons.values(), *dialog.combos.values(),
                    dialog.rows, dialog.redirects, dialog.assert_scope, dialog.consent, dialog.revision,
                    dialog.preview, dialog.details]:
        assert control.accessibleName() and control.toolTip() and control.objectName()
        assert control.focusPolicy() != Qt.FocusPolicy.NoFocus
    assert all(not button.autoDefault() for button in dialog.buttons.values())
    for field in dialog.findChildren(QLineEdit):
        assert field.accessibleName() and field.toolTip()
    dialog.tabs.setCurrentIndex(1)
    dialog.buttons['refresh'].setFocus()
    qtbot.keyClick(dialog.buttons['refresh'], Qt.Key.Key_Space)
    settle(qtbot, dialog)
    assert '0 saved inventories' in dialog.status.full_text()
    for control_type in (QAbstractButton, QComboBox, QPlainTextEdit, QSpinBox):
        assert dialog.findChildren(control_type)
    dialog.reject()


def test_panel_inventory_entry_is_visible_without_project_and_reuses_one_dialog(qtbot, tmp_path):
    controller, *_ = panel_build(qtbot, fixed(leads_report()))
    controller.workspace = tmp_path / 'ws'
    controller.project_changed(None)
    button = controller.panel.buttons['inventory']
    assert button.isEnabled() and button.isVisibleTo(controller.panel)
    assert not controller.panel.content.isVisibleTo(controller.panel)
    button.click()
    first = controller._inventory_dialog
    assert first is not None and first.isVisible()
    assert first.fields['workspace'].text() == str(tmp_path / 'ws')
    button.click()
    assert controller._inventory_dialog is first
    first.fields['investigation'].setText('old-investigation')
    controller.project_changed(None)
    assert not first.fields['investigation'].text()
    controller.shutdown()
    assert controller._inventory_dialog is None
