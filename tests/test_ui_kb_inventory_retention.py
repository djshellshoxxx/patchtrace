"""Explicit retained-page controls use immutable worker requests, not table paging."""
from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import FixedClock
from PySide6.QtCore import Qt
from qt_support import join_gui_threads  # noqa: F401
from test_ui_kb_inventory import imported, make, reply, settle

from patchtrace.gui.qt.tasks import TaskRunner
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.inventory_contracts import InventoryContext, InventoryLimits
from patchtrace.kbcorrelation.inventory_qt import InventoryRequest, execute_inventory
from patchtrace.kbcorrelation.inventory_store import add_inventory
from patchtrace.kbcorrelation.service import Outcome
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')


def test_retain_controls_require_active_saved_source_and_do_not_select_a_filename(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path, investigation='existing', product='scope', expected_revision=7)
    assert not dialog.buttons['retain'].isEnabled()
    imported(qtbot, tmp_path, dialog)
    source = dialog.imports.currentData()
    assert dialog.combos['retain_architecture'].currentData() == 'amd64'
    assert dialog.source_page.value() == 1 and dialog.buttons['retain'].isEnabled()
    dialog.buttons['retain'].setFocus()
    qtbot.keyClick(dialog.buttons['retain'], Qt.Key.Key_Space)
    settle(qtbot, dialog)
    assert 'Source scan: complete' in dialog.status.full_text()
    assert dialog.imports.currentData() != source
    assert dialog.rows.rowCount() == 0 and not dialog.buttons['select'].isEnabled()
    assert dialog.revision.value() == 7 and dialog.fields['investigation'].text() == 'existing'
    dialog.buttons['inspect'].click()
    settle(qtbot, dialog)
    assert dialog.rows.rowCount() == 1 and dialog.rows.item(0, 0).text() == 'exampledrv.sys'
    assert dialog._selected_entry() is None
    assert 'scan_complete' in dialog.details.toPlainText()
    for control in (dialog.combos['retain_architecture'], dialog.source_page, dialog.buttons['retain'],
                    dialog.source_page.lineEdit()):
        assert control.accessibleName() and control.toolTip()
        assert control.focusPolicy() != Qt.FocusPolicy.NoFocus
    dialog.reject()


def test_worker_retention_uses_only_captured_source_policy_and_cancellation(tmp_path):
    calls = []
    token = SimpleNamespace(raise_if_cancelled=lambda: None)

    class Service:
        def retain_inventory(self, import_id, **kwargs):
            calls.append((import_id, kwargs, threading.get_ident()))
            return Outcome(0, 'complete', {'contract': 'kbcorrelation/1', 'import_id': 'b' * 64,
                                           'inventory': {'retention': {'architecture': 'amd64', 'page': 2},
                                                         'scan_complete': True}}, 'Retained')

    request = InventoryRequest('retain', tmp_path, json.dumps({'import_id': 'a' * 64,
                                                              'architecture': 'amd64', 'page': 2}))
    response = execute_inventory(request, token, service_factory=lambda path: Service())
    assert response.code is None and response.outcome.exit == 0
    assert calls[0][:2] == ('a' * 64, {'architecture': 'amd64', 'page': 2, 'cancel': token})
    assert 'retention' in response.display_text and 'scan_complete' in response.display_text


@pytest.mark.parametrize('edit', ['architecture', 'page'])
def test_retention_input_edit_cancels_worker_and_ignores_late_retained_source(qtbot, tmp_path, edit):
    gate, started, done = threading.Event(), threading.Event(), threading.Event()
    requests, tokens = [], []

    def execute(request, token):
        requests.append(request)
        tokens.append(token)
        started.set()
        gate.wait(5)
        done.set()
        return reply({'import_id': 'b' * 64,
                      'inventory': {'import_id': 'b' * 64, 'context': {'kb': 'KB5099001'}}})

    runner = TaskRunner(reraise=True)
    dialog = make(qtbot, tmp_path, tasks=runner, execute=execute)
    dialog.imports.addItem('Chosen saved source', 'a' * 64)
    dialog.imports.setCurrentIndex(1)
    dialog.buttons['retain'].click()
    qtbot.waitUntil(started.is_set)
    payload = json.loads(requests[0].payload)
    assert requests[0].operation == 'retain'
    assert payload == {'import_id': 'a' * 64, 'architecture': 'amd64', 'page': 1}
    if edit == 'page':
        dialog.source_page.setValue(2)
    else:
        dialog.combos['retain_architecture'].setCurrentIndex(
            dialog.combos['retain_architecture'].findData('arm64'))
    assert tokens[0].is_set()
    gate.set()
    qtbot.waitUntil(done.is_set)
    qtbot.wait(20)
    assert dialog.imports.currentData() == 'a' * 64 and dialog.imports.findData('b' * 64) == -1
    assert json.loads(requests[0].payload) == payload
    dialog.reject()
    runner.shutdown()


def test_incomplete_source_scan_stays_inspectable_but_cannot_enable_filename_selection(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path, investigation='existing', product='scope', expected_revision=7)
    imported(qtbot, tmp_path, dialog)
    dialog._shown['inventory']['scan_complete'] = False
    dialog.rows.selectRow(0)
    assert dialog._selected_entry() is not None
    assert not dialog.buttons['select'].isEnabled()
    dialog.reject()


def test_failed_retention_keeps_the_inspected_source_rows_and_details(qtbot, tmp_path):
    dialog = make(qtbot, tmp_path)
    imported(qtbot, tmp_path, dialog)
    previous, source, details = dialog._shown, dialog.imports.currentData(), dialog.details.toPlainText()
    dialog.source_page.setValue(2)  # the small source has no second retained page
    dialog.buttons['retain'].click()
    settle(qtbot, dialog)
    assert 'PT-KBC-INPUT' in dialog.status.full_text()
    assert dialog.imports.currentData() == source and dialog._shown is previous
    assert dialog.rows.rowCount() == 2 and dialog.details.toPlainText() == details
    dialog.reject()


@pytest.mark.parametrize('date_length', [10, 65536])
def test_selected_row_keeps_its_exact_witness_before_long_fields_and_full_diagnostics(qtbot, tmp_path, date_length):
    header = b'File name,File version,File size,Architecture,Date\n'
    rejected = b'../unsafe.sys,1.2.3.4,128,x64,2026-01-01\n' * 1000
    date = 'x' * date_length
    claims = (f'first.sys,1.2.3.4,128,x64,{date}\n'
              'second.sys,1.2.3.4,128,x64,2026-01-01\n'
              'healthy.sys,1.2.3.4,128,x64,2026-01-01\n'
              f'first.sys,1.2.3.4,256,x64,{date}\n'
              'second.sys,1.2.3.4,512,x64,2026-01-01\n').encode()
    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock())
    with WorkspaceStore(service.root) as ws:
        original, _ = add_inventory(ws, header + rejected + claims, InventoryContext(kb='KB5099001'),
                                    now=service._now(), limits=InventoryLimits(max_entries=3))
    retained = service.retain_inventory(original.import_id).result['import_id']
    dialog = make(qtbot, tmp_path)
    dialog.tabs.setCurrentIndex(1)
    dialog.imports.addItem('Chosen retained page', retained)
    dialog.imports.setCurrentIndex(1)
    dialog.buttons['inspect'].click()
    settle(qtbot, dialog)
    assert dialog.rows.rowCount() == 3
    inventory = dialog._shown['inventory']
    assert len(inventory['diagnostics']) == 1000 and inventory['diagnostics_omitted'] > 0
    witnesses = {item['conflict_group']: item for item in inventory['conflict_witnesses']}
    assert len(witnesses) == 2
    assert '[Display truncated;' in dialog.details.toPlainText()
    assert '"conflict_witnesses"' not in dialog.details.toPlainText()
    for row in (0, 1):
        dialog.rows.selectRow(row)
        entry = dialog._shown['entries'][row]
        expected = witnesses[entry['conflict_group']]
        detail = dialog.details.toPlainText()
        assert len(detail) <= 65536
        assert 'Conflict witness:\n' in detail
        witness_text = detail.split('Conflict witness:\n', 1)[1].split('\n\nEntry:\n', 1)[0]
        assert json.loads(witness_text) == expected
        assert detail.index('Conflict witness:\n') < detail.index('"original_fields"')
        assert expected['first']['logical_record'] == 1002 + row
        assert expected['second']['logical_record'] == 1005 + row
        assert all(group not in detail for group in witnesses if group != entry['conflict_group'])
        if date_length == 65536 and row == 0:
            assert '[Display truncated;' in detail
    dialog.rows.selectRow(2)
    healthy = dialog.details.toPlainText()
    assert 'healthy.sys' in healthy and 'Conflict witness:\n' not in healthy
    assert all(group not in healthy for group in witnesses)
    dialog.reject()
