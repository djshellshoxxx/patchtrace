"""Existing desktop text presenter, supplied a real scoped Outcome; no new document-scope UI."""
from __future__ import annotations

import pytest
from PySide6.QtCore import Qt
from test_kbc_named_superseded import NEW_KB, OLD_KB, PREFIX, Clock, scope_file, seeded_service

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.investigation_qt import InvestigationDialog
from patchtrace.kbcorrelation.investigation_service import InvestigationResult


@pytest.mark.parametrize('selected_old', [True, False])
def test_existing_dialog_text_presenter_keeps_the_scoped_outcome_explanation(qtbot, tmp_path, selected_old):
    service, (older, newer) = seeded_service(tmp_path)
    selected = older if selected_old else newer
    path = scope_file(tmp_path, selected.doc_id)
    outcomes = []

    def execute(request, _cancel):
        # The dialog currently has no scope-file input. Exercise its existing presenter using
        # a real scoped service result created/opened entirely on this worker's thread.
        outcome = wiring.build_service(request.workspace, clock=Clock()).search(request.lead, scope_file=path)
        outcomes.append(outcome)
        return InvestigationResult('search', outcome.text, outcome.result)

    dialog = InvestigationDialog(workspace=service.root, execute=execute)
    qtbot.addWidget(dialog)
    try:
        dialog.fields['lead'].setText(OLD_KB if selected_old else NEW_KB)
        dialog.buttons['search'].click()
        qtbot.waitUntil(lambda: dialog._pending is None, timeout=10000)
        assert len(outcomes) == 1 and outcomes[0].exit == (4 if selected_old else 0)
        assert dialog.status.textFormat() == Qt.TextFormat.PlainText
        # The existing status label deliberately abbreviates; the details pane keeps the explanation.
        assert dialog.details.toPlainText().startswith(outcomes[0].text)
        if selected_old:
            assert PREFIX in dialog.details.toPlainText() and older.doc_id in dialog.details.toPlainText()
            assert 'these documents do not list it' not in dialog.details.toPlainText()
            assert outcomes[0].result['edges'] == outcomes[0].result['cards'] == []
        else:
            assert PREFIX not in dialog.details.toPlainText() and len(outcomes[0].result['edges']) == 1
    finally:
        dialog.reject()
