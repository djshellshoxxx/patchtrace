"""Offscreen desktop integration checks. No native analysis or model is simulated as real."""
from __future__ import annotations

import os
import threading
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QApplication, QDialog

from patchtrace.evidence import build_context
from patchtrace.models import AnalysisRun
from patchtrace.reports import export_project
from patchtrace.service import ProjectService
from patchtrace.ui import ContextDialog, ExportDialog, MainWindow, NewProjectDialog


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    if view.worker:
        view.cancel_job()
        qtbot.waitUntil(lambda: view.worker is None, timeout=5000)
    view.close()


def test_sample_navigation_filters_and_missing_assembly(window):
    assert window.navigator.count() == 4
    assert 'SYNTHETIC SAMPLE' in window.project_label.text()
    window.search.setText('read_item')
    assert window.navigator.count() == 1
    assert 'buffer[index]' in window.views['older'].toPlainText()
    assert 'index >= length' in window.views['newer'].toPlainText()
    assert window.hunk_list.count() > 0
    window.mode.setCurrentIndex(1)
    assert 'Assembly unavailable' in window.views['newer'].toPlainText()
    window.mode.setCurrentIndex(2)
    assert 'artifact_id' in window.views['older'].toPlainText()
    window.search.clear()
    window.category_filter.setCurrentText('added')
    assert window.navigator.count() == 1
    assert 'No older function' in window.views['older'].toPlainText()


def test_match_review_note_and_provenance_clipboard(window):
    window.search.setText('read_item')
    match_id = window.current_match().id
    window.match_review.setCurrentText('accepted')
    assert window.current_match().review == 'accepted'
    window.notes.setPlainText('Manually checked the added guard.')
    window.save_note()
    note = window.project.annotations[-1]
    assert note.target_id == match_id
    assert 'Manually checked' in window.finding_detail.toPlainText()
    window.copy_code('newer')
    copied = QApplication.clipboard().text()
    assert match_id in copied and 'SHA-256:' in copied and 'Run:' in copied


def test_finding_review_evidence_and_bookmark(window):
    window.findings_list.setCurrentRow(0)
    assert 'Preconditions:' in window.finding_detail.toPlainText()
    assert window.evidence_list.count() == 3
    window.evidence_list.setCurrentRow(1)
    ref = window._evidence[window.evidence_list.currentItem().data(Qt.ItemDataRole.UserRole)]
    assert window.views[ref.side].textCursor().selectedText().replace('\u2029', '\n') == ref.text
    window.bookmark_evidence()
    assert window.project.annotations[-1].kind == 'bookmark'
    window.finding_review.setCurrentText('needs-review')
    window.conclusion.setPlainText('Need caller validation before accepting this hypothesis.')
    window.review_finding()
    assert window._finding.review == 'needs-review'
    assert window._finding.analyst_conclusion.startswith('Need caller')


def test_stale_evidence_never_jumps_to_current_code(window, monkeypatch):
    window.service.swap_orientation()
    window.refresh()
    window.findings_list.setCurrentRow(0)
    assert 'STALE:' in window.finding_detail.toPlainText()
    captured = []
    monkeypatch.setattr('patchtrace.ui.text_dialog', lambda parent, title, text: captured.append((title, text)))
    before = window.views['newer'].textCursor().position()
    window.evidence_list.setCurrentRow(0)
    assert captured and 'Stale evidence' in captured[0][0]
    assert window.views['newer'].textCursor().position() == before


def test_interpretation_preview_cancel_sends_nothing(window, monkeypatch):
    called = []
    monkeypatch.setattr(ContextDialog, 'exec', lambda dialog: QDialog.DialogCode.Rejected)
    monkeypatch.setattr('patchtrace.ui.interpret', lambda *args: called.append(args))
    window.preview_interpretation()
    assert not called and window.worker is None


def test_context_dialog_exact_preview_and_secret_is_session_only(window):
    context = build_context(window.project, [window.current_match().id])
    dialog = ContextDialog(context, window.settings, window)
    views = dialog.findChildren(type(window.views['older']))
    assert context.payload in [view.toPlainText() for view in views]
    dialog.model.setText('test-model')
    dialog.key.setText('session-key-never-persist')
    assert dialog.config().api_key == 'session-key-never-persist'
    assert all('session-key-never-persist' not in str(window.settings.value(k)) for k in window.settings.allKeys())


def test_worker_cancellation_responsive_and_gui_commit(window, qtbot):
    main_thread = threading.get_ident()
    task_threads, complete_threads = [], []
    def task(cancel, event):
        task_threads.append(threading.get_ident())
        cancel.wait(2)
        return 'done'
    def complete(value):
        complete_threads.append(threading.get_ident())
    window.start_job('Test cooperative cancellation', task, complete)
    assert not window.run_action.isEnabled() and window.cancel_action.isEnabled()
    window.search.setText('read_item')
    assert window.navigator.count() == 1
    window.cancel_job()
    qtbot.waitUntil(lambda: window.worker is None, timeout=5000)
    assert task_threads[0] != main_thread and complete_threads == [main_thread]
    assert window.run_action.isEnabled()


def test_failed_analysis_preserves_matches_and_records_attempt(window, monkeypatch):
    ids = [match.id for match in window.project.matches]
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    run = AnalysisRun(status='failed', error='PT-BACKEND: missing dependency')
    window.complete_analysis((Path('/unused/quarantine'), run))
    assert [match.id for match in window.project.matches] == ids
    assert window.project.runs[-1].status == 'failed'
    assert errors == ['PT-BACKEND: missing dependency']


def test_export_preview_matches_written_output(window, tmp_path):
    dialog = ExportDialog(window.project, window.service.root, [], window)
    assert not dialog.code.isChecked() and dialog.notes.isChecked()
    preview = dialog.preview.toPlainText()
    assert 'SHA-256' in preview or 'sha256' in preview
    assert 'buffer[index]' not in preview
    assert 'Synthetic' in preview
    dialog.format.setCurrentText('json')
    dialog.code.setChecked(True)
    assert 'buffer[index]' in dialog.preview.toPlainText()
    output = tmp_path / 'report.json'
    export_project(window.project, dialog.format.currentText(), output, **dialog.options())
    assert output.read_text(encoding='utf-8') == dialog.preview.toPlainText()


def test_font_preference_and_imported_label_are_plain_text(window, qtbot):
    window.apply_font(17)
    QApplication.processEvents()
    assert window.views['older'].font().pointSize() == 17
    candidate = window.project.model_copy(deep=True)
    candidate.name = '<b>plain project</b>'
    window.service._commit(candidate)
    window.refresh()
    assert window.project_label.textFormat() == Qt.TextFormat.PlainText
    assert '<b>' in window.project_label.text()


def test_new_wizard_rejects_invalid_paths(qtbot):
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    dialog.accept()
    assert dialog.result() == QDialog.DialogCode.Rejected
    assert dialog.error.text()
    dialog.older.setText('older.exe')
    dialog.newer.setText('newer.exe')
    dialog.swap()
    assert dialog.older.text() == 'newer.exe' and dialog.newer.text() == 'older.exe'


def test_manual_and_findings_filters_and_finding_review_filter(window):
    window.finding_match_filter.setChecked(True)
    assert window.navigator.count() == 1
    window.manual_filter.setChecked(True)
    assert window.navigator.count() == 0
    window.manual_filter.setChecked(False)
    window.finding_match_filter.setChecked(False)
    window.finding_review_filter.setCurrentText('accepted')
    assert window.findings_list.count() == 0
    window.finding_review_filter.setCurrentIndex(0)
    window.finding_stale_filter.setCurrentText('Stale only')
    assert window.findings_list.count() == 0
    window.service.swap_orientation()
    window.refresh()
    assert window.findings_list.count() == 1
    window.finding_search.setText('does not exist')
    assert window.findings_list.count() == 0


def test_cancelled_prepared_import_never_changes_revision(window, monkeypatch, qtbot, tmp_path):
    import json

    from PySide6.QtWidgets import QFileDialog

    from patchtrace.sample import sample_diff
    path = tmp_path / 'import.json'
    path.write_text(json.dumps(sample_diff(window.project)))
    before = window.project.revision
    original = window.service.prepare_import
    prepared = threading.Event()
    def slow_prepare(path):
        value = original(path)
        prepared.set()
        window.worker.cancel.wait(2)
        return value
    monkeypatch.setattr(window.service, 'prepare_import', slow_prepare)
    monkeypatch.setattr(QFileDialog, 'getOpenFileName', lambda *args: (str(path), 'JSON'))
    window.import_diff()
    qtbot.waitUntil(prepared.is_set, timeout=3000)
    window.cancel_job()
    qtbot.waitUntil(lambda: window.worker is None, timeout=3000)
    assert window.project.revision == before
    assert 'Cancelled' in window.job_label.text()
    assert not window.service._prepared


def test_context_budget_is_used_in_preview(window, monkeypatch):
    original = build_context
    seen = []
    def capture(project, ids, max_chars, **kwargs):
        seen.append(max_chars)
        return original(project, ids, max_chars=max_chars, **kwargs)
    window.settings.setValue('provider/context_budget', 12000)
    monkeypatch.setattr('patchtrace.ui.build_context', capture)
    monkeypatch.setattr(ContextDialog, 'exec', lambda dialog: QDialog.DialogCode.Rejected)
    window.preview_interpretation()
    assert seen == [12000]


def test_multi_function_evidence_offsets_select_exact_text(window):
    from patchtrace.models import Finding, Hypothesis, InterpretationRun
    read = next(m for m in window.project.matches if m.newer and m.newer[0].name == 'read_item')
    version = next(m for m in window.project.matches if m.newer and m.newer[0].name == 'get_version')
    window.service.correct_match(read.id, [read.older[0].id, version.older[0].id],
                                 [read.newer[0].id], 'merged', 'Test exact second-function evidence offset')
    context = build_context(window.project, [read.id])
    ref = next(e for e in context.evidence if e.function_id == version.older[0].id)
    finding = Finding(context_id=context.id, match_ids=[read.id], summary='Offset regression fixture',
                      fix_purpose='Fixture', category='unknown',
                      hypothesis=Hypothesis(explanation='Fixture', supporting=[ref.id]))
    window.service.add_interpretation(InterpretationRun(context=context, provider='test fixture',
                                                       model='none', status='completed', findings=[finding]))
    window.refresh()
    window.findings_list.setCurrentRow(window.findings_list.count() - 1)
    window.evidence_list.setCurrentRow(0)
    assert window.views['older'].textCursor().selectedText().replace('\u2029', '\n') == ref.text


def test_rejected_evidence_navigation_does_not_jump(window, monkeypatch):
    window.findings_list.setCurrentRow(0)
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    def reject(*args):
        raise ValueError('Invalid exact evidence ownership')
    monkeypatch.setattr('patchtrace.ui.resolve_evidence', reject)
    before = window.views['older'].textCursor().position()
    window.evidence_list.setCurrentRow(0)
    assert errors == ['Invalid exact evidence ownership']
    assert window.views['older'].textCursor().position() == before


def test_undo_latest_manual_correction_restores_relationship(window):
    match = window.current_match()
    original_names = [f.name for f in match.older + match.newer]
    window.service.correct_match(match.id, [f.id for f in match.older], [f.id for f in match.newer],
                                 'ambiguous', 'Manual correction undo regression')
    window.refresh()
    assert window.undo_match_action.isEnabled()
    window.undo_match_correction()
    restored = next(m for m in window.project.matches if m.id == match.id)
    assert restored.category == 'modified'
    assert [f.name for f in restored.older + restored.newer] == original_names
    assert not window.undo_match_action.isEnabled()


def test_backend_normalization_error_is_quarantined_and_recorded(window, monkeypatch, qtbot):
    import hashlib

    from patchtrace.models import uid
    run_id = uid()
    raw = window.service.root / 'runs' / run_id / 'raw' / 'bad.json'
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b'{"unexpected":"fixture"}')
    run = AnalysisRun(id=run_id, status='completed', raw_path=raw.relative_to(window.service.root).as_posix(),
                      raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
    monkeypatch.setattr('patchtrace.ui.run_comparison', lambda *args: (raw, run))
    errors = []
    monkeypatch.setattr(window, 'show_error', errors.append)
    window.settings.setValue('backend/python', '/configured/test-python')
    window.settings.setValue('backend/ghidra', '/configured/test-ghidra')
    before = [m.id for m in window.project.matches]
    window.run_analysis()
    qtbot.waitUntil(lambda: window.worker is None, timeout=5000)
    terminal = window.project.runs[-1]
    assert terminal.status == 'failed'
    assert terminal.raw_path.startswith('runs/quarantine-')
    assert (window.service.root / terminal.raw_path).is_file()
    assert [m.id for m in window.project.matches] == before
    assert errors and 'PT-SCHEMA' in errors[0]


def test_symbol_server_policy_disabled_by_default_and_persisted(window, monkeypatch):
    from patchtrace.ui import SetupDialog

    dialog = SetupDialog(window.settings, window)
    assert not dialog.allow_symbol_downloads.isChecked()
    assert not dialog.config().allow_symbol_downloads

    dialog.allow_symbol_downloads.setChecked(True)
    assert dialog.config().allow_symbol_downloads
    def accept_with_symbol_lookup(self):
        self.allow_symbol_downloads.setChecked(True)
        return QDialog.DialogCode.Accepted

    monkeypatch.setattr(SetupDialog, 'exec', accept_with_symbol_lookup)
    # Save settings through the existing GUI workflow using a real dialog.
    window.setup()
    assert window.settings.value('backend/allow_symbol_downloads', False, type=bool)
    assert window.backend_config().allow_symbol_downloads


def test_setup_prefills_unique_existing_tools_without_overwriting_manual_paths(window, qtbot, tmp_path, monkeypatch):
    from patchtrace.runtime_discovery import RuntimeCandidates
    from patchtrace.ui import SetupDialog

    python = tmp_path / "backend" / "Scripts" / "python.exe"
    ghidra = tmp_path / "Ghidra Tools"
    candidates = RuntimeCandidates((python,), (ghidra,))
    monkeypatch.setattr('patchtrace.ui.discover_local_runtimes', lambda: candidates)
    dialog = SetupDialog(window.settings, window)
    qtbot.waitUntil(lambda: dialog.python.text() == str(python), timeout=5000)
    assert dialog.ghidra.text() == str(ghidra)

    window.settings.setValue('backend/python', '/manual/python.exe')
    extra = RuntimeCandidates((python, tmp_path / "other-python.exe"), (ghidra,))
    monkeypatch.setattr('patchtrace.ui.discover_local_runtimes', lambda: extra)
    second = SetupDialog(window.settings, window)
    qtbot.waitUntil(lambda: 'retaining' in second.diagnostics.toPlainText(), timeout=5000)
    assert second.python.text() == '/manual/python.exe'
    assert second.ghidra.text() == str(ghidra)


def test_setup_does_not_choose_ambiguous_runtime_automatically(window, qtbot, tmp_path, monkeypatch):
    from patchtrace.runtime_discovery import RuntimeCandidates
    from patchtrace.ui import SetupDialog

    python_a = tmp_path / 'a' / 'python.exe'
    python_b = tmp_path / 'b' / 'python.exe'
    monkeypatch.setattr('patchtrace.ui.discover_local_runtimes',
                        lambda: RuntimeCandidates((python_a, python_b), ()))
    dialog = SetupDialog(window.settings, window)
    qtbot.waitUntil(lambda: 'multiple' in dialog.diagnostics.toPlainText().lower(), timeout=5000)
    assert dialog.python.text() == ''


def test_offline_bundle_explicit_import_updates_paths_only_after_accept(window, tmp_path, monkeypatch, qtbot):
    from PySide6.QtWidgets import QFileDialog, QMessageBox

    from patchtrace.offline_bundle import build_offline_bundle
    from patchtrace.ui import SetupDialog

    local = tmp_path / 'local data'
    monkeypatch.setenv('LOCALAPPDATA', str(local))
    source = tmp_path / 'bundle payload'
    items = {
        'python/python.exe': b'fake-private-python',
        'ghidra/Ghidra/application.properties': b'application.version=12.0.4',
        'jdk/bin/java.exe': b'fake-private-java',
        'LICENSES/NOTICE.txt': b'Test fake bundle only, no actual dependencies',
    }
    for path, data in items.items():
        file = source / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(data)
    archive = tmp_path / 'backend.zip'
    runtime_id = 'test-private-runtime'
    build_offline_bundle(source, runtime_id,
                         {'python': '3.12.10', 'ghidra': '12.0.4', 'jdk': '25',
                          'ghidriff_revision': '4f5d895fcbb1eacd65efd81145922c15bb7e741d'},
                         archive)
    monkeypatch.setattr(QFileDialog, 'getOpenFileName', lambda *args: (str(archive), 'ZIP'))
    # The consent prompt is an explicit plain-text QMessageBox (untrusted bundle names); confirm it.
    monkeypatch.setattr(QMessageBox, 'exec', lambda *args, **kwargs: QMessageBox.StandardButton.Yes)
    dialog = SetupDialog(window.settings, window)
    qtbot.addWidget(dialog)
    assert not dialog.python.text()
    dialog.import_offline_bundle()
    expected = local / 'PatchTrace' / 'runtimes' / runtime_id
    qtbot.waitUntil(lambda: dialog.worker is None and (expected / 'manifest.json').is_file(),
                    timeout=10000)
    assert dialog.python.text() == str(expected / 'payload' / 'python' / 'python.exe')
    assert dialog.ghidra.text() == str(expected / 'payload' / 'ghidra')
    assert dialog.java_home.text() == str(expected / 'payload' / 'jdk')
    # No persistent selection unless the user also saves Setup.
    assert not window.settings.value('backend/java_home')


def test_setup_persists_manual_private_java_home(window, monkeypatch):
    from patchtrace.ui import SetupDialog

    def accept(self):
        self.java_home.setText('/custom/Java Home')
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(SetupDialog, 'exec', accept)
    window.setup()
    assert window.backend_config().java_home == '/custom/Java Home'


def test_new_project_dialog_rejects_directory_that_is_a_file(qtbot, tmp_path):
    from patchtrace.ui import NewProjectDialog
    binary = tmp_path / 'a.bin'
    binary.write_bytes(b'MZ')
    dialog = NewProjectDialog()
    qtbot.addWidget(dialog)
    dialog.name.setText('p')
    dialog.older.setText(str(binary))
    dialog.newer.setText(str(binary))
    dialog.root.setText(str(binary))
    dialog.accept()
    assert 'absent or empty' in dialog.error.text()


@pytest.mark.parametrize('error', ['PT-QUARANTINE: 1 of 3 findings dropped', None], ids=['partial', 'clean'])
def test_completed_interpretation_shows_its_error_note(window, error):
    from patchtrace.models import InterpretationRun
    match = window.project.matches[0]
    context = build_context(window.project, [match.id])
    window.complete_interpretation(InterpretationRun(context=context, provider='fixture', model='none',
                                                     status='completed', error=error))
    shown = window.job_label.text() + window.statusBar().currentMessage() + window.logs.toPlainText()
    assert (error in shown) if error else ('PT-' not in shown)
