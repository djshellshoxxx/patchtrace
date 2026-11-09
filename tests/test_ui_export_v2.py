"""SPEC-50 RPT2-6 GUI half: report/2 controls in the existing ExportDialog (offscreen, hermetic)."""
from __future__ import annotations

import json
import os
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import QDialog
from test_report2_adapters import publish_engine

from patchtrace.report2 import export_vm
from patchtrace.report2.adapters import collect_from_service
from patchtrace.reports import export_project
from patchtrace.service import ProjectService
from patchtrace.ui import ExportDialog, MainWindow

VOLATILE = ('generated_at', 'created', 'content_digest')


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


@pytest.fixture
def window(qtbot, tmp_path):
    service = ProjectService.sample(tmp_path / 'sample')
    settings = QSettings(str(tmp_path / 'ui.ini'), QSettings.Format.IniFormat)
    view = MainWindow(service, settings)
    qtbot.addWidget(view)
    view.show()
    yield view
    view.close()


def make(qtbot, window, **kwargs):
    dialog = ExportDialog(window.project, window.service.root, [], window, **kwargs)
    qtbot.addWidget(dialog)
    return dialog


def stable(text: str) -> dict:
    data = json.loads(text)
    return {k: v for k, v in data.items() if k not in VOLATILE}


def items(dialog) -> dict[str, tuple[str, bool, bool]]:
    lst = dialog.sections_list
    out = {}
    for i in range(lst.count()):
        item = lst.item(i)
        out[item.data(Qt.ItemDataRole.UserRole)] = (
            item.text(), bool(item.flags() & Qt.ItemFlag.ItemIsEnabled),
            item.checkState() == Qt.CheckState.Checked)
    return out


def test_v1_default_dialog_output_is_unchanged(qtbot, window, tmp_path):
    dialog = make(qtbot, window)
    assert dialog.options() == {'include_code': False, 'include_notes': True, 'finding_ids': None,
                                'enrichment': None}
    dialog.format.setCurrentText('json')
    expected = tmp_path / 'direct.json'
    export_project(window.project, 'json', expected, include_code=False, include_notes=True, finding_ids=None,
                   enrichment=None)
    assert dialog.preview.toPlainText() == expected.read_text(encoding='utf-8')
    assert 'report_version' not in json.loads(dialog.preview.toPlainText())


def test_new_rows_follow_destination_and_names_are_accessible(qtbot, window):
    dialog = make(qtbot, window)
    form = dialog.findChild(type(dialog.layout().itemAt(0).layout()))
    labels = [form.itemAt(r, form.ItemRole.LabelRole).widget().text() for r in range(form.rowCount())
              if form.itemAt(r, form.ItemRole.LabelRole)]
    assert labels[:5] == ['Format', 'Destination', '&Contract', '&Profile', '&Sections']
    for widget, key in ((dialog.contract, 'contract'), (dialog.profile, 'profile'),
                        (dialog.sections_list, 'sections')):
        assert widget.accessibleName() == export_vm.ACCESSIBLE_NAMES[key] and widget.toolTip()
    assert [dialog.contract.itemText(i) for i in range(2)] == list(export_vm.CONTRACTS)
    assert [dialog.profile.itemText(i) for i in range(2)] == list(export_vm.PROFILES)


def test_v1_lists_every_section_disabled_with_the_v1_reason(qtbot, window):
    shown = items(make(qtbot, window))
    assert set(shown) == set(export_vm.SECTION_LABELS)
    assert all(not enabled and export_vm.V1_REASON in text for text, enabled, _ in shown.values())


def test_sections_reflect_real_counts_and_reasons(qtbot, window):
    publish_engine(window.service, 'rz-diff', '1' * 64)
    sections = collect_from_service(window.service)
    dialog = make(qtbot, window, sections=sections)
    dialog.contract.setCurrentIndex(1)
    shown = items(dialog)
    count = len(sections.engine_evidence.rows)
    assert shown['engine_evidence'] == (f'Engine evidence ({count})', True, True)
    assert shown['build_facts'][1] and shown['build_facts'][0].startswith('Build facts (')
    assert shown['advisories'] == (f'Advisories: {export_vm.UNAVAILABLE["advisories"]}', False, False)
    assert shown['series'][0].endswith(export_vm.UNAVAILABLE['series'])


def test_unchecking_a_section_removes_it_from_the_preview(qtbot, window):
    publish_engine(window.service, 'rz-diff', '1' * 64)
    dialog = make(qtbot, window, sections=collect_from_service(window.service))
    dialog.format.setCurrentText('json')
    dialog.contract.setCurrentIndex(1)
    assert 'engine_evidence' in json.loads(dialog.preview.toPlainText())
    row = next(i for i in range(dialog.sections_list.count())
               if dialog.sections_list.item(i).data(Qt.ItemDataRole.UserRole) == 'engine_evidence')
    dialog.sections_list.item(row).setCheckState(Qt.CheckState.Unchecked)
    assert 'engine_evidence' not in json.loads(dialog.preview.toPlainText())
    assert items(dialog)['engine_evidence'][2] is False


def test_share_profile_switches_contract_disables_code_and_notes_and_writes_redacted_v2(qtbot, window, tmp_path):
    dialog = make(qtbot, window, sections=collect_from_service(window.service))
    dialog.format.setCurrentText('json')
    dialog.code.setChecked(True)
    dialog.profile.setCurrentIndex(1)
    assert dialog.contract.currentIndex() == 1
    assert not dialog.code.isEnabled() and not dialog.notes.isEnabled()
    assert export_vm.SHARE_HINT in dialog.hint.text() and export_vm.SHARE_NEEDS_V2 in dialog.hint.text()
    options = dialog.options()
    assert options['report_version'] == 2 and options['include_code'] is False and options['include_notes'] is False
    output = tmp_path / 'share.json'
    window.service.export_report('json', output, **options)
    data = json.loads(output.read_text(encoding='utf-8'))
    assert data['report_version'] == 2 and data['redaction']['profile'] == 'share'
    assert data['annotations'] == [] and 'buffer[index]' not in output.read_text(encoding='utf-8')
    assert stable(dialog.preview.toPlainText()) == stable(output.read_text(encoding='utf-8'))
    dialog.profile.setCurrentIndex(0)
    assert dialog.code.isEnabled() and dialog.notes.isEnabled()


def test_choosing_v1_while_sharing_falls_back_to_local_with_a_notice(qtbot, window):
    dialog = make(qtbot, window)
    dialog.profile.setCurrentIndex(1)
    dialog.contract.setCurrentIndex(0)
    assert dialog.profile.currentIndex() == 0 and export_vm.V1_NO_SHARE in dialog.hint.text()


def test_local_warning_goes_to_the_hint_not_the_error_label_and_only_once(qtbot, window):
    dialog = make(qtbot, window)
    dialog.contract.setCurrentIndex(1)
    assert export_vm.LOCAL_WARNING in dialog.hint.text() and dialog.error.text() == ''
    dialog.profile.setCurrentIndex(1)
    dialog.profile.setCurrentIndex(0)
    assert export_vm.LOCAL_WARNING not in dialog.hint.text()
    dialog.refresh_preview()
    assert dialog.error.text() == ''


def test_selection_and_enrichment_merge_with_v2_kwargs(qtbot, window):
    dialog = ExportDialog(window.project, window.service.root, ['finding-1'], window)
    qtbot.addWidget(dialog)
    dialog.enrichment = {'ranking': None}
    dialog.selection.setChecked(True)
    dialog.contract.setCurrentIndex(1)
    options = dialog.options()
    assert options['finding_ids'] == ['finding-1'] and options['enrichment'] == {'ranking': None}
    assert options['report_version'] == 2 and 'sections' in options


def test_main_window_collects_sections_when_the_dialog_opens(qtbot, window, monkeypatch):
    publish_engine(window.service, 'rz-diff', '1' * 64)
    seen = {}

    def inspect(self):
        self.contract.setCurrentIndex(1)
        seen.update(items(self))
        return QDialog.DialogCode.Rejected
    monkeypatch.setattr(ExportDialog, 'exec', inspect)
    window.export_report()
    assert seen['engine_evidence'][0].startswith('Engine evidence (') and seen['engine_evidence'][1]


def test_main_window_survives_a_failing_collection(qtbot, window, monkeypatch):
    def boom(service):
        raise RuntimeError('collect failed')
    monkeypatch.setattr('patchtrace.report2.adapters.collect_from_service', boom)
    seen = {}
    monkeypatch.setattr(ExportDialog, 'exec', lambda self: seen.update(items(self)) or QDialog.DialogCode.Rejected)
    window.export_report()
    assert set(seen) == set(export_vm.SECTION_LABELS)


def test_tooltip_ids_are_registered():
    from patchtrace.tooltips import REGISTRY
    assert {'export.contract', 'export.profile', 'export.sections'} <= set(REGISTRY)


def test_written_file_matches_dialog_options_end_to_end(qtbot, window, tmp_path, monkeypatch):
    out = Path(tmp_path / 'out.md')

    def accept(self):
        self.destination.setText(str(out))
        self.profile.setCurrentIndex(1)
        return QDialog.DialogCode.Accepted
    monkeypatch.setattr(ExportDialog, 'exec', accept)
    window.export_report()
    written = out.read_text(encoding='utf-8')
    assert 'Content digest' in written and 'buffer[index]' not in written
