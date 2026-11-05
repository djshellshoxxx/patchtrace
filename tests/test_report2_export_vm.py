"""SPEC-50 RPT2-6 (view-model half): the Export dialog logic without Qt; repeat-safe by construction."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from test_report2_support import frozen_project, hostile_project, synergy_sections

from patchtrace.report2 import export_vm
from patchtrace.report2.export_vm import ExportViewModel
from patchtrace.report2.inputs import SectionInputs
from patchtrace.service import ProjectService


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


def _vm(sections=True):
    project, a, b = hostile_project()
    return ExportViewModel(project, synergy_sections(a, b) if sections else None)


def test_choices_and_names_match_the_spec():
    assert export_vm.CONTRACTS == ('Report v1 (current)', 'Report v2')
    assert export_vm.PROFILES == ('Local analysis', 'Share with others')
    assert set(export_vm.ACCESSIBLE_NAMES.values()) == {'export.contract', 'export.profile', 'export.sections',
                                                        'export.preview'}
    assert export_vm.TAB_ORDER == ('export.contract', 'export.profile', 'export.sections', 'export.preview',
                                   'export.button')


def test_v1_disables_every_section_with_a_reason():
    rows = _vm().section_rows()
    assert len(rows) == 7 and not any(r.enabled or r.checked for r in rows)
    assert {r.reason for r in rows} == {export_vm.V1_REASON}


def test_v2_checks_sections_with_data_and_disables_the_rest_with_reasons():
    vm = _vm()
    vm.set_contract(1)
    rows = {r.key: r for r in vm.section_rows()}
    assert rows['engine_evidence'].enabled and rows['engine_evidence'].checked and rows['engine_evidence'].count == 2
    assert rows['advisories'].count == 1 and rows['symbols'].count == 1
    assert (rows['series'].enabled, rows['series'].checked, rows['series'].reason) == (
        False, False, 'Not available: no series is loaded.')
    assert rows['unified_result'].reason == 'Not available: no stored unified result.'


def test_no_secondary_engine_reason_copy():
    vm = _vm(sections=False)
    vm.set_contract(1)
    rows = {r.key: r for r in vm.section_rows()}
    assert rows['engine_evidence'].reason == 'Not available: no secondary engine ran.'
    assert rows['symbols'].count in (0, 1)


def test_unchecking_a_section_removes_it_from_the_export():
    vm = _vm()
    vm.set_contract(1)
    vm.set_section_checked('advisories', False)
    assert {r.key: r.checked for r in vm.section_rows()}['advisories'] is False
    sections = vm.sections_for_export()
    assert sections.advisories is None and sections.engine_evidence is not None
    vm.set_section_checked('advisories', True)
    assert vm.sections_for_export().advisories is not None
    with pytest.raises(ValueError):
        vm.set_section_checked('bogus', True)


def test_share_profile_switches_to_v2_and_hints():
    vm = _vm()
    assert vm.profile_hint() == ''
    assert vm.set_profile(1) == export_vm.SHARE_NEEDS_V2 and vm.report_version == 2
    assert vm.profile_hint() == ('Share profile removes code, notes and file paths and writes web addresses as '
                                 'inert text.')
    assert vm.set_contract(0) == export_vm.V1_NO_SHARE and vm.profile_index == 0
    with pytest.raises(ValueError):
        vm.set_profile(2)


def test_local_warning_is_shown_once_per_dialog():
    vm = _vm()
    assert vm.take_local_warning() == export_vm.LOCAL_WARNING and vm.take_local_warning() is None
    other = _vm()
    other.set_profile(1)
    assert other.take_local_warning() is None


def test_export_kwargs_follow_the_profile():
    vm = _vm()
    assert vm.export_kwargs(include_code=True) == {'include_code': True, 'include_notes': True}
    vm.set_contract(1)
    local = vm.export_kwargs(include_code=True, include_notes=False)
    assert (local['report_version'], local['include_code'], local['include_notes']) == (2, True, False)
    vm.set_profile(1)
    share = vm.export_kwargs(include_code=True, include_notes=True)
    assert (share['include_code'], share['include_notes'], share['redaction'].name) == (False, False, 'share')


def test_empty_project_state():
    project = frozen_project()
    project.matches.clear()
    assert ExportViewModel(project).nothing_to_export == 'Nothing to export: no matches yet.'
    assert _vm().nothing_to_export is None


def test_error_copy_and_calibration_line():
    assert ExportViewModel.error_text('PT-EXPORT-IO') == (
        'Export failed: PT-EXPORT-IO. The previous file, if any, is unchanged.')
    assert export_vm.CALIBRATION_LINE == 'Scores are ordinal triage indices, not probabilities of a vulnerability.'


def test_preview_is_the_exact_text_and_plain():
    vm = _vm()
    vm.set_contract(1)
    text = vm.preview('md')
    assert text.startswith('# PatchTrace report') and 'Engine evidence' in text
    assert '\u202e' not in text and '<U+202E>' in text
    assert '<' not in ''.join(line for line in text.split('\n') if line.startswith('#'))


def test_preview_respects_the_checklist():
    vm = _vm()
    vm.set_contract(1)
    assert 'Advisories' in vm.preview('md')
    vm.set_section_checked('advisories', False)
    assert '## Advisories' not in vm.preview('md')


def test_preview_v1_matches_the_v1_renderer():
    from patchtrace.reports import _render, _snapshot
    project = frozen_project()
    vm = ExportViewModel(project)
    assert vm.preview('json') == _render(_snapshot(project, False, True, None, None), 'json')


def test_preview_is_capped_at_200_kib_with_the_note(monkeypatch):
    monkeypatch.setattr(export_vm, 'PREVIEW_LIMIT', 500)
    text = _vm().preview('json')
    assert text.endswith(export_vm.PREVIEW_NOTE + '\n') and len(text.encode('utf-8')) < 500 + 200
    assert export_vm.PREVIEW_LIMIT == 500
    monkeypatch.undo()
    assert export_vm.PREVIEW_LIMIT == 200 * 1024


def test_preview_cap_never_splits_a_character(monkeypatch):
    project = frozen_project()
    project.name = '\u00e9' * 400
    monkeypatch.setattr(export_vm, 'PREVIEW_LIMIT', 301)
    text = ExportViewModel(project).preview('json')
    text.encode('utf-8')
    assert text.endswith(export_vm.PREVIEW_NOTE + '\n')


@pytest.mark.parametrize('run', range(20))
def test_vm_is_repeat_safe(run):
    vm = _vm()
    vm.set_contract(1)
    vm.set_profile(run % 2)
    assert vm.preview('md', generated_at='t') == vm.preview('md', generated_at='t') and vm.report_version == 2


def test_export_through_the_service_with_vm_kwargs(tmp_path):
    from patchtrace.sample import create_sample
    service = create_sample(tmp_path / 'p')
    try:
        vm = ExportViewModel(service.project)
        vm.set_contract(1)
        vm.set_profile(1)
        manifest = service.export_report('json', tmp_path / 'out.json', **vm.export_kwargs())
        assert (manifest.report_version, manifest.redaction_profile) == (2, 'share')
    finally:
        service.close()
    assert isinstance(service, ProjectService)


def test_section_inputs_default_is_all_absent():
    assert all(getattr(SectionInputs(), k) is None for k in export_vm.SECTION_LABELS)


def test_view_model_imports_no_qt():
    root = Path(export_vm.__file__).parents[2]
    code = (f'import sys; sys.path.insert(0, {str(root)!r}); import patchtrace.report2.export_vm;'
            'print(sorted(m for m in sys.modules if m.startswith(("PySide", "shiboken", "patchtrace.ui"))))')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == '[]'
