"""SPEC-50 RPT2-5: `export_project(report_version=2)`, the additive manifest and v1 byte identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from test_report2_support import frozen_project, hostile_project, synergy_sections

from patchtrace import reports
from patchtrace.models import ExportManifest
from patchtrace.report2.inputs import RedactionProfile
from patchtrace.report2.render_json import content_digest
from patchtrace.reports import ExportError, export_project

GOLDEN = Path(__file__).parent / 'golden' / 'report2'


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


@pytest.mark.parametrize('fmt', ['json', 'md', 'html'])
def test_v1_output_is_byte_identical_to_the_frozen_main_output(tmp_path, fmt):
    out = tmp_path / f'r.{fmt}'
    manifest = export_project(frozen_project(), fmt, out)
    # HTML goldens carry a data suffix so code analysers do not treat test output as HTML source
    name = f'v1_expected.{fmt}' + ('.golden' if fmt == 'html' else '')
    expected = (GOLDEN / name).read_bytes().replace(b'\r\n', b'\n')
    assert out.read_bytes() == expected
    assert manifest.sha256 == hashlib.sha256(expected).hexdigest()


@pytest.mark.parametrize('fmt', ['json', 'md', 'html'])
def test_explicit_report_version_1_equals_the_default(tmp_path, fmt):
    export_project(frozen_project(), fmt, tmp_path / 'a')
    export_project(frozen_project(), fmt, tmp_path / 'b', report_version=1)
    assert (tmp_path / 'a').read_bytes() == (tmp_path / 'b').read_bytes()


def test_manifest_gains_only_additive_defaulted_fields():
    assert ExportManifest.model_fields['report_version'].default == 1
    manifest = ExportManifest(project_id='p', revision=1, format='json', sha256='a' * 64, finding_ids=[],
                              include_code=False, include_notes=True)
    assert (manifest.report_version, manifest.content_digest, manifest.sections, manifest.redaction_profile) == (
        1, None, [], 'local')
    with pytest.raises(ValueError):
        ExportManifest(project_id='p', revision=1, format='json', sha256='a', finding_ids=[], include_code=False,
                       include_notes=True, unknown=1)


def test_v1_manifest_reports_version_1(tmp_path):
    manifest = export_project(frozen_project(), 'json', tmp_path / 'r.json')
    assert (manifest.report_version, manifest.content_digest, manifest.sections) == (1, None, [])


def test_v2_json_export_manifest_digest_and_sections(tmp_path):
    project, a, b = hostile_project()
    out = tmp_path / 'r.json'
    manifest = export_project(project, 'json', out, report_version=2, sections=synergy_sections(a, b))
    data = json.loads(out.read_text(encoding='utf-8'))
    assert data['report_version'] == 2 and data['calibration']['display_level'] == 'ordinal'
    assert manifest.report_version == 2 and manifest.content_digest == data['content_digest'] == content_digest(data)
    assert manifest.sections == data['sections_present'] == ['advisories', 'build_facts', 'engine_evidence',
                                                             'leads', 'symbols']
    assert manifest.redaction_profile == 'local' and manifest.sha256 == hashlib.sha256(out.read_bytes()).hexdigest()
    assert '<U+202E>gnidnuf' in out.read_text(encoding='utf-8')


@pytest.mark.parametrize('fmt', ['md', 'html'])
def test_v2_other_formats_write_and_carry_the_digest(tmp_path, fmt):
    project, a, b = hostile_project()
    manifest = export_project(project, fmt, tmp_path / f'r.{fmt}', report_version=2, sections=synergy_sections(a, b))
    assert manifest.content_digest in (tmp_path / f'r.{fmt}').read_text(encoding='utf-8')


def test_v2_content_digest_is_stable_across_exports(tmp_path):
    project, a, b = hostile_project()
    first = export_project(project, 'json', tmp_path / '1.json', report_version=2, sections=synergy_sections(a, b))
    second = export_project(project, 'md', tmp_path / '2.md', report_version=2, sections=synergy_sections(a, b))
    assert first.content_digest == second.content_digest


def test_v2_symbols_section_comes_from_the_persisted_run_settings(tmp_path):
    project = frozen_project()
    project.runs[0].settings = {'symbol_mode': 'local', 'launcher_version': '1.2'}
    data = json.loads(_export(project, tmp_path))
    assert data['symbols'] == {'mode': 'local', 'servers': [], 'staged': [], 'launcher_version': '1.2',
                               'consent': None}
    assert 'symbols' in data['sections_present']


def _export(project, tmp_path, **kwargs):
    export_project(project, 'json', tmp_path / 'r.json', report_version=2, **kwargs)
    return (tmp_path / 'r.json').read_text(encoding='utf-8')


def test_share_profile_forces_code_and_notes_off_and_defangs_urls(tmp_path):
    project, a, b = hostile_project()
    manifest = export_project(project, 'json', tmp_path / 'r.json', include_code=True, include_notes=True,
                              report_version=2, sections=synergy_sections(a, b), redaction=RedactionProfile.share())
    data = json.loads((tmp_path / 'r.json').read_text(encoding='utf-8'))
    assert (manifest.include_code, manifest.include_notes, manifest.redaction_profile) == (False, False, 'share')
    assert data['redaction'] == {'profile': 'share', 'paths': True, 'code': False, 'notes': False,
                                 'urls': 'defanged', 'rules_applied': data['redaction']['rules_applied']}
    assert data['advisories'][0]['url_text'].startswith('hxxps://evil[.]example')
    assert all('code' not in f for m in data['matches'] for f in m['older'] + m['newer'])
    assert data['annotations'] == []


def test_local_profile_with_code_keeps_code_normalized(tmp_path):
    project, _, _ = hostile_project()
    project.matches[0].newer[0].code = 'a\r\nb\x1b\u202ec'
    data = json.loads(_export(project, tmp_path, include_code=True))
    assert 'a\nb?<U+202E>c' in {f.get('code') for m in data['matches'] for f in m['older'] + m['newer']}


def test_unknown_report_version_is_a_contract_error_and_writes_nothing(tmp_path):
    with pytest.raises(ExportError, match='PT-EXPORT-CONTRACT'):
        export_project(frozen_project(), 'json', tmp_path / 'r.json', report_version=3)
    assert not (tmp_path / 'r.json').exists()


@pytest.mark.parametrize('kwargs', [{'sections': object()}, {'redaction': RedactionProfile()},
                                    {'calibration_profile': 'G'}], ids=['sections', 'redaction', 'calibration'])
def test_v2_only_options_with_v1_are_refused(tmp_path, kwargs):
    with pytest.raises(ExportError, match='PT-EXPORT-CONTRACT'):
        export_project(frozen_project(), 'json', tmp_path / 'r.json', **kwargs)


def test_unknown_format_still_uses_the_v1_message(tmp_path):
    with pytest.raises(ExportError, match='supported formats are json, html, and md'):
        export_project(frozen_project(), 'pdf', tmp_path / 'r', report_version=2)


def test_lone_surrogate_in_a_project_name_is_replaced_not_a_crash(tmp_path):
    project = frozen_project()
    project.name = 'x\ud800y'
    data = json.loads(_export(project, tmp_path))
    assert data['name'] == 'x\ufffdy'


def test_lone_surrogate_that_survives_rendering_raises_the_encoding_code(tmp_path, monkeypatch):
    monkeypatch.setitem(__import__('patchtrace.report2.export', fromlist=['RENDERERS']).RENDERERS, 'json',
                        lambda data: 'x\ud800y')
    out = tmp_path / 'r.json'
    with pytest.raises(ExportError, match='PT-EXPORT-ENCODING'):
        export_project(frozen_project(), 'json', out, report_version=2)
    assert not out.exists()


def test_v2_oversize_uses_the_size_code(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, 'MAX_REPORT_BYTES', 100)
    with pytest.raises(ExportError, match='PT-EXPORT-SIZE'):
        export_project(frozen_project(), 'json', tmp_path / 'r.json', report_version=2)
    with pytest.raises(ExportError, match='^PT-EXPORT: report exceeds 20 MiB'):
        export_project(frozen_project(), 'json', tmp_path / 'r.json')


def test_v2_write_failure_keeps_the_previous_file_and_uses_the_io_code(tmp_path, monkeypatch):
    out = tmp_path / 'r.json'
    out.write_text('previous', encoding='utf-8')

    def fail(*_a, **_k):
        raise OSError('disk full')
    monkeypatch.setattr(reports.os, 'replace', fail)
    with pytest.raises(ExportError, match='PT-EXPORT-IO'):
        export_project(frozen_project(), 'json', out, report_version=2)
    assert out.read_text(encoding='utf-8') == 'previous'
    assert not [p for p in tmp_path.iterdir() if p.name.startswith('.patchtrace-export-')]


def test_finding_selection_is_honoured_by_v2(tmp_path):
    project = frozen_project()
    finding = project.interpretations[0].findings[0]
    data = json.loads(_export(project, tmp_path, finding_ids=[finding.id]))
    assert data['selection']['finding_ids'] == [finding.id]
    with pytest.raises(ExportError, match='requested finding ID'):
        export_project(project, 'json', tmp_path / 'x.json', finding_ids=['forged'], report_version=2)


def test_v2_respects_destination_protection(tmp_path):
    project = frozen_project()
    link = tmp_path / 'link.json'
    link.symlink_to(tmp_path / 'target.json')
    with pytest.raises(ExportError, match='symlink'):
        export_project(project, 'json', link, report_version=2)
