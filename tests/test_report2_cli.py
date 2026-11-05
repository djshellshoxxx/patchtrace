"""SPEC-50 RPT2-6 (CLI half): `patchtrace export`, envelope enrichment-cli/1, exit codes 0/2/3/4/5."""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from argparse import Namespace
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover
from patchtrace.report2 import cli as export_cli
from patchtrace.report2 import options
from patchtrace.sample import create_sample


@pytest.fixture(autouse=True)
def no_artifact(tmp_path_factory, monkeypatch):
    monkeypatch.setattr('patchtrace.calibration.artifact.BUNDLED_DIR', tmp_path_factory.mktemp('nocal'))


@pytest.fixture
def project(tmp_path):
    service = create_sample(tmp_path / 'p')
    service.close()
    return tmp_path / 'p'


def run(capsys, *argv):
    code = cli.main(['export', *map(str, argv)])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_adapter_is_discovered_and_at_most_25_lines():
    verbs, failed = discover()
    assert 'export' in verbs and 'export' not in {m.replace('_', '-') for m in failed}
    source = Path(export_cli.__file__).parent.parent / 'cli_commands' / 'export.py'
    assert len(source.read_text(encoding='utf-8').splitlines()) <= 25


def test_default_is_report_v1_json_and_exit_0(project, tmp_path, capsys):
    out = tmp_path / 'r.json'
    code, stdout, _ = run(capsys, project, '--out', out, '--json')
    envelope = json.loads(stdout)
    assert code == 0 and envelope['contract'] == 'enrichment-cli/1' and envelope['command'] == 'export'
    assert envelope['status'] == 'complete'
    assert envelope['result']['report_version'] == 1 and envelope['result']['content_digest'] is None
    assert json.loads(out.read_text(encoding='utf-8'))['schema_version'] == 1
    assert 'report_version' not in json.loads(out.read_text(encoding='utf-8'))


@pytest.mark.parametrize('fmt', ['json', 'md', 'html'])
def test_report_v2_all_formats(project, tmp_path, capsys, fmt):
    out = tmp_path / f'r.{fmt}'
    code, stdout, _ = run(capsys, project, '--format', fmt, '--report-version', 2, '--out', out, '--json')
    manifest = json.loads(stdout)['result']
    assert code == 0 and manifest['report_version'] == 2 and manifest['format'] == fmt
    assert manifest['content_digest'] in out.read_text(encoding='utf-8')
    # the sample's two PE files supply build_facts through report2.adapters; nothing else is stored
    assert manifest['sections'] == ['build_facts'] or manifest['sections'] == ['build_facts', 'symbols']


def test_text_mode_prints_one_summary_line(project, tmp_path, capsys):
    code, stdout, _ = run(capsys, project, '--report-version', 2, '--out', tmp_path / 'r.json')
    assert code == 0 and stdout.startswith('Exported report/2 (json) to ') and 'content digest' in stdout


def test_share_profile_forces_code_and_notes_off_and_defangs(project, tmp_path, capsys):
    out = tmp_path / 'share.json'
    code, stdout, _ = run(capsys, project, '--report-version', 2, '--profile', 'share', '--out', out, '--json')
    manifest = json.loads(stdout)['result']
    data = json.loads(out.read_text(encoding='utf-8'))
    assert code == 0 and (manifest['include_code'], manifest['include_notes']) == (False, False)
    assert data['redaction']['profile'] == 'share' and data['redaction']['urls'] == 'defanged'
    assert data['annotations'] == []


def test_include_code_and_notes_flags_reach_the_export(project, tmp_path, capsys):
    out = tmp_path / 'code.json'
    code, stdout, _ = run(capsys, project, '--include-code', '--no-include-notes', '--out', out, '--json')
    manifest = json.loads(stdout)['result']
    assert code == 0 and (manifest['include_code'], manifest['include_notes']) == (True, False)


def test_finding_selection(project, tmp_path, capsys):
    from patchtrace.service import ProjectService
    service = ProjectService.open(project)
    finding = service.project.interpretations[0].findings[0].id
    service.close()
    code, stdout, _ = run(capsys, project, '--finding', finding, '--out', tmp_path / 'f.json', '--json')
    assert code == 0 and json.loads(stdout)['result']['finding_ids'] == [finding]


@pytest.mark.parametrize('extra', [
    ['--profile', 'share'], ['--urls', 'defanged'], ['--include-ordinal-index'],
    ['--report-version', '2', '--profile', 'share', '--include-code'],
    ['--report-version', '2', '--profile', 'share', '--include-notes'],
    ['--report-version', '2', '--profile', 'share', '--urls', 'text'],
    ['--format', 'pdf'], ['--report-version', '3'], ['--profile', 'other']],
    ids=['v1-share', 'v1-urls', 'v1-index', 'share-code', 'share-notes', 'share-text', 'format', 'version', 'profile'])
def test_invalid_arguments_exit_2_and_write_nothing(project, tmp_path, capsys, extra):
    out = tmp_path / 'r.json'
    code, _, err = run(capsys, project, *extra, '--out', out)
    assert code == 2 and not out.exists() and err


def test_missing_out_is_exit_2(project, capsys):
    assert run(capsys, project)[0] == 2


def test_unopenable_project_is_exit_2(tmp_path, capsys):
    code, _, err = run(capsys, tmp_path / 'nope', '--out', tmp_path / 'r.json')
    assert code == 2 and 'error:' in err


def test_unknown_finding_is_export_failure_exit_3(project, tmp_path, capsys):
    out = tmp_path / 'r.json'
    code, stdout, err = run(capsys, project, '--finding', 'forged', '--out', out, '--json')
    assert code == 3 and 'Export failed' in err and 'previous file' in err and not out.exists()
    assert json.loads(stdout)['status'] == 'failed'


def test_destination_inside_the_project_is_refused_exit_3(project, capsys):
    code, _, err = run(capsys, project, '--out', project / 'project.sqlite3')
    assert code == 3 and 'Export failed' in err


def test_nothing_to_export_is_exit_4(tmp_path, capsys):
    from patchtrace.sample import synthetic_pe
    from patchtrace.service import ProjectService
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    ProjectService.create(older, newer, 'empty', tmp_path / 'empty').close()
    out = tmp_path / 'r.json'
    code, stdout, _ = run(capsys, tmp_path / 'empty', '--out', out, '--json')
    assert code == 4 and json.loads(stdout)['status'] == 'no-results' and not out.exists()


def test_cancelled_is_exit_5_and_writes_nothing(project, tmp_path, capsys):
    out = tmp_path / 'r.json'
    cancel = threading.Event()
    cancel.set()
    args = Namespace(project=project, format='json', report_version=1, profile='local', include_code=False,
                     include_notes=None, finding=None, out=out, include_ordinal_index=False, urls=None, json=True)
    assert export_cli.run(args, cancel) == 5
    assert json.loads(capsys.readouterr().out)['status'] == 'cancelled' and not out.exists()


def test_unified_port_reads_only_the_reference(project, tmp_path, capsys, monkeypatch):
    import patchtrace.unified.store as store

    def boom(*_a, **_k):
        raise AssertionError('bulk rows must not be read')
    monkeypatch.setattr(store, 'read_rows', boom)
    monkeypatch.setattr(store, 'read_facts', boom)
    out = tmp_path / 'r.json'
    assert run(capsys, project, '--report-version', 2, '--out', out)[0] == 0
    assert 'unified_result' not in json.loads(out.read_text(encoding='utf-8'))  # no stored result in the sample


def test_export_module_path_imports_no_qt():
    root = Path(export_cli.__file__).parents[2]
    code = (f'import sys; sys.path.insert(0, {str(root)!r}); from patchtrace import cli;'
            'from patchtrace.cli_commands import discover; discover(); import patchtrace.report2.cli;'
            'print(sorted(m for m in sys.modules if m.startswith(("PySide", "shiboken"))))')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, check=True)
    assert result.stdout.strip() == '[]'


@pytest.mark.parametrize('kwargs,message', [
    ({'report_version': 3}, 'must be 1 or 2'), ({'profile': 'share'}, 'need --report-version 2'),
    ({'report_version': 2, 'profile': 'share', 'include_code': True}, 'excludes code'),
    ({'report_version': 2, 'profile': 'share', 'include_notes': True}, 'excludes notes'),
    ({'report_version': 2, 'profile': 'share', 'urls': 'text'}, 'defanged or removed')],
    ids=['version', 'v1-share', 'code', 'notes', 'urls'])
def test_option_conflicts_raise(kwargs, message):
    with pytest.raises(ValueError, match=message):
        options.resolve(**kwargs)


def test_option_defaults():
    local = options.resolve(report_version=2)
    assert (local.include_notes, local.include_code, local.profile.urls) == (True, False, 'text')
    share = options.resolve(report_version=2, profile='share', include_ordinal_index=True)
    assert (share.include_notes, share.profile.urls, share.profile.include_ordinal_index) == (False, 'defanged', True)
    assert options.resolve(report_version=2, profile='share', urls='removed').profile.urls == 'removed'


def test_report_v2_cli_includes_stored_sections_and_records_unknowns(project, tmp_path, capsys):
    from test_report2_adapters import publish_engine

    from patchtrace.service import ProjectService
    with ProjectService.open(project) as service:
        publish_engine(service, 'rz-diff', '1' * 64)
    out = tmp_path / 'r.json'
    code, stdout, _ = run(capsys, project, '--report-version', 2, '--out', out, '--json')
    data = json.loads(out.read_text(encoding='utf-8'))
    assert code == 0 and 'engine_evidence' in json.loads(stdout)['result']['sections']
    assert [e['name'] for e in data['engine_evidence']['engines']] == ['rz-diff']
    assert any('bindiff has no stored match set' in u for u in data['unknowns'])
    assert all(f['claim_level'] == 'observed-in-file' for f in data['build_facts'])
