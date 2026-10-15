"""Static invariants of .github/workflows/unified-live-gates.yml (SPEC-31 S6b). They parse the workflow only; they prove
nothing about a live Actions run (the first dispatch is recorded in docs/qa.md). tests/test_workflows.py enforces the
plain-scalar rule for every workflow."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip('yaml')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
WORKFLOW = ROOT / '.github' / 'workflows' / 'unified-live-gates.yml'
ALLOWED_ACTIONS = {'actions/checkout@v4', 'actions/setup-python@v5', 'actions/setup-java@v4',
                   'actions/upload-artifact@v4', 'actions/download-artifact@v4'}


@pytest.fixture(scope='module')
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def run_text(job: dict) -> str:
    return '\n'.join(str(step.get('run', '')) for step in job['steps'])


def test_it_is_dispatch_only_and_advisory(doc):
    assert set(doc.get('on', doc.get(True))) == {'workflow_dispatch'}
    assert doc['permissions'] == {'contents': 'read'}
    assert doc['jobs']['pairs']['continue-on-error'] is True and doc['jobs']['mutants']['continue-on-error'] is True
    assert doc['jobs']['report']['if'] == '${{ !cancelled() }}' and '--strict' not in run_text(doc['jobs']['report'])
    assert all(job['timeout-minutes'] <= 240 for job in doc['jobs'].values())


def test_actions_are_pinned_and_dispatch_inputs_reach_scripts_only_through_env(doc):
    used = {s['uses'] for job in doc['jobs'].values() for s in job['steps'] if 'uses' in s}
    assert used <= ALLOWED_ACTIONS, used - ALLOWED_ACTIONS
    for job in doc['jobs'].values():
        for step in job['steps']:
            assert 'inputs.' not in str(step.get('run', ''))
            assert 'matrix.' not in str(step.get('run', ''))


def test_the_ghidra_pin_is_the_one_of_the_extraction_workflow_and_checked_by_digest(doc):
    other = yaml.safe_load((ROOT / '.github' / 'workflows' / 'live-unified.yml').read_text(encoding='utf-8'))
    for key in ('GHIDRA_URL', 'GHIDRA_SHA256', 'GHIDRIFF_PIN'):
        assert doc['env'][key] == other['env'][key]
    for name in ('pairs', 'mutants'):
        assert 'sha256sum -c' in run_text(doc['jobs'][name])


def test_every_pip_install_takes_wheels_only_except_the_pinned_ghidriff_revision(doc):
    installs = [line for job in doc['jobs'].values() for line in run_text(job).splitlines() if 'pip install' in line]
    assert installs and all('--only-binary=:all:' in line or 'GHIDRIFF_PIN' in line for line in installs)
    assert all('pyghidra' not in line for line in installs if 'GHIDRIFF_PIN' in line)      # the pin is its own line


def test_the_matrix_covers_every_mutant_class_and_both_operating_systems(doc):
    from tools.unified.mutations import classes
    assert doc['jobs']['mutants']['strategy']['matrix']['cls'] == [c.id for c in classes.CLASSES]
    assert doc['jobs']['pairs']['strategy']['matrix']['os'] == ['ubuntu-latest', 'windows-latest']
    assert doc['jobs']['mutants']['strategy']['fail-fast'] is False


def test_only_open_source_test_builds_are_uploaded_and_only_briefly(doc):
    for job in doc['jobs'].values():
        for step in job['steps']:
            if str(step.get('uses', '')).startswith('actions/upload-artifact'):
                paths = str(step['with']['path'])
                if 'images' in paths:
                    assert step['with']['retention-days'] <= 3 and step['with']['name'] == 'unified-live-corpus'
                assert not re.search(r'\.pdb|\.gzf', paths)


def test_every_command_it_runs_exists_and_the_report_reads_what_the_jobs_upload(doc):
    from tools.unified import live_pairs
    from tools.unified.corpus import cli
    text = '\n'.join(run_text(job) for job in doc['jobs'].values())
    for module in sorted(set(re.findall(r'python -m (tools\.unified\.[\w.]+)', text))):
        path = ROOT / Path(*module.split('.'))
        assert path.with_suffix('.py').is_file() or (path / '__main__.py').is_file(), module
    help_text = cli.parser().format_help()
    assert all(re.search(rf'\b{c}\b', help_text) for c in re.findall(r'tools\.unified\.corpus (\w+)', text))
    source = Path(live_pairs.__file__).read_text(encoding='utf-8')
    for line in (row for row in text.splitlines() if 'tools.unified.live_pairs' in row):
        for flag in re.findall(r'(--[a-z-]+)', line):
            assert f"'{flag}'" in source, flag
    download = [s for s in doc['jobs']['report']['steps'] if str(s.get('uses', '')).startswith('actions/download')]
    assert {s['with'].get('name') or s['with'].get('pattern') for s in download} == {'unified-live-manifest',
                                                                                     'unified-live-outcomes-*'}
    assert 'in/unified-corpus-manifest.json' in run_text(doc['jobs']['report']) and '--outcomes' in text


def test_names_have_no_colon_space(doc):
    texts = [doc['name']] + [job['name'] for job in doc['jobs'].values()]
    texts += [str(s.get('name', '')) for job in doc['jobs'].values() for s in job['steps']]
    assert not [t for t in texts if ': ' in t]
