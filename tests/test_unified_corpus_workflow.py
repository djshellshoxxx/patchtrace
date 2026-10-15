"""Static invariants of .github/workflows/unified-corpus.yml (SPEC-31 S6a).

These parse the workflow only; they prove nothing about a live Actions run (the first dispatch is recorded in docs/qa.md).
The plain-scalar rule (no ": " in an unquoted value) is enforced for every workflow by tests/test_workflows.py."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip('yaml')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
WORKFLOW = ROOT / '.github' / 'workflows' / 'unified-corpus.yml'
ALLOWED_ACTIONS = {'actions/checkout@v4', 'actions/setup-python@v5', 'actions/upload-artifact@v4',
                   'actions/download-artifact@v4'}
JOBS = ('corpus', 'bench-windows', 'report')


@pytest.fixture(scope='module')
def doc() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))


def triggers(doc: dict) -> dict:
    return doc.get('on', doc.get(True))                # YAML 1.1 parses the key `on` as boolean true


def run_text(job: dict) -> str:
    return '\n'.join(str(step.get('run', '')) for step in job['steps'])


def test_it_is_dispatch_only_so_it_can_never_gate_or_burden_a_merge(doc):
    on = triggers(doc)
    assert set(on) == {'workflow_dispatch'}
    assert set(on['workflow_dispatch']['inputs']) == {'pairs', 'per_class', 'bench_sizes'}
    assert all(spec['type'] == 'string' and spec['default'] for spec in on['workflow_dispatch']['inputs'].values())


def test_it_is_advisory_the_windows_leg_cannot_fail_the_run_and_the_report_is_never_strict(doc):
    assert set(doc['jobs']) == set(JOBS)
    assert doc['jobs']['bench-windows']['continue-on-error'] is True
    assert 'continue-on-error' not in doc['jobs']['corpus']
    assert '--strict' not in run_text(doc['jobs']['report'])
    assert doc['jobs']['report']['if'] == '${{ !cancelled() }}'                     # a failed leg still gets its report
    assert doc['jobs']['report']['needs'] == ['corpus', 'bench-windows']


def test_least_privilege_and_bounded_runs(doc):
    assert doc['permissions'] == {'contents': 'read'}
    assert not [j for j, job in doc['jobs'].items() if 'permissions' in job]
    assert all(job['timeout-minutes'] <= 180 for job in doc['jobs'].values())


def test_actions_are_pinned_like_the_other_workflows(doc):
    used = {s['uses'] for job in doc['jobs'].values() for s in job['steps'] if 'uses' in s}
    assert used <= ALLOWED_ACTIONS, used - ALLOWED_ACTIONS


def test_dispatch_inputs_reach_scripts_only_through_env_never_inside_a_run(doc):
    for name, job in doc['jobs'].items():
        for step in job['steps']:
            assert 'inputs.' not in str(step.get('run', '')), (name, step.get('name'))
    steps = [s for job in doc['jobs'].values() for s in job['steps'] if 'inputs.' in str(s.get('env', ''))]
    assert steps and all(re.fullmatch(r'\$\{\{ inputs\.\w+ \}\}', v) for s in steps for v in s['env'].values())
    assert all('"$' in s['run'] for s in steps)                                       # always expanded quoted


def test_every_pip_install_takes_wheels_only(doc):
    installs = [line for job in doc['jobs'].values() for line in run_text(job).splitlines() if 'pip install' in line]
    assert installs and all('--only-binary=:all:' in line for line in installs)


def test_the_corpus_store_is_outside_the_work_tree_and_no_image_is_uploaded(doc):
    text = run_text(doc['jobs']['corpus'])
    assert 'PATCHTRACE_CALIB_ROOT=$RUNNER_TEMP/calib' in text
    for job in doc['jobs'].values():
        for step in job['steps']:
            if str(step.get('uses', '')).startswith('actions/upload-artifact'):
                paths = step['with']['path']
                assert not re.search(r'images|\.dll|\.exe|\.pdb|calib', paths), paths


def test_the_mingw_variant_is_pinned_to_the_one_the_evidence_came_from(doc):
    env = doc['jobs']['corpus']['env']
    assert env['PATCHTRACE_KA_MINGW_GCC'].endswith('x86_64-w64-mingw32-gcc-win32') and Path(env['PATCHTRACE_KA_MINGW_GCC']).is_absolute()
    assert 'gcc-mingw-w64-x86-64-win32' in run_text(doc['jobs']['corpus'])


def test_names_and_descriptions_have_no_colon_space(doc):
    texts = [doc['name']]
    for job in doc['jobs'].values():
        texts.append(job['name'])
        texts.extend(str(s.get('name', '')) for s in job['steps'])
    texts.extend(spec['description'] for spec in triggers(doc)['workflow_dispatch']['inputs'].values())
    assert not [t for t in texts if ': ' in t]


def test_every_command_it_runs_exists(doc):
    from tools.unified.corpus import cli
    help_text = cli.parser().format_help()
    text = '\n'.join(run_text(job) for job in doc['jobs'].values())
    for module in sorted(set(re.findall(r'python -m (tools\.unified\.[\w.]+)', text))):
        path = ROOT / Path(*module.split('.'))
        assert path.with_suffix('.py').is_file() or (path / '__main__.py').is_file(), module
    commands = re.findall(r'tools\.unified\.corpus (\w+)', text)
    assert commands and all(re.search(rf'\b{command}\b', help_text) for command in commands)
    for test_file in re.findall(r'tests/(test_\w+\.py)', text):
        assert (ROOT / 'tests' / test_file).is_file(), test_file


def test_the_report_job_reads_what_the_other_jobs_upload(doc):
    corpus, windows, report = (run_text(doc['jobs'][j]) for j in JOBS)
    assert 'out/unified-corpus-manifest.json' in corpus and 'out/bench-linux.json' in corpus
    assert '--junitxml=out/junit.xml' in corpus and 'out/bench-windows.json' in windows
    for name in ('unified-corpus-manifest.json', 'bench-linux.json', 'bench-windows.json', 'junit.xml'):
        assert f'in/{name}' in report
    download = next(s for s in doc['jobs']['report']['steps'] if str(s.get('uses', '')).startswith('actions/download'))
    assert download['with']['pattern'] == 'unified-corpus-*' and download['with']['merge-multiple'] is True
