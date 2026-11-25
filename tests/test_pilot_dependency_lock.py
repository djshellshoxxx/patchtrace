"""The advisory pilot bootstrap has a complete Linux hash lock; application install stays separate."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from tools.ci_pip_install_audit import pip_installs, run_scalars

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'tools/calibration/pilot/requirements-ci.lock'
WORKFLOW = ROOT / '.github/workflows/pilot-eval.yml'
REQUIREMENT = re.compile(r'([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)*) --hash=sha256:([0-9a-f]{64})')
VERSIONS = {
    'hypothesis': '6.170.17', 'iniconfig': '2.3.1', 'packaging': '26.3', 'pluggy': '1.7.0',
    'pygments': '2.21.0', 'pytest': '9.2.0', 'sortedcontainers': '2.4.0',
}


def _requirements(path: Path):
    assert path.is_file(), f'Reviewed tooling lock is missing: {path}'
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = REQUIREMENT.fullmatch(line)
        assert match, f'Every entry must be exactly pinned with its reviewed wheel SHA-256: {line!r}'
        name, version, digest = match.groups()
        assert name not in result, f'Duplicate tooling distribution: {name}'
        result[name] = (version, digest)
    return result


def test_pilot_lock_pins_the_complete_selected_linux_qa_tooling_closure():
    requirements = _requirements(LOCK)
    assert {name: value[0] for name, value in requirements.items()} == VERSIONS
    assert requirements['hypothesis'][1] == 'fd5f7feb13c275bb4672c5ef651ab6df1cb4a054c54d14aa44e578274241587a'
    assert requirements['sortedcontainers'][1] == 'a163dcaede0f1c021485e957a39245190e74249897e2ae4b2aa38595db237ee0'


def test_pilot_reuses_exact_reviewed_pytest_wheels_without_site_packages():
    requirements = _requirements(LOCK)
    site = _requirements(ROOT / 'tools/site/requirements-ci.lock')
    shared = {'pytest', 'iniconfig', 'packaging', 'pluggy', 'pygments'}
    assert all(requirements[name] == site[name] for name in shared)
    assert set(requirements) - shared == {'hypothesis', 'sortedcontainers'}


def test_pilot_bootstrap_requires_hashes_and_keeps_dependency_resolution():
    source = WORKFLOW.read_text(encoding='utf-8')
    installs = pip_installs(source)
    assert len(installs) == 2
    assert installs[0].arguments == (
        '--require-hashes', '--only-binary=:all:', '-r', 'tools/calibration/pilot/requirements-ci.lock')
    assert installs[0].has_boundary
    assert installs[1].arguments == ('-e', '.')
    assert not installs[1].has_boundary
    workflow = yaml.safe_load(source)
    job = workflow['jobs']['evaluate']
    first_install = next(step for step in job['steps'] if 'run' in step)
    assert set(first_install) == {'run'}
    assert 'env' not in workflow and 'env' not in job


def test_pilot_keeps_manual_advisory_scope_and_existing_evaluation_commands():
    source = WORKFLOW.read_text(encoding='utf-8')
    runs = list(run_scalars(source))  # Also rejects duplicate/ambiguous YAML mappings.
    workflow = yaml.safe_load(source)
    assert workflow.get('on', workflow.get(True)) == {'workflow_dispatch': None}
    assert workflow['permissions'] == {'contents': 'read'}
    assert set(workflow['jobs']) == {'evaluate'}
    job = workflow['jobs']['evaluate']
    assert job['runs-on'] == 'ubuntu-latest' and job['timeout-minutes'] == 30
    assert len(job['steps']) == 8 and len(runs) == 5
    assert runs[1] == 'python -m pip install -e .'
    assert runs[2] == ('mkdir -p out\n'
                       'sha256sum docs/plans/pilot-preregistration-v1.md | tee out/prereg.sha256\n')
    assert runs[3] == ('python -m pytest tests/test_pilot_eval_metrics.py '
                       'tests/test_pilot_eval_gate.py -q -p no:cacheprovider')
    assert "gate={'status': 'not-evaluated', 'conditions': {}}" in runs[4]
    assert job['steps'][-1]['with'] == {'name': 'pilot-eval', 'path': 'out/'}
