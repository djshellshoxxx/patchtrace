"""Preserve the actual Sigstore toolchain while hashing its complete Linux closure."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

from tools.ci_pip_install_audit import pip_installs, run_scalars

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'tools/requirements-sigstore-ci.lock'
WORKFLOW = ROOT / '.github/workflows/backend-bundle.yml'
REQUIREMENT = re.compile(r'([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)*) --hash=sha256:([0-9a-f]{64})')
VERSIONS = {
    'annotated-types': '0.8.0',
    'certifi': '2026.7.22',
    'cffi': '2.1.1',
    'charset-normalizer': '3.5.2',
    'cryptography': '50.0.2',
    'dnspython': '2.9.0',
    'email-validator': '2.3.0',
    'id': '1.6.1',
    'idna': '3.20',
    'markdown-it-py': '4.2.0',
    'mdurl': '0.1.2',
    'platformdirs': '4.13.0',
    'pyasn1': '0.6.4',
    'pycparser': '3.11',
    'pydantic': '2.14.1',
    'pydantic-core': '2.50.1',
    'pygments': '2.21.0',
    'pyjwt': '2.15.1',
    'pyopenssl': '26.4.0',
    'requests': '2.34.2',
    'rfc3161-client': '1.0.9',
    'rfc8785': '0.1.4',
    'rich': '15.0.0',
    'securesystemslib': '1.5.1',
    'sigstore': '4.5.0',
    'sigstore-models': '0.0.6',
    'sigstore-rekor-types': '0.0.18',
    'tuf': '7.0.1',
    'typing-extensions': '4.16.0',
    'typing-inspection': '0.4.4',
    'urllib3': '2.8.0',
}


def _requirements(path: Path):
    assert path.is_file(), f'Reviewed Sigstore tooling lock is missing: {path}'
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        match = REQUIREMENT.fullmatch(line)
        assert match, f'Every entry needs an exact version and reviewed wheel SHA-256: {line!r}'
        name, version, digest = match.groups()
        assert name not in result, f'Duplicate tooling distribution: {name}'
        result[name] = (version, digest)
    return result


def test_sigstore_lock_preserves_the_complete_actual_verifier_closure():
    requirements = _requirements(LOCK)
    assert {name: value[0] for name, value in requirements.items()} == VERSIONS
    assert requirements['sigstore'][1] == 'f045b207f2e12605cf775ec38e89c5eda625d71ffa7830477db65e47ec2bc8b2'
    assert requirements['email-validator'][1] == '80f13f623413e6b197ae73bb10bf4eb0908faf509ad8362c5edeb0be7fd450b4'


def test_sigstore_reuses_only_the_exact_reviewed_pygments_artifact():
    requirements = _requirements(LOCK)
    for relative in ['tools/site/requirements-ci.lock', 'tools/calibration/pilot/requirements-ci.lock']:
        existing = _requirements(ROOT / relative)
        assert set(requirements) & set(existing) == {'pygments'}
        assert requirements['pygments'] == existing['pygments']


def test_sigstore_installer_requires_hashes_and_normal_dependency_resolution():
    source = WORKFLOW.read_text(encoding='utf-8')
    installs = pip_installs(source)
    assert len(installs) == 3
    assert installs[0].arguments == (
        '--require-hashes', '--only-binary=:all:', '-r', 'tools/requirements-sigstore-ci.lock')
    assert installs[0].has_boundary
    assert all(not install.has_boundary for install in installs[1:])
    assert all(install.arguments == ('--only-binary=:all:', '-e', '.[dev,search,rules]')
               for install in installs[1:])
    workflow = yaml.safe_load(source)
    job = workflow['jobs']['vrfy']
    step = next(item for item in job['steps'] if item.get('name') == 'Install the Sigstore client (pinned)')
    assert set(step) == {'name', 'run'}
    assert 'env' not in workflow
    assert job['env'] == {
        'IN_IDENTITY': '${{ inputs.sigstore_identity }}',
        'IN_ISSUER': '${{ inputs.sigstore_issuer }}',
        'IN_FPR': '${{ inputs.gpg_fingerprint }}',
    }


def test_sigstore_change_preserves_every_other_frozen_workflow_byte():
    source = WORKFLOW.read_text(encoding='utf-8')
    assert len(list(run_scalars(source))) == 26  # Reject ambiguous/invalid YAML too.
    old = "        run: python -m pip install 'sigstore==4.5.0'"
    new = '        run: "python -m pip install --require-hashes --only-binary=:all: -r tools/requirements-sigstore-ci.lock"'
    assert source.count(old) + source.count(new) == 1
    normalized = source.replace(old, '        run: <reviewed-sigstore-tooling-installer>').replace(new, '        run: <reviewed-sigstore-tooling-installer>')
    # Frozen f086 with only the installer line replaced: triggers, inputs, plans,
    # permissions, Action pins, identity/artifact commands and other installs stay intact.
    assert hashlib.sha256(normalized.encode('utf-8')).hexdigest() == '18a60705b63fe3242a2d2ddf7feebeb8048e9af40e66d56a7df96f6772391563'
