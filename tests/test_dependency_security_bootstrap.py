"""Authored bootstrap transitions; no live advisory or native qualification."""
from __future__ import annotations

import copy
import importlib

import pytest
from test_dependency_security import authored_evidence, native_environment
from test_dependency_security import project as project


@pytest.fixture
def scan():
    return importlib.import_module('tools.dependency_security')


def transition(scan, root):
    identity = {'executable': str(root / 'env/bin/python'), 'prefix': str(root / 'env'),
                'base_prefix': str(root / 'base'), 'version': '3.12.14', 'implementation': 'CPython',
                'system': 'Linux', 'machine': 'x86_64', 'ensurepip': '25.0.1'}
    before = {'version': '1', 'pip_version': '25.0.1', 'environment': native_environment(),
              'installed': [{'metadata': {'name': 'pip', 'version': '25.0.1'}}]}
    after = copy.deepcopy(before)
    after['pip_version'] = scan.BOOTSTRAP_PIP
    after['installed'][0]['metadata']['version'] = scan.BOOTSTRAP_PIP
    report = {'version': '1', 'pip_version': '25.0.1', 'environment': native_environment(),
              'install': [{'metadata': {'name': 'pip', 'version': scan.BOOTSTRAP_PIP},
                           'requested': True, 'is_direct': False, 'is_yanked': False,
                           'download_info': {'url': scan.BOOTSTRAP_WHEEL_URL,
                               'archive_info': {'hashes': {'sha256': scan.BOOTSTRAP_WHEEL_SHA256}}}}]}
    return {'identity': identity, 'before': before, 'installation': report, 'after': after}


def test_transition_preserves_original_issuer_and_pinned_target(scan, tmp_path):
    record = transition(scan, tmp_path)
    assert scan.validate_bootstrap(record, record['identity']) == {
        'from_version': '25.0.1', 'to_version': '26.3', 'wheel_sha256': scan.BOOTSTRAP_WHEEL_SHA256}
    assert record['identity']['ensurepip'] == '25.0.1'
    assert record['before']['installed'][0]['metadata']['version'] == '25.0.1'
    assert record['installation']['pip_version'] == '25.0.1'


@pytest.mark.parametrize(('path', 'value'), [
    (('before',), None), (('after',), None), (('installation',), None), (('identity',), None),
    (('installation', 'pip_version'), '26.3'),
    (('installation', 'install', 0, 'metadata', 'version'), '26.2'),
    (('installation', 'install', 0, 'download_info', 'archive_info', 'hashes', 'sha256'), '0' * 64),
    (('installation', 'install', 0, 'download_info', 'archive_info', 'hashes'), None),
    (('installation', 'install', 0, 'download_info', 'url'), 'https://example.invalid/pip.whl'),
    (('installation', 'install', 0, 'is_yanked'), True),
    (('installation', 'install', 0, 'requested'), False),
    (('installation', 'install', 0, 'is_direct'), True),
    (('installation', 'install'), []),
    (('before', 'environment', 'platform_machine'), 'foreign-machine'),
    (('after', 'environment', 'platform_machine'), 'foreign-machine'),
    (('installation', 'environment', 'platform_machine'), 'foreign-machine'),
    (('identity', 'version'), '3.12.10'),
    (('identity', 'ensurepip'), '25.1'),
    (('after', 'pip_version'), '25.0.1'),
])
def test_forged_or_missing_transition_is_refused(scan, tmp_path, path, value):
    record = transition(scan, tmp_path)
    final_identity = copy.deepcopy(record['identity'])
    node = record
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = value
    with pytest.raises(scan.EvidenceError):
        scan.validate_bootstrap(record, final_identity)


@pytest.mark.parametrize('where', ['before', 'after', 'installation'])
def test_transition_refuses_any_extra_distribution(scan, tmp_path, where):
    record = transition(scan, tmp_path)
    rows = record[where]['install' if where == 'installation' else 'installed']
    rows.append(copy.deepcopy(rows[0]))
    with pytest.raises(scan.EvidenceError):
        scan.validate_bootstrap(record, record['identity'])


def test_newer_bootstrap_cannot_be_silently_downgraded(scan, tmp_path):
    record = transition(scan, tmp_path)
    record['identity']['ensurepip'] = '27.0'
    record['before']['pip_version'] = record['installation']['pip_version'] = '27.0'
    record['before']['installed'][0]['metadata']['version'] = '27.0'
    with pytest.raises(scan.EvidenceError):
        scan.validate_bootstrap(record, record['identity'])


def test_same_pinned_fresh_bootstrap_keeps_full_origin_proof(scan, tmp_path):
    record = transition(scan, tmp_path)
    record['identity']['ensurepip'] = scan.BOOTSTRAP_PIP
    record['before']['pip_version'] = record['installation']['pip_version'] = scan.BOOTSTRAP_PIP
    record['before']['installed'][0]['metadata']['version'] = scan.BOOTSTRAP_PIP
    assert scan.validate_bootstrap(record, record['identity'])['from_version'] == scan.BOOTSTRAP_PIP


def test_final_installed_pip_remains_auditable_and_requires_transition(scan, tmp_path):
    record = transition(scan, tmp_path)
    final = copy.deepcopy(record['after'])
    final['installed'].append({'metadata': {'name': 'authored-tool', 'version': '1'}})
    report = {'version': '1', 'pip_version': scan.BOOTSTRAP_PIP, 'environment': native_environment(),
              'install': [{'metadata': {'name': 'authored-tool', 'version': '1'}, 'is_yanked': False,
                           'download_info': {'url': 'https://files.pythonhosted.org/packages/tool.whl',
                                             'archive_info': {'hashes': {'sha256': 'a' * 64}}}}]}
    with pytest.raises(scan.EvidenceError):
        scan.validate_installation(final, record['identity'], [report], tmp_path)
    scan.validate_installation(final, record['identity'], [report], tmp_path, bootstrap=record)
    assert next(row for row in final['installed'] if row['metadata']['name'] == 'pip')['metadata']['version'] == '26.3'


def test_bootstrap_command_requires_hash_and_only_pip(scan, tmp_path):
    assert scan.bootstrap_requirements_text() == (
        'pip==26.3 --hash=sha256:f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13\n')
    argv = scan.bootstrap_commands(tmp_path, 'scanner')['scanner-bootstrap-install']
    for flag in ('--require-hashes', '--no-deps', '--force-reinstall', '--upgrade', '--only-binary=:all:'):
        assert flag in argv
    assert argv[argv.index('-r') + 1] == str(tmp_path / 'bootstrap-pip.txt')
    assert not {'--ignore-installed', '--no-require-hashes', '--trusted-host'}.intersection(argv)


@pytest.mark.parametrize('static', [False, True])
def test_current_pipeline_cannot_qualify_complete_predecessor_receipts(scan, tmp_path, project, static):
    out = tmp_path / 'receipts'
    out.mkdir()
    expected = authored_evidence(scan, out, tmp_path, project, static=static)
    for path in out.iterdir():
        if path.is_file() and ('bootstrap' in path.name or 'prepared' in path.name):
            path.unlink()
    with pytest.raises(scan.EvidenceError):
        scan.validate_evidence(out, expected, tmp_path, project)


@pytest.mark.parametrize('profile', ['runtime', 'packaging', 'static'])
def test_every_current_profile_prepares_each_installer_before_third_party_packages(scan, tmp_path, project, profile):
    plan = list(scan.commands(tmp_path, tmp_path, project, profile))
    labels = ['scanner'] if profile == 'static' else ['scanner', 'profile']
    for label in labels:
        third_party = 'scanner-install' if label == 'scanner' else 'build-install'
        assert plan.index(label + '-bootstrap-inspect') < plan.index(label + '-bootstrap-install')
        assert plan.index(label + '-bootstrap-install') < plan.index(label + '-prepared-inspect')
        assert plan.index(label + '-prepared-inspect') < plan.index(third_party)
