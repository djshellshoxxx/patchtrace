"""Authored scanner/receipt controls only; no advisory service or native credit."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SHA = 'a' * 40
PROFILES = ('runtime', 'packaging')
PLATFORMS = ('ubuntu-latest', 'windows-latest')


@pytest.fixture
def scan():
    return importlib.import_module('tools.dependency_security')


@pytest.fixture
def project():
    return {
        'build-system': {'requires': ['setuptools>=75,<100']},
        'project': {
            'name': 'patchtrace', 'version': '0.1.0', 'dependencies': ['widget==2.0'],
            'optional-dependencies': {'search': ['finder==1.2'], 'rules': ['rule-engine==3.0'],
                                      'dev': ['builder>=6,<7']},
        },
    }


def inspected(root, *, packaging=False):
    packages = [('patchtrace', '0.1.0'), ('widget', '2.0'), ('finder', '1.2'),
                ('rule-engine', '3.0'), ('pip', '26.0'), ('setuptools', '85.0')]
    if packaging:
        packages.append(('builder', '6.2'))
    result = {'version': '1', 'pip_version': '26.0', 'environment': native_environment(),
              'installed': [{'metadata': {'name': name, 'version': version}}
                            for name, version in packages]}
    result['installed'][0]['direct_url'] = {'url': root.as_uri(), 'dir_info': {'editable': True}}
    return result


def native_environment():
    return {'platform_system': 'Linux', 'python_version': '3.12', 'python_full_version': '3.12.14',
            'implementation_name': 'cpython', 'implementation_version': '3.12.14',
            'platform_python_implementation': 'CPython', 'platform_machine': 'x86_64'}


def encoded(data):
    return json.dumps(data).encode()


def test_workflow_has_every_native_inventory_and_mandatory_unsuppressed_step():
    workflow = ROOT / '.github/workflows/dependency-security.yml'
    document = yaml.safe_load(workflow.read_text())
    triggers = document.get('on', document.get(True))
    assert set(triggers) == {'push', 'pull_request', 'workflow_dispatch'}
    assert not triggers['push'].get('paths')
    assert not triggers['pull_request'] or not triggers['pull_request'].get('paths')
    assert document['permissions'] == {'contents': 'read'}
    dependency = document['jobs']['dependency-audit']
    assert dependency['name'] == 'dependency-audit (${{ matrix.os }}, ${{ matrix.profile }})'
    assert dependency['strategy']['matrix'] == {'os': list(PLATFORMS), 'profile': list(PROFILES)}
    assert dependency['strategy']['fail-fast'] is False
    assert dependency['runs-on'] == '${{ matrix.os }}'
    for name, job in document['jobs'].items():
        assert 0 < job['timeout-minutes'] <= 30
        assert not job.get('continue-on-error') and not job.get('if')
        critical = 'Audit installed dependencies' if name == 'dependency-audit' else 'Static security scan'
        critical_steps = [s for s in job['steps'] if s.get('name') == critical]
        assert len(critical_steps) == 1
        step = critical_steps[0]
        assert 'tools.dependency_security' in step['run']
        assert ' validate ' in step['run']
        assert not step.get('if') and not step.get('continue-on-error')
        assert '||' not in step['run'] and 'continue-on-error' not in workflow.read_text()
        upload = next(s for s in job['steps'] if 'upload-artifact@' in s.get('uses', ''))
        assert upload['if'] == 'always()'
        assert upload['with']['if-no-files-found'] == 'error'
        for action in (s['uses'] for s in job['steps'] if 'uses' in s):
            assert len(action.rsplit('@', 1)[1]) == 40


def test_release_policy_requires_four_native_profiles_and_static():
    gate = importlib.import_module('tools.release_qualification')
    required = gate.requirements('desktop', ('windows', 'linux'))['.github/workflows/dependency-security.yml']
    assert required == {
        **{f'dependency-audit ({platform}, {profile})': ('Audit installed dependencies',)
           for platform in PLATFORMS for profile in PROFILES},
        'security-scan': ('Static security scan',),
    }


@pytest.mark.parametrize('profile', PROFILES)
def test_complete_actual_inventory_preserves_owned_distribution_and_audits_all_others(scan, tmp_path,
                                                                                     project, profile):
    inventory = inspected(tmp_path, packaging=profile == 'packaging')
    result = scan.validate_inventory(inventory, tmp_path, project, profile, 'Linux', 0)
    assert result['repository_owned']['name'] == 'patchtrace'
    assert result['repository_owned']['origin'] == tmp_path.as_uri()
    assert {d['name'] for d in result['auditable']} == {
        d['metadata']['name'] for d in inventory['installed'] if d['metadata']['name'] != 'patchtrace'}
    assert result['selected_extras'] == (['search', 'rules'] if profile == 'runtime' else ['dev', 'search', 'rules'])


@pytest.mark.parametrize('mutation', [
    'missing-owner', 'wrong-origin', 'not-editable', 'owner-version', 'duplicate',
    'foreign-direct', 'missing-extra', 'wrong-production-version', 'wrong-platform',
    'missing-build-backend', 'out-of-range-dev', 'unsafe-version', 'schema', 'broken-pip-check',
])
def test_inventory_refuses_unowned_or_incomplete_closure(scan, tmp_path, project, mutation):
    inventory = inspected(tmp_path, packaging=True)
    owner = inventory['installed'][0]
    check_exit = 0
    if mutation == 'missing-owner':
        inventory['installed'].pop(0)
    elif mutation == 'wrong-origin':
        owner['direct_url']['url'] = (tmp_path / 'unrelated').as_uri()
    elif mutation == 'not-editable':
        owner['direct_url']['dir_info']['editable'] = False
    elif mutation == 'owner-version':
        owner['metadata']['version'] = '0.2.0'
    elif mutation == 'duplicate':
        inventory['installed'].append({'metadata': {'name': 'Rule_Engine', 'version': '3.0'}})
    elif mutation == 'foreign-direct':
        inventory['installed'][1]['direct_url'] = {'url': 'https://example.invalid/widget.whl'}
    elif mutation == 'missing-extra':
        inventory['installed'].pop(2)
    elif mutation == 'wrong-production-version':
        inventory['installed'][1]['metadata']['version'] = '1.0'
    elif mutation == 'wrong-platform':
        inventory['environment']['platform_system'] = 'Windows'
    elif mutation == 'missing-build-backend':
        inventory['installed'] = [p for p in inventory['installed'] if p['metadata']['name'] != 'setuptools']
    elif mutation == 'out-of-range-dev':
        inventory['installed'][-1]['metadata']['version'] = '7.0'
    elif mutation == 'unsafe-version':
        inventory['installed'][1]['metadata']['version'] = '2.0\n--index-url=https://example.invalid/'
    elif mutation == 'schema':
        inventory['version'] = 1
    elif mutation == 'broken-pip-check':
        check_exit = 1
    with pytest.raises(scan.EvidenceError):
        scan.validate_inventory(inventory, tmp_path, project, 'packaging', 'Linux', check_exit)


def clean_audit():
    return {'dependencies': [{'name': 'widget', 'version': '2.0', 'vulns': []},
                             {'name': 'pip', 'version': '26.0', 'vulns': []}], 'fixes': []}


def test_audit_requires_exact_complete_inventory_and_empty_findings(scan):
    expected = [{'name': 'widget', 'version': '2.0'}, {'name': 'pip', 'version': '26.0'}]
    assert scan.validate_audit(clean_audit(), expected, 0) == 2


@pytest.mark.parametrize('mutation', [
    'nonzero', 'missing', 'unexpected', 'duplicate', 'wrong-version', 'skipped',
    'finding', 'fixed', 'shape', 'bool-exit', 'missing-exit',
])
def test_audit_never_treats_failure_skips_or_incomplete_coverage_as_clean(scan, mutation):
    result = clean_audit()
    exit_code = 0
    if mutation == 'nonzero':
        exit_code = 1
    elif mutation == 'missing':
        result['dependencies'].pop()
    elif mutation == 'unexpected':
        result['dependencies'].append({'name': 'extra', 'version': '1', 'vulns': []})
    elif mutation == 'duplicate':
        result['dependencies'].append(copy.deepcopy(result['dependencies'][0]))
    elif mutation == 'wrong-version':
        result['dependencies'][0]['version'] = '1.0'
    elif mutation == 'skipped':
        result['dependencies'][0] = {'name': 'widget', 'skip_reason': 'advisory lookup unavailable'}
    elif mutation == 'finding':
        result['dependencies'][0]['vulns'] = [{'id': 'AUTHORED-1', 'fix_versions': ['3']}]
    elif mutation == 'fixed':
        result['fixes'] = [{'name': 'widget', 'old_version': '2.0', 'new_version': '3'}]
    elif mutation == 'shape':
        result = []
    elif mutation == 'bool-exit':
        exit_code = False
    elif mutation == 'missing-exit':
        exit_code = None
    with pytest.raises(scan.EvidenceError):
        scan.validate_audit(result, [{'name': 'widget', 'version': '2.0'}, {'name': 'pip', 'version': '26.0'}],
                            exit_code)


@pytest.mark.parametrize(('data', 'exit_code'), [([], 1), ([{'code': 'S314'}], 0), ({}, 0), ([], None), ([], False)])
def test_static_scanner_failure_or_findings_cannot_be_overridden_by_empty_json(scan, data, exit_code):
    with pytest.raises(scan.EvidenceError):
        scan.validate_static(data, exit_code)


def test_static_empty_real_success_is_accepted(scan):
    scan.validate_static([], 0)


@pytest.mark.parametrize('raw', [b'{"x": 1, "x": 2}', b'{"x": 1e999}', b'{"x": -1e999}',
                                b'{"x": NaN}', b'[] trailing', b'\xff', b'[' * 100 + b']' * 100])
def test_receipts_refuse_ambiguous_nonfinite_or_deep_json(scan, tmp_path, raw):
    path = tmp_path / 'evidence.json'
    path.write_bytes(raw)
    with pytest.raises(scan.EvidenceError):
        scan.read_json(path)


def test_receipts_refuse_missing_and_oversized_json(scan, tmp_path):
    with pytest.raises(scan.EvidenceError):
        scan.read_json(tmp_path / 'missing.json')
    path = tmp_path / 'large.json'
    path.write_bytes(b' ' * (scan.MAX_JSON + 1))
    with pytest.raises(scan.EvidenceError):
        scan.read_json(path)


@pytest.mark.parametrize('field', ['repository', 'source_sha', 'source_tree', 'workflow', 'run_id',
                                   'run_attempt', 'platform', 'profile', 'origin', 'event'])
def test_receipt_identity_must_match_each_actual_owner_field(scan, field):
    expected = {'repository': 'owner/repo', 'source_sha': SHA, 'source_tree': 'b' * 40,
                'workflow': '.github/workflows/dependency-security.yml', 'run_id': 123, 'run_attempt': 2,
                'platform': 'ubuntu-latest', 'profile': 'runtime', 'origin': 'github-actions', 'event': 'push'}
    changed = copy.deepcopy(expected)
    changed[field] = 'wrong'
    with pytest.raises(scan.EvidenceError):
        scan.validate_context(changed, expected)
    with pytest.raises(scan.EvidenceError):
        scan.validate_context({key: value for key, value in expected.items() if key != field}, expected)


def test_missing_evidence_cannot_qualify_even_with_a_passed_verdict(scan, tmp_path, project):
    (tmp_path / 'verdict.json').write_text('{"status": "passed"}')
    with pytest.raises(scan.EvidenceError):
        scan.validate_evidence(tmp_path, {}, tmp_path, project)


def test_raw_command_failure_and_output_are_preserved(scan, tmp_path):
    argv = [sys.executable, '-I', '-c',
            'import sys; sys.stdout.buffer.write(b"raw\\n"); sys.stderr.buffer.write(b"failure\\n"); sys.exit(3)']
    result = scan.run_logged(argv, tmp_path, 'authored', timeout=10)
    assert result['exit_code'] == 3
    assert result['argv'] == argv
    assert (tmp_path / 'authored.stdout').read_bytes() == b'raw\n'
    assert (tmp_path / 'authored.stderr').read_bytes() == b'failure\n'
    assert scan.read_json(tmp_path / 'authored.process.json') == result


def test_command_refuses_to_replace_prior_receipts(scan, tmp_path):
    prior = tmp_path / 'authored.stdout'
    prior.write_bytes(b'preserved evidence')
    with pytest.raises(scan.EvidenceError):
        scan.run_logged([sys.executable, '-I', '-c', 'print("replacement")'], tmp_path, 'authored', timeout=10)
    assert prior.read_bytes() == b'preserved evidence'


def test_command_output_limit_is_failed_and_retains_bounded_raw_bytes(scan, tmp_path):
    result = scan.run_logged([sys.executable, '-I', '-c', 'print("x" * 100000)'], tmp_path,
                             'bounded', timeout=10, limit=1000)
    assert result['output_limited'] is True
    assert result['exit_code'] != 0 or result['output_limited']
    assert 0 < (tmp_path / 'bounded.stdout').stat().st_size <= 1000


def test_scanner_commands_are_pinned_strict_and_have_no_suppression(scan, tmp_path):
    audit = scan.audit_argv('python', tmp_path)
    for flag in ('--strict', '--no-deps', '--disable-pip'):
        assert flag in audit
    assert audit[audit.index('--vulnerability-service') + 1] == 'pypi'
    assert audit[audit.index('--timeout') + 1] == '15'
    assert not {'--ignore-vuln', '--skip-editable', '--fix', '--dry-run'}.intersection(audit)
    static = scan.static_argv('python', tmp_path)
    for flag in ('--isolated', '--ignore-noqa', '--no-cache', '--no-respect-gitignore'):
        assert flag in static
    assert static[static.index('--select') + 1] == 'S'
    assert not {'--ignore', '--per-file-ignores', '--exit-zero', '--fix', '--unsafe-fixes'}.intersection(static)
    assert scan.PINS == {'pip-audit': '2.10.1', 'ruff': '0.17.5'}


def test_identity_does_not_accept_boolean_or_float_as_integer(scan):
    for changed in (True, 1.0):
        with pytest.raises(scan.EvidenceError):
            scan.validate_context({'run_attempt': changed}, {'run_attempt': 1})


def test_missing_command_timing_cannot_be_fabricated_as_a_pass(scan, tmp_path):
    argv = [sys.executable, '-I', '-c', 'pass']
    scan.run_logged(argv, tmp_path, 'authored', timeout=10)
    path = tmp_path / 'authored.process.json'
    receipt = scan.read_json(path)
    receipt.pop('elapsed_s')
    path.write_text(json.dumps(receipt))
    with pytest.raises(scan.EvidenceError):
        scan.process_receipt(tmp_path, 'authored', argv)


def test_stale_command_receipt_cannot_be_counted_as_current(scan, tmp_path):
    argv = [sys.executable, '-I', '-c', 'pass']
    scan.run_logged(argv, tmp_path, 'authored', timeout=10)
    path = tmp_path / 'authored.process.json'
    receipt = scan.read_json(path)
    receipt['started_at'] = (dt.datetime.now(dt.UTC) - dt.timedelta(days=2)).isoformat()
    path.write_text(json.dumps(receipt))
    with pytest.raises(scan.EvidenceError):
        scan.process_receipt(tmp_path, 'authored', argv)


def test_changed_command_raw_output_is_not_a_pass(scan, tmp_path):
    argv = [sys.executable, '-I', '-c', 'pass']
    scan.run_logged(argv, tmp_path, 'authored', timeout=10)
    (tmp_path / 'authored.stdout').write_bytes(b'changed')
    with pytest.raises(scan.EvidenceError):
        scan.process_receipt(tmp_path, 'authored', argv)


def installation_report(packages, root, *, pip_version='26.0'):
    rows = []
    for name, version in packages:
        info = ({'url': root.as_uri(), 'dir_info': {'editable': True}} if name == 'patchtrace' else
                {'url': f'https://files.pythonhosted.org/packages/{name}-{version}-py3-none-any.whl',
                 'archive_info': {'hashes': {'sha256': 'f' * 64}}})
        rows.append({'metadata': {'name': name, 'version': version}, 'download_info': info, 'is_yanked': False})
    return {'version': '1', 'pip_version': pip_version, 'environment': native_environment(), 'install': rows}


def authored_bootstrap(scan, out, label, identity):
    before = {'version': '1', 'pip_version': identity['ensurepip'], 'environment': native_environment(),
              'installed': [{'metadata': {'name': 'pip', 'version': identity['ensurepip']}}]}
    after = copy.deepcopy(before)
    after['pip_version'] = after['installed'][0]['metadata']['version'] = scan.BOOTSTRAP_PIP
    report = installation_report([('pip', scan.BOOTSTRAP_PIP)], out, pip_version=identity['ensurepip'])
    report['install'][0].update({'requested': True, 'is_direct': False, 'download_info': {
        'url': scan.BOOTSTRAP_WHEEL_URL, 'archive_info': {'hashes': {'sha256': scan.BOOTSTRAP_WHEEL_SHA256}}}})
    (out / f'{label}-bootstrap-identity.stdout').write_bytes(encoded(identity))
    (out / f'{label}-bootstrap-inspect.stdout').write_bytes(encoded(before))
    (out / f'{label}-bootstrap-install.json').write_bytes(encoded(report))
    (out / f'{label}-prepared-inspect.stdout').write_bytes(encoded(after))


def authored_evidence(scan, out, root, project, *, static=False):
    """Complete positive schema fixture; it is explicitly not an executed scan."""
    expected = {'profile': 'static' if static else 'runtime', 'platform': 'ubuntu-latest', 'source_sha': SHA}
    plan = scan.commands(out, root, project, expected['profile'])
    for name, argv in plan.items():
        stdout, stderr = out / f'{name}.stdout', out / f'{name}.stderr'
        stdout.write_bytes(b'')
        stderr.write_bytes(b'')
        receipt = {'argv': argv, 'exit_code': 0, 'timed_out': False, 'output_limited': False, 'error': None,
                   'started_at': dt.datetime.now(dt.UTC).isoformat(), 'timeout_s': 600, 'elapsed_s': 0.1}
        (out / f'{name}.process.json').write_text(json.dumps(receipt))
    tooling = {'version': '1', 'pip_version': scan.BOOTSTRAP_PIP, 'environment': native_environment(),
               'installed': [{'metadata': {'name': name, 'version': version}}
                             for name, version in [('pip', scan.BOOTSTRAP_PIP), ('ruff', '0.17.5'),
                                                   ('pip-audit', '2.10.1')]]}
    (out / 'scanner-inspect.stdout').write_bytes(encoded(tooling))
    (out / 'scanner-install.json').write_bytes(encoded(installation_report(
        [('ruff', '0.17.5'), ('pip-audit', '2.10.1')], root, pip_version=scan.BOOTSTRAP_PIP)))
    (out / 'unaudited.json').write_bytes(encoded(scan.UNAUDITED))
    (out / 'context.json').write_bytes(encoded(expected))
    (out / 'bootstrap-pip.txt').write_text(scan.bootstrap_requirements_text())
    environments = ['scanner'] if static else ['scanner', 'profile']
    for label in environments:
        identity = {'executable': scan.python_path(out, f'{label}-env'), 'version': '3.12.14',
                    'prefix': str(out / f'{label}-env'), 'base_prefix': str(out / 'controller'),
                    'implementation': 'CPython', 'system': 'Linux', 'machine': 'x86_64', 'ensurepip': '26.0'}
        (out / f'{label}-identity.stdout').write_bytes(encoded(identity))
        authored_bootstrap(scan, out, label, identity)
    if static:
        (out / 'static.stdout').write_bytes(b'[]')
    else:
        inspect = inspected(root)
        inspect['pip_version'] = scan.BOOTSTRAP_PIP
        next(row for row in inspect['installed'] if row['metadata']['name'] == 'pip')['metadata']['version'] = (
            scan.BOOTSTRAP_PIP)
        inventory = scan.validate_inventory(inspect, root, project, 'runtime', 'Linux', 0)
        (out / 'profile-inspect.stdout').write_bytes(encoded(inspect))
        (out / 'inventory.json').write_bytes(encoded(inventory))
        (out / 'audit-requirements.txt').write_text(scan.requirements_text(inventory))
        (out / 'build-install.json').write_bytes(encoded(installation_report(
            [('setuptools', '85.0')], root, pip_version=scan.BOOTSTRAP_PIP)))
        pairs = [(row['metadata']['name'], row['metadata']['version']) for row in inspect['installed']
                 if row['metadata']['name'] not in {'setuptools', 'pip'}]
        (out / 'profile-install.json').write_bytes(encoded(installation_report(
            pairs, root, pip_version=scan.BOOTSTRAP_PIP)))
        (out / 'audit.stdout').write_bytes(encoded({'dependencies': [dict(row, vulns=[])
                                                                    for row in inventory['auditable']], 'fixes': []}))
    for name in plan:
        path = out / f'{name}.process.json'
        receipt = json.loads(path.read_text())
        receipt.update({f'{stream}_sha256': hashlib.sha256((out / f'{name}.{stream}').read_bytes()).hexdigest()
                        for stream in ('stdout', 'stderr')})
        path.write_bytes(encoded(receipt))
    return expected


@pytest.mark.parametrize('static', [False, True])
def test_independent_validation_requires_all_raw_evidence(scan, tmp_path, project, static):
    out = tmp_path / 'evidence'
    out.mkdir()
    expected = authored_evidence(scan, out, tmp_path, project, static=static)
    assert scan.validate_evidence(out, expected, tmp_path, project)['kind'] == ('static' if static else 'dependency')
    (out / 'scanner-install.json').unlink()
    with pytest.raises(scan.EvidenceError):
        scan.validate_evidence(out, expected, tmp_path, project)


@pytest.mark.parametrize('mutation', ['missing', 'different-version', 'yanked', 'foreign-origin', 'no-hash',
                                     'bootstrap', 'duplicate', 'wrong-owner'])
def test_installation_proof_refuses_incomplete_or_foreign_origins(scan, tmp_path, project, mutation):
    out = tmp_path / 'evidence'
    out.mkdir()
    expected = authored_evidence(scan, out, tmp_path, project)
    path = out / 'profile-install.json'
    report = json.loads(path.read_text())
    if mutation == 'missing':
        report['install'].pop()
    elif mutation == 'different-version':
        report['install'][-1]['metadata']['version'] = '999'
    elif mutation == 'yanked':
        report['install'][-1]['is_yanked'] = True
    elif mutation == 'foreign-origin':
        report['install'][-1]['download_info']['url'] = 'https://example.invalid/foreign.whl'
    elif mutation == 'no-hash':
        report['install'][-1]['download_info']['archive_info']['hashes'].clear()
    elif mutation == 'bootstrap':
        report['install'].append(installation_report([('pip', '25.0')], tmp_path)['install'][0])
    elif mutation == 'duplicate':
        report['install'].append(copy.deepcopy(report['install'][-1]))
    elif mutation == 'wrong-owner':
        report['install'][0]['download_info']['url'] = (tmp_path / 'foreign').as_uri()
    path.write_bytes(encoded(report))
    with pytest.raises(scan.EvidenceError):
        scan.validate_evidence(out, expected, tmp_path, project)


def authored_repository(root):
    def git(*args):
        return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout.decode().strip()

    root.mkdir()
    git('init', '-q')
    git('config', 'user.name', 'Authored control')
    git('config', 'user.email', 'authored@example.invalid')
    (root / 'src').mkdir()
    (root / 'src' / 'example.py').write_text('VALUE = 1\n')
    git('add', 'src')
    git('commit', '-qm', 'Authored scan source [no release]')
    return git, git('rev-parse', 'HEAD')


def test_scanning_a_held_commit_does_not_change_publication_hold(scan, tmp_path):
    root = tmp_path / 'repo'
    git, sha = authored_repository(root)
    assert scan.checked_tree(root, sha) == git('rev-parse', 'HEAD^{tree}')
    with pytest.raises(scan.EvidenceError, match=r'\[no release\]'):
        importlib.import_module('tools.release_qualification').checked_source(root, sha)


@pytest.fixture
def host_crlf_text(monkeypatch):
    """Author the same default-newline translation that Windows text I/O applies."""
    original = Path.write_text

    def write(path, data, *args, **kwargs):
        if kwargs.get('newline') is None:
            kwargs['newline'] = '\r\n'
        return original(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, 'write_text', write)


@pytest.mark.parametrize('static,receipt', [(False, 'bootstrap-pip.txt'), (True, 'bootstrap-pip.txt'),
                                           (False, 'audit-requirements.txt')])
def test_authored_receipts_remain_exact_under_host_text_newlines(scan, tmp_path, project,
                                                               host_crlf_text, static, receipt):
    out = tmp_path / 'evidence'
    out.mkdir()
    expected = authored_evidence(scan, out, tmp_path, project, static=static)
    wanted = scan.bootstrap_requirements_text() if receipt == 'bootstrap-pip.txt' else (
        scan.requirements_text(json.loads((out / 'inventory.json').read_bytes())))
    assert (out / receipt).read_bytes() == wanted.encode('utf-8')
    assert scan.validate_evidence(out, expected, tmp_path, project)['kind'] == (
        'static' if static else 'dependency')


@pytest.mark.parametrize('autocrlf', ['true', 'false'])
def test_authored_repository_survives_host_git_normalization(scan, tmp_path, monkeypatch,
                                                            host_crlf_text, autocrlf):
    config = tmp_path / 'authored.gitconfig'
    config.write_bytes(f'[core]\n\tautocrlf = {autocrlf}\n\teol = crlf\n'.encode('ascii'))
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', str(config))
    monkeypatch.setenv('GIT_CONFIG_NOSYSTEM', '1')
    root = tmp_path / 'repo'
    git, sha = authored_repository(root)
    working = (root / 'src/example.py').read_bytes()
    committed = subprocess.check_output(['git', '-C', str(root), 'show', f'{sha}:src/example.py'])
    setting = git('config', '--show-origin', '--get', 'core.autocrlf')
    assert working == committed == b'VALUE = 1\n', (working, committed, setting)
    assert git('config', '--local', '--get', 'core.autocrlf') == 'false'
    assert scan.checked_tree(root, sha) == git('rev-parse', 'HEAD^{tree}')
    with pytest.raises(scan.EvidenceError, match=r'\[no release\]'):
        importlib.import_module('tools.release_qualification').checked_source(root, sha)


@pytest.mark.parametrize('hide', ['assume-unchanged', 'skip-worktree', 'replace', 'untracked'])
def test_source_identity_never_uses_hidden_index_or_replacement_bytes(scan, tmp_path, hide):
    root = tmp_path / 'repo'
    git, sha = authored_repository(root)
    if hide in {'assume-unchanged', 'skip-worktree'}:
        git('update-index', f'--{hide}', 'src/example.py')
    if hide == 'untracked':
        (root / 'src' / 'extra.py').write_text('EXTRA = True\n')
    else:
        (root / 'src' / 'example.py').write_text('VALUE = 2\n')
    if hide == 'replace':
        git('add', 'src')
        git('commit', '-qm', 'Different authored source')
        replacement = git('rev-parse', 'HEAD')
        git('update-ref', 'HEAD', sha)
        git('replace', sha, replacement)
    with pytest.raises(scan.EvidenceError):
        scan.checked_tree(root, sha)


@pytest.mark.skipif(os.name == 'nt', reason='POSIX-created symlink control; native Windows inventory remains required')
def test_source_scanner_does_not_follow_tracked_outside_symlink(scan, tmp_path):
    root = tmp_path / 'repo'
    git, _ = authored_repository(root)
    external = tmp_path / 'outside.py'
    external.write_text('VALUE = 1\n')
    (root / 'src' / 'example.py').unlink()
    (root / 'src' / 'example.py').symlink_to(external)
    git('add', 'src')
    git('commit', '-qm', 'Authored external symlink')
    with pytest.raises(scan.EvidenceError):
        scan.checked_tree(root, git('rev-parse', 'HEAD'))


@pytest.mark.parametrize('field', ['python_full_version', 'python_version', 'platform_system',
                                   'platform_machine', 'implementation_name', 'implementation_version',
                                   'platform_python_implementation'])
@pytest.mark.parametrize('mutation', ['missing', 'wrong', 'wrong-type'])
def test_inventory_requires_complete_matching_native_interpreter_metadata(scan, tmp_path, field, mutation):
    identity = {'executable': str(tmp_path / 'env/bin/python'), 'prefix': str(tmp_path / 'env'),
                'base_prefix': str(tmp_path / 'base'), 'version': '3.12.14', 'implementation': 'CPython',
                'system': 'Linux', 'machine': 'x86_64', 'ensurepip': '26.0'}
    inspect = inspected(tmp_path)
    if mutation == 'missing':
        inspect['environment'].pop(field)
    else:
        inspect['environment'][field] = 'unrelated' if mutation == 'wrong' else None
    with pytest.raises(scan.EvidenceError):
        scan.validate_interpreter(identity, identity['executable'], 'Linux', inspect)


@pytest.mark.parametrize('field', ['version', 'implementation', 'machine', 'executable', 'prefix',
                                   'base_prefix', 'system', 'ensurepip'])
def test_interpreter_identity_missing_fields_are_not_verified(scan, tmp_path, field):
    identity = {'executable': str(tmp_path / 'env/bin/python'), 'prefix': str(tmp_path / 'env'),
                'base_prefix': str(tmp_path / 'base'), 'version': '3.12.14', 'implementation': 'CPython',
                'system': 'Linux', 'machine': 'x86_64', 'ensurepip': '26.0'}
    python = identity['executable']
    identity.pop(field)
    with pytest.raises(scan.EvidenceError):
        scan.validate_interpreter(identity, python, 'Linux', inspected(tmp_path))


@pytest.mark.parametrize(('where', 'mutation'), [
    ('inspect-pip', 'different'), ('report-pip', 'different'), ('report-pip', 'missing'),
    ('report-environment', 'different'), ('report-environment', 'missing'),
    ('report-environment', 'incomplete'), ('report-environment', 'wrong-type'),
])
def test_installation_requires_same_pip_and_complete_environment(scan, tmp_path, project, where, mutation):
    out = tmp_path / 'evidence'
    out.mkdir()
    authored_evidence(scan, out, tmp_path, project)
    inspect = scan.read_json(out / 'profile-inspect.stdout')
    identity = scan.read_json(out / 'profile-identity.stdout')
    reports = [scan.read_json(out / 'build-install.json'), scan.read_json(out / 'profile-install.json')]
    bootstrap = scan.bootstrap_record(out, 'profile')
    scan.validate_installation(inspect, identity, reports, tmp_path, owned=True, bootstrap=bootstrap)
    if where == 'inspect-pip':
        inspect['pip_version'] = '27.0'
    elif where == 'report-pip':
        if mutation == 'missing':
            reports[0].pop('pip_version')
        else:
            reports[0]['pip_version'] = '27.0'
    elif mutation == 'missing':
        reports[0].pop('environment')
    elif mutation == 'incomplete':
        reports[0]['environment'].pop('platform_machine')
    elif mutation == 'wrong-type':
        reports[0]['environment']['platform_machine'] = None
    else:
        reports[0]['environment']['platform_system'] = 'Windows'
    with pytest.raises(scan.EvidenceError):
        scan.validate_installation(inspect, identity, reports, tmp_path, owned=True, bootstrap=bootstrap)


@pytest.mark.parametrize('requirement', ['--prefix=/unrelated', 'tool @ https://example.invalid/tool.whl',
                                       'tool>=1; python_version > "3.10"', 'tool[extra]==1'])
def test_unhandled_requirement_cannot_reach_an_installer_command(scan, tmp_path, project, requirement):
    project['build-system']['requires'] = [requirement]
    with pytest.raises(scan.EvidenceError):
        scan.commands(tmp_path, tmp_path, project, 'runtime')


@pytest.mark.parametrize('bad', [None, [], 'missing'])
def test_malformed_interpreter_inputs_are_refused_with_a_receipt_error(scan, tmp_path, bad):
    identity = {'executable': str(tmp_path / 'env/bin/python'), 'prefix': str(tmp_path / 'env'),
                'base_prefix': str(tmp_path / 'base'), 'version': '3.12.14', 'implementation': 'CPython',
                'system': 'Linux', 'machine': 'x86_64', 'ensurepip': '26.0'}
    with pytest.raises(scan.EvidenceError):
        scan.validate_interpreter(identity, identity['executable'], 'Linux', bad)
    with pytest.raises(scan.EvidenceError):
        scan.validate_installation(inspected(tmp_path), bad, [], tmp_path)
