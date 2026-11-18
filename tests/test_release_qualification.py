"""Authored REST metadata/artifacts only; never live or native qualification."""
from __future__ import annotations

import copy
import importlib
import io
import json
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
REPO = 'owner/patchtrace'
SHA = 'a' * 40
START = '2026-11-18T10:00:00Z'
FINISH = '2026-11-18T10:10:00Z'


@pytest.mark.parametrize('workflow,job', [('qa-windows.yml', 'release'), ('backend-bundle.yml', 'pub')])
def test_publishers_require_shared_guard_before_mutation(workflow, job):
    document = yaml.safe_load((ROOT / '.github/workflows' / workflow).read_text())
    steps = document['jobs'][job]['steps']
    guards = [i for i, s in enumerate(steps) if 'release_qualification.py' in s.get('run', '')]
    mutations = [i for i, s in enumerate(steps)
                 if 'action-gh-release@' in s.get('uses', '') or 'gh release create' in s.get('run', '')]
    assert len(guards) == 1 and mutations and guards[0] < min(mutations)
    assert not steps[guards[0]].get('continue-on-error', False)
    assert document['jobs'][job]['permissions']['actions'] == 'read'


def test_publishers_never_replace_existing_release_assets():
    bundle = (ROOT / '.github/workflows/backend-bundle.yml').read_text()
    desktop = yaml.safe_load((ROOT / '.github/workflows/qa-windows.yml').read_text())
    assert '--clobber' not in bundle
    publisher = next(s for s in desktop['jobs']['release']['steps'] if 'action-gh-release@' in s.get('uses', ''))
    assert publisher['with']['overwrite_files'] is False


@pytest.fixture
def gate():
    return importlib.import_module('tools.release_qualification')


class AuthoredAPI:
    def __init__(self, gate, profile='desktop'):
        self.repo = REPO
        self.commit_record = {'sha': SHA, 'commit': {'message': 'Reviewed release candidate'}}
        self.runs_data, self.jobs_data, self.artifacts_data, self.blobs = [], {}, {}, {}
        self.refs_data, self.releases_data, self.tags_data = [], [], {}
        self.calls = []
        for index, (path, jobs) in enumerate(gate.requirements(profile, ('windows', 'linux')).items(), 1):
            run = {'id': index, 'workflow_id': index + 100, 'path': path, 'event': 'push',
                   'head_sha': SHA, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success',
                   'repository': {'full_name': REPO, 'id': 10},
                   'head_repository': {'full_name': REPO, 'id': 10}, 'run_started_at': START}
            self.runs_data.append(run)
            self.jobs_data[index] = [
                {'id': index * 100 + j, 'run_id': index, 'run_attempt': 1, 'head_sha': SHA,
                 'run_url': f'https://api.github.com/repos/{REPO}/actions/runs/{index}',
                 'name': name, 'status': 'completed', 'conclusion': 'success',
                 'started_at': START, 'completed_at': FINISH,
                 'steps': [{'name': step, 'number': k, 'status': 'completed', 'conclusion': 'success'}
                           for k, step in enumerate(critical, 1)]}
                for j, (name, critical) in enumerate(jobs.items(), 1)]
            if path.endswith('live-bindiff.yml'):
                for os_name in ('linux', 'windows'):
                    artifact_id = index * 1000 + len(self.artifacts_data.get(index, []))
                    self.artifacts_data.setdefault(index, []).append({
                        'id': artifact_id, 'name': f'live-bindiff-{os_name}', 'expired': False,
                        'size_in_bytes': 1000, 'created_at': '2026-11-18T10:05:00Z',
                        'workflow_run': {'id': index, 'head_sha': SHA, 'repository_id': 10,
                                         'head_repository_id': 10}})
                    self.blobs[artifact_id] = self.archive({'engine': 'bindiff', 'status': 'passed',
                        'mocked': False, 'checks': {name: {'status': 'passed'} for name in gate.BINDIFF_CHECKS}})
        expected = '.github/workflows/' + ('qa-windows.yml' if profile == 'desktop' else 'backend-bundle.yml')
        self.current = next(r['id'] for r in self.runs_data if r['path'] == expected)
        self.run(self.current)['status'], self.run(self.current)['conclusion'] = 'in_progress', None

    @staticmethod
    def archive(document):
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as bundle:
            bundle.writestr('bindiff.json', json.dumps(document))
        return out.getvalue()

    def commit(self, sha):
        assert sha == SHA
        return copy.deepcopy(self.commit_record)

    def runs(self, sha):
        assert sha == SHA
        self.calls.append('runs')
        return copy.deepcopy(self.runs_data)

    def run(self, run_id):
        return next(r for r in self.runs_data if r['id'] == run_id)

    def jobs(self, run_id, attempt):
        assert attempt == self.run(run_id)['run_attempt']
        return copy.deepcopy(self.jobs_data[run_id])

    def artifacts(self, run_id):
        return copy.deepcopy(self.artifacts_data.get(run_id, []))

    def artifact_bytes(self, artifact_id):
        return self.blobs[artifact_id]

    def refs(self, tag):
        return copy.deepcopy(self.refs_data)

    def releases(self):
        return copy.deepcopy(self.releases_data)

    def release_assets(self, release_id):
        return copy.deepcopy(next(r['assets'] for r in self.releases_data if r['id'] == release_id))

    def tag(self, sha):
        return copy.deepcopy(self.tags_data[sha])


def assess(gate, api, **options):
    return gate.qualify(api, sha=SHA, current_run=api.current, profile=options.pop('profile', 'desktop'),
                        platforms=('windows', 'linux'), tag='v0.1.0-beta.1', assets={'new.zip'}, **options)


@pytest.mark.parametrize('profile', ['desktop', 'bundle'])
def test_complete_authored_evidence_can_pass_without_a_publish_operation(gate, profile):
    api = AuthoredAPI(gate, profile)
    result = assess(gate, api, profile=profile)
    assert result['qualified'] and not result['blockers']
    assert result['head_sha'] == SHA and result['repository'] == REPO
    assert api.calls.count('runs') == 2


@pytest.mark.parametrize('state', ['missing', 'queued', 'skipped', 'failure', 'cancelled', 'neutral'])
def test_missing_or_incomplete_mandatory_job_never_qualifies(gate, state):
    api = AuthoredAPI(gate)
    if state == 'missing':
        api.jobs_data[api.current].pop()
    else:
        job = api.jobs_data[api.current][0]
        job['status'], job['conclusion'] = ('queued', None) if state == 'queued' else ('completed', state)
    assert not assess(gate, api)['qualified']


@pytest.mark.parametrize('change', ['sha', 'repo', 'fork', 'preview', 'attempt', 'duplicate', 'path'])
def test_foreign_stale_or_ambiguous_run_and_job_identity_is_refused(gate, change):
    api = AuthoredAPI(gate)
    run = api.runs_data[1]
    if change == 'sha':
        run['head_sha'] = 'b' * 40
    elif change == 'repo':
        run['repository']['full_name'] = 'someone/else'
    elif change == 'fork':
        run['head_repository']['full_name'] = 'someone/else'
    elif change == 'preview':
        run['event'] = 'pull_request'
    elif change == 'attempt':
        api.jobs_data[run['id']][0]['run_attempt'] = 0
    elif change == 'duplicate':
        api.jobs_data[run['id']].append(copy.deepcopy(api.jobs_data[run['id']][0]))
    else:
        run['path'] = '.github/workflows/unrelated.yml'
    assert not assess(gate, api)['qualified']


def test_newer_failed_attempt_cannot_fall_back_to_an_older_success(gate):
    api = AuthoredAPI(gate)
    newer = copy.deepcopy(api.runs_data[1])
    newer.update(id=999, status='completed', conclusion='failure')
    api.runs_data.append(newer)
    assert not assess(gate, api)['qualified']


def test_missing_security_workflow_is_an_explicit_blocker(gate):
    api = AuthoredAPI(gate)
    api.runs_data = [r for r in api.runs_data if not r['path'].endswith('dependency-security.yml')]
    result = assess(gate, api)
    assert not result['qualified'] and any('dependency-security' in reason for reason in result['blockers'])


@pytest.mark.parametrize('critical', ['missing', 'failure', 'skipped'])
def test_advisory_job_success_does_not_override_critical_step(gate, critical):
    api = AuthoredAPI(gate)
    run = next(r for r in api.runs_data if r['path'].endswith('live-bindiff.yml'))
    step = api.jobs_data[run['id']][0]['steps'][0]
    if critical == 'missing':
        step['name'] = 'different check'
    else:
        step['conclusion'] = critical
    assert not assess(gate, api)['qualified']


@pytest.mark.parametrize('damage', ['blocked', 'mocked', 'subcheck', 'expired', 'old', 'sha', 'duplicate', 'bad-json'])
def test_green_advisory_badge_requires_owned_unmocked_native_report(gate, damage):
    api = AuthoredAPI(gate)
    run_id = next(iter(api.artifacts_data))
    artifact = api.artifacts_data[run_id][0]
    report = {'engine': 'bindiff', 'status': 'passed', 'mocked': False,
              'checks': {name: {'status': 'passed'} for name in gate.BINDIFF_CHECKS}}
    if damage == 'blocked':
        report['status'] = 'blocked'
    if damage == 'mocked':
        report['mocked'] = True
    if damage == 'subcheck':
        report['checks']['no_network']['status'] = 'blocked'
    if damage == 'expired':
        artifact['expired'] = True
    if damage == 'old':
        artifact['created_at'] = '2026-11-17T10:05:00Z'
    if damage == 'sha':
        artifact['workflow_run']['head_sha'] = 'b' * 40
    if damage == 'duplicate':
        api.artifacts_data[run_id].append(copy.deepcopy(artifact))
    api.blobs[artifact['id']] = b'not a zip' if damage == 'bad-json' else api.archive(report)
    assert not assess(gate, api)['qualified']


@pytest.mark.parametrize('profile', ['desktop', 'bundle'])
def test_actual_commit_hold_applies_without_push_event_payload(gate, profile):
    api = AuthoredAPI(gate, profile)
    api.commit_record['commit']['message'] = 'Integration\n\n[no release]'
    result = assess(gate, api, profile=profile)
    assert not result['qualified'] and any('[no release]' in reason for reason in result['blockers'])


@pytest.mark.parametrize('kind', ['wrong-tag', 'draft', 'stable-release', 'asset-collision', 'tag-cycle'])
def test_existing_release_identity_and_assets_are_preserved(gate, kind):
    api = AuthoredAPI(gate)
    target = 'b' * 40 if kind == 'wrong-tag' else SHA
    api.refs_data = [{'ref': 'refs/tags/v0.1.0-beta.1', 'object': {'type': 'commit', 'sha': target}}]
    api.releases_data = [{'id': 900, 'tag_name': 'v0.1.0-beta.1', 'draft': kind == 'draft',
                          'prerelease': kind != 'stable-release', 'assets':
                          [{'name': 'new.zip'}] if kind == 'asset-collision' else []}]
    if kind == 'tag-cycle':
        api.refs_data[0]['object']['type'] = 'tag'
        api.tags_data[SHA] = {'sha': SHA, 'object': {'type': 'tag', 'sha': SHA}}
    assert not assess(gate, api)['qualified']


def existing_release(api):
    api.refs_data = [{'ref': 'refs/tags/v0.1.0-beta.1', 'object': {'type': 'commit', 'sha': SHA}}]
    api.releases_data = [{'id': 900, 'tag_name': 'v0.1.0-beta.1', 'draft': False,
                          'prerelease': True, 'assets': [{'name': 'previous.zip'}]}]


def test_matching_prerelease_reuses_only_new_asset_names(gate):
    api = AuthoredAPI(gate)
    existing_release(api)
    result = assess(gate, api)
    assert result['qualified'] and result['destination']['release_exists']
    assert api.releases_data[0]['assets'] == [{'name': 'previous.zip'}]


@pytest.mark.parametrize('damage', ['repository-id', 'job-attempt-bool', 'job-run-id-bool',
                                   'nameless-run', 'nameless-job', 'malformed-ref', 'malformed-release'])
def test_malformed_or_disagreeing_identity_never_counts_as_absence(gate, damage):
    api = AuthoredAPI(gate)
    if damage == 'repository-id':
        api.runs_data[1]['repository']['id'] = 99
        api.runs_data[1]['head_repository']['id'] = 99
    elif damage == 'job-attempt-bool':
        api.jobs_data[api.current][0]['run_attempt'] = True
    elif damage == 'job-run-id-bool':
        api.jobs_data[api.current][0]['run_id'] = True
    elif damage == 'nameless-run':
        api.runs_data.append({})
    elif damage == 'nameless-job':
        api.jobs_data[api.current].append({})
    elif damage == 'malformed-ref':
        api.refs_data.append({})
    else:
        api.releases_data.append({})
    assert not assess(gate, api)['qualified']


def test_publisher_attempt_must_be_the_actual_running_attempt(gate):
    api = AuthoredAPI(gate)
    assert not assess(gate, api, current_attempt=2)['qualified']


@pytest.mark.parametrize('raw', [b'{"status":"blocked","status":"passed"}',
                                 b'{"value":NaN}', b'{"value":Infinity}', b'\xff', b'{} trailing'])
def test_strict_json_refuses_ambiguous_or_non_json_values(gate, raw):
    with pytest.raises(gate.QualificationError):
        gate.strict_json(raw)


@pytest.mark.parametrize('raw', [b'{"elapsed":1e999}', b'{"nested":[{"elapsed":-1e999}]}'])
def test_overflowed_json_numbers_are_not_finite_evidence(gate, raw):
    with pytest.raises(gate.QualificationError):
        gate.strict_json(raw)


def test_one_native_artifact_id_cannot_qualify_two_platforms(gate):
    api = AuthoredAPI(gate)
    artifacts = next(iter(api.artifacts_data.values()))
    artifacts[1]['id'] = artifacts[0]['id']
    assert not assess(gate, api)['qualified']


def test_native_artifact_report_bytes_are_bounded_before_json(gate, monkeypatch):
    monkeypatch.setattr(gate, 'MAX_REPORT', 10)
    with pytest.raises(gate.QualificationError):
        gate.bindiff_report(AuthoredAPI.archive({'status': 'passed'}))


def test_duplicate_native_status_members_are_refused(gate):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as archive:
        archive.writestr('bindiff.json', '{}')
        with pytest.warns(UserWarning):
            archive.writestr('bindiff.json', '{}')
    with pytest.raises(gate.QualificationError):
        gate.bindiff_report(out.getvalue())


@pytest.mark.parametrize('damage', ['total-too-large', 'incomplete', 'count-changed', 'duplicate-page'])
def test_rest_pagination_refuses_partial_or_ambiguous_reads(gate, damage, monkeypatch):
    api = gate.GitHubAPI(REPO)
    if damage == 'total-too-large':
        pages = [{'total_count': 1001, 'workflow_runs': []}]
    elif damage == 'incomplete':
        pages = [{'total_count': 1, 'workflow_runs': []}]
    elif damage == 'count-changed':
        pages = [{'total_count': 101, 'workflow_runs': [{}] * 100},
                 {'total_count': 102, 'workflow_runs': [{}, {}]}]
    else:
        record = AuthoredAPI(gate).runs_data[0]
        pages = [{'total_count': 101, 'workflow_runs': [record] * 100},
                 {'total_count': 101, 'workflow_runs': [record]}]
    monkeypatch.setattr(api, '_get', lambda path: pages.pop(0))
    with pytest.raises(gate.QualificationError):
        gate.select_runs(api.runs(SHA), gate.requirements('desktop', ('windows', 'linux')), REPO, SHA)


def test_transport_uses_only_get_and_bounds_every_response(gate, monkeypatch):
    calls = []

    def receive(argv, **kwargs):
        calls.append((argv, kwargs))
        return b'{"sha":"' + SHA.encode() + b'"}'

    monkeypatch.setattr(gate, 'command', receive)
    gate.GitHubAPI(REPO).commit(SHA)
    argv, options = calls[0]
    assert argv[argv.index('--method') + 1] == 'GET'
    assert argv[-1] == f'repos/{REPO}/commits/{SHA}'
    assert options['limit'] == gate.MAX_JSON
    assert 'GH_TOKEN' not in ' '.join(argv)


def authored_checkout(tmp_path, message='Authored qualification fixture'):
    import subprocess

    root = tmp_path / 'source'
    root.mkdir()
    env = {**__import__('os').environ, 'GIT_CONFIG_NOSYSTEM': '1'}
    commands = [['init', '-q'], ['config', 'core.autocrlf', 'false'], ['config', 'user.name', 'Authored fixture'],
                ['config', 'user.email', 'fixture@example.invalid']]
    (root / 'sample.txt').write_text('authored data\n')
    commands += [['add', 'sample.txt'], ['commit', '-q', '-m', message]]
    for args in commands:
        subprocess.run(['git', *args], cwd=root, env=env, check=True, capture_output=True)
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, env=env, text=True).strip()
    return root, sha


@pytest.mark.parametrize('mask', ['assume-unchanged', 'skip-worktree', 'replacement', 'stat-cache', 'clean-filter'])
def test_source_identity_checks_bytes_independently_of_the_git_index(gate, tmp_path, mask):
    import os
    import subprocess

    root, sha = authored_checkout(tmp_path)
    file = root / 'sample.txt'
    before = file.stat()
    if mask in ('assume-unchanged', 'skip-worktree'):
        subprocess.run(['git', 'update-index', '--' + mask, 'sample.txt'], cwd=root, check=True)
    file.write_text('modified data\n')  # same length as original fixture
    if mask == 'replacement':
        subprocess.run(['git', 'add', 'sample.txt'], cwd=root, check=True)
        subprocess.run(['git', 'commit', '-q', '-m', 'Authored replacement'], cwd=root, check=True)
        replacement = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
        subprocess.run(['git', 'reset', '--soft', sha], cwd=root, check=True)
        subprocess.run(['git', 'replace', sha, replacement], cwd=root, check=True)
    if mask == 'stat-cache':
        os.utime(file, ns=(before.st_atime_ns, before.st_mtime_ns))
    if mask == 'clean-filter':
        (root / '.git/info/attributes').write_text('sample.txt filter=hide\n')
        subprocess.run(['git', 'config', 'filter.hide.clean', "printf 'authored data\\n'"], cwd=root, check=True)
    with pytest.raises(gate.QualificationError):
        gate.checked_source(root, sha)


@pytest.mark.parametrize('mode', ['clean', 'wrong-head', 'modified', 'hold'])
def test_checked_source_uses_commit_metadata_and_refuses_tree_drift(gate, tmp_path, mode):
    root, sha = authored_checkout(tmp_path, 'Authored [no release]' if mode == 'hold' else 'Authored fixture')
    if mode == 'wrong-head':
        sha = 'f' * 40
    if mode == 'modified':
        (root / 'sample.txt').write_text('changed\n')
    if mode == 'clean':
        gate.checked_source(root, sha)
    else:
        with pytest.raises(gate.QualificationError):
            gate.checked_source(root, sha)


def test_local_hold_emits_blocked_receipt_before_any_remote_read(gate, tmp_path, monkeypatch):
    root, sha = authored_checkout(tmp_path, 'Authored fixture\n\n[no release]')
    monkeypatch.setattr(gate, '__file__', str(root / 'tools/release_qualification.py'))
    monkeypatch.setattr(gate, 'GitHubAPI', lambda repo: pytest.fail('local hold must stop before REST'))
    output, receipt = tmp_path / 'output', tmp_path / 'receipt.json'
    status = gate.main(['--repo', REPO, '--head', sha, '--run-id', '1', '--attempt', '1',
                        '--profile', 'bundle', '--tag', 'v0.1.0', '--assets-dir', str(tmp_path),
                        '--report', str(receipt), '--github-output', str(output)])
    assert status == 1 and not output.exists()
    report = json.loads(receipt.read_text())
    assert report['qualified'] is False and '[no release]' in report['blockers'][0]


def test_policy_critical_names_match_actual_source_workflows(gate):
    import itertools
    import re

    def expand(text, matrix):
        return re.sub(r'\$\{\{\s*matrix\.([\w-]+)\s*\}\}', lambda match: str(matrix[match[1]]), text)

    for path, expected in gate.requirements('bundle', ('windows', 'linux')).items():
        source = ROOT / path
        if path.endswith('/dependency-security.yml'):
            assert not source.exists()  # explicit missing category, no invented qualifying scan
            continue
        jobs = yaml.safe_load(source.read_text())['jobs']
        actual = {}
        for key, job in jobs.items():
            matrix = job.get('strategy', {}).get('matrix', {})
            rows = matrix.get('include') if 'include' in matrix else [
                dict(zip(matrix, values, strict=True)) for values in itertools.product(*matrix.values())]
            for row in rows:
                name = job.get('name', key + (' (' + ', '.join(str(value) for value in row.values()) + ')' if row else ''))
                actual[expand(name, row)] = {
                    expand(step.get('name', 'Run ' + step['run'].splitlines()[0]), row)
                    for step in job['steps'] if 'run' in step}
        for name, critical in expected.items():
            assert name in actual, (path, name)
            assert set(critical) <= actual[name], (path, name, set(critical) - actual[name])



def test_annotated_tag_must_peel_to_exact_source(gate):
    api = AuthoredAPI(gate)
    tag_sha = 'b' * 40
    api.refs_data = [{'ref': 'refs/tags/v0.1.0-beta.1', 'object': {'type': 'tag', 'sha': tag_sha}}]
    api.tags_data[tag_sha] = {'sha': tag_sha, 'object': {'type': 'commit', 'sha': SHA}}
    assert assess(gate, api)['qualified']


def test_api_failure_produces_a_blocked_receipt(gate):
    api = AuthoredAPI(gate)
    api.runs = lambda sha: (_ for _ in ()).throw(gate.QualificationError('API unavailable'))
    result = assess(gate, api)
    assert not result['qualified'] and any('API unavailable' in reason for reason in result['blockers'])


def test_run_selection_changed_during_check_is_refused(gate):
    api = AuthoredAPI(gate)
    original = api.runs

    def mutate(sha):
        if api.calls.count('runs') == 1:
            api.runs_data[1]['run_attempt'] = 2
        return original(sha)

    api.runs = mutate
    assert not assess(gate, api)['qualified']


@pytest.mark.parametrize('bad_output', [False, True])
def test_cli_receipt_and_workflow_output_cannot_turn_an_error_into_a_pass(gate, tmp_path, monkeypatch, bad_output):
    api = AuthoredAPI(gate)
    monkeypatch.setattr(gate, 'GitHubAPI', lambda repo: api)
    monkeypatch.setattr(gate, 'checked_source', lambda root, sha: None)
    assets = tmp_path / 'assets'
    assets.mkdir()
    (assets / 'new.zip').write_bytes(b'authored fixture, not a release')
    output = tmp_path / 'output'
    if bad_output:
        output.mkdir()
    receipt = tmp_path / 'receipt.json'
    status = gate.main(['--repo', REPO, '--head', SHA, '--run-id', str(api.current), '--attempt', '1',
                        '--profile', 'desktop', '--tag', 'v0.1.0-beta.1', '--assets-dir', str(assets),
                        '--report', str(receipt), '--github-output', str(output)])
    report = json.loads(receipt.read_text())
    assert status == (1 if bad_output else 0)
    assert report['qualified'] is (not bad_output)
    if not bad_output:
        assert output.read_text() == 'release_exists=false\n'


def test_duplicate_existing_asset_evidence_is_refused(gate):
    api = AuthoredAPI(gate)
    existing_release(api)
    api.releases_data[0]['assets'] *= 2
    assert not assess(gate, api)['qualified']
