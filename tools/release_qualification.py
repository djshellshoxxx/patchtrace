"""Read-only, exact-source publication qualification; no trigger or publish operation.

The policy deliberately reserves dependency/security gates which do not yet exist.
A missing lane is a blocker, never a substitute scan or an approval bypass.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import io
import json
import os
import re
import stat
import subprocess
import threading
import zipfile
from pathlib import Path
from urllib.parse import quote

POLICY_VERSION = 1
MAX_JSON = 4 * 1024 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_REPORT = 1024 * 1024
MAX_PAGES = 10
MAX_TAG_DEPTH = 8
BINDIFF_CHECKS = frozenset({
    'probe', 'pinned_version', 'reversed_refused', 'end_to_end',
    'cancel_at_first_output', 'timeout_mid_run', 'no_network',
})
CANONICAL_EVENTS = frozenset({'push', 'workflow_dispatch', 'schedule'})
SHA_RE = re.compile(r'[0-9a-f]{40}\Z')
REPO_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z')
NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+-]{0,254}\Z')
PREFIX = '.github/workflows/'


class QualificationError(ValueError):
    """Missing, contradictory or unreadable qualification evidence."""


def require(condition, reason):
    if not condition:
        raise QualificationError(reason)


def positive_int(value):
    return type(value) is int and value > 0


def requirements(profile, platforms):
    """Explicit job and critical-step allowlist; names are checked against YAML in tests."""
    require(profile in {'desktop', 'bundle'}, 'unknown publication profile')
    require(bool(platforms) and set(platforms) <= {'windows', 'linux'}, 'invalid platform selection')
    qa = {}
    for platform in ('ubuntu-latest', 'windows-latest'):
        critical = ['Run python -m pytest -q --junitxml=qa-results.xml',
                    'Run python -m ruff check src tests tools']
        if platform == 'windows-latest':
            critical += ['Run python tools/build_windows.py',
                         'Frozen EXE headless smoke (A1-A4) and self-test',
                         'Extract and run portable Windows ZIP outside checkout',
                         'Build per-user Windows installer', 'Install, launch, and uninstall the setup package']
        qa[f'qa ({platform})'] = tuple(critical)
    for platform, repeat, shards in (('ubuntu-latest', 20, 4), ('windows-latest', 5, 1)):
        for index in range(1, shards + 1):
            shard = f'{index}/{shards}'
            qa[f'qt-gate ({platform}, {repeat}, {shard})'] = (
                f'Run python tools/qt_gate.py --repeat {repeat} --shard {shard}',)
    qa['linux-package'] = ('Run python tools/build_linux.py',)
    for platform in ('ubuntu-22.04', 'ubuntu-24.04'):
        qa[f'linux-smoke ({platform})'] = (
            'Run QT_QPA_PLATFORM=offscreen PatchTrace/PatchTrace --self-test',
            'Run QT_QPA_PLATFORM=xcb xvfb-run -a PatchTrace/PatchTrace --self-test')
    native = {
        'native (repro-plain-ghidriff)': (
            'Reproduce cached-PDB FileExistsError with plain Ghidriff --no-symbols',),
        'native (raw-cache-hit)': ('Native raw-output cache hit is byte-identical',),
    }
    for variant in ('patchtrace-clean', 'patchtrace-seeded-store', 'patchtrace-seeded-store-no-adjacent-pdb'):
        native[f'native ({variant})'] = ('PatchTrace offline analysis succeeds despite persisted symbol store',)
    policy = {
        'qa-windows.yml': qa,
        'live-backend.yml': native,
        'live-rizin.yml': {f'live rz-diff ({platform})': ('Run live rz-diff check',)
                           for platform in ('ubuntu-latest', 'windows-latest')},
        'live-bindiff.yml': {f'live BinDiff ({platform})': (
            'Live BinDiff tests (records passed / failed / blocked)', 'Live status summary')
            for platform in ('ubuntu-22.04', 'windows-latest')},
        'live-unified.yml': {
            'windows': ('Live extraction, CI fixture pair', 'Live extraction, probe pair'),
            'linux': ('Live extraction on the Windows-built DLLs, CI fixture pair',
                      'Live extraction on the Windows-built DLLs, probe pair'),
        },
        'optional-deps.yml': {f'probe ({platform})': ('every optional dependency imports',)
                              for platform in ('ubuntu-latest', 'windows-latest')},
        'nightly-fuzz.yml': {
            'fuzz': ('Fuzz inspect_bytes (seeded mutation loop; findings are saved under build/fuzz-crashes)',),
            'parsers': ('Fuzz every untrusted-input parser (findings saved under build/parser-fuzz-crashes)',),
        },
        # Reserved policy, not a claim that these jobs or a qualifying scanner currently exist.
        'dependency-security.yml': {
            'dependency-audit': ('Audit installed dependencies',),
            'security-scan': ('Static security scan',),
        },
    }
    if profile == 'bundle':
        bundle = {'pin-resolves-and-plan': (
            'Pin release gate (placeholders resolved; publish also needs every licence approval)',)}
        for platform in platforms:
            bundle[f'build-{platform}-full-bundle'] = (
                'Build the backend payload (pinned, hash-checked downloads)',
                'Lite build smoke then full build', 'Check release sidecars')
        if 'windows' in platforms:
            bundle['accept-windows-no-network-readonly'] = (
                'Verify sidecar, extract to a hostile path, run acceptance (firewall block with positive control)',)
        if 'linux' in platforms:
            for platform in ('ubuntu-22.04', 'ubuntu-24.04'):
                bundle[f'accept-linux-no-network-readonly ({platform})'] = (
                    'Verify sidecar, extract to a hostile path, run acceptance (network namespace with positive control)',)
        policy['backend-bundle.yml'] = bundle
    return {PREFIX + path: jobs for path, jobs in policy.items()}


def strict_json(raw, limit=MAX_JSON):
    require(isinstance(raw, bytes) and len(raw) <= limit, 'JSON size exceeds the evidence limit')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result

    def constant(_):
        raise QualificationError('nonfinite JSON number')

    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise QualificationError('invalid strict JSON evidence') from exc


def command(argv, *, cwd=None, limit=MAX_JSON):
    """Bound stdout while reading; no shell, stderr/token output or interactive prompts."""
    env = {**os.environ, 'GH_PROMPT_DISABLED': '1', 'GH_PAGER': 'cat',
           'GH_NO_UPDATE_NOTIFIER': '1', 'GIT_TERMINAL_PROMPT': '0'}
    try:
        with subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            timer = threading.Timer(60, process.kill)
            timer.daemon = True
            timer.start()
            try:
                output = process.stdout.read(limit + 1)
                if len(output) > limit:
                    process.kill()
                    raise QualificationError('command output exceeds the evidence limit')
                require(process.wait(timeout=5) == 0, 'read-only command failed or timed out')
                return output
            finally:
                timer.cancel()
                if process.poll() is None:
                    process.kill()
    except (OSError, subprocess.SubprocessError) as exc:
        raise QualificationError('read-only command unavailable or timed out') from exc


class GitHubAPI:
    """Only bounded GitHub REST GET requests; a nonzero exit never means absence."""

    def __init__(self, repo):
        require(isinstance(repo, str) and REPO_RE.fullmatch(repo), 'invalid repository identity')
        self.repo = repo

    def _get(self, path, *, limit=MAX_JSON, binary=False):
        try:
            raw = command(['gh', 'api', '--hostname', 'github.com', '--method', 'GET',
                           '-H', 'Accept: application/vnd.github+json',
                           '-H', 'X-GitHub-Api-Version: 2022-11-28',
                           f'repos/{self.repo}/{path}'], limit=limit)
            return raw if binary else strict_json(raw, limit)
        except QualificationError as exc:
            raise QualificationError(f'GitHub GET {path.split("?")[0]} failed: {exc}') from exc

    def _pages(self, path, key=None):
        rows, total = [], None
        for page in range(1, MAX_PAGES + 1):
            separator = '&' if '?' in path else '?'
            data = self._get(f'{path}{separator}per_page=100&page={page}')
            if key:
                require(isinstance(data, dict), 'malformed paginated evidence')
                count, items = data.get('total_count'), data.get(key)
                require(type(count) is int and 0 <= count <= MAX_PAGES * 100, 'unbounded evidence count')
                require(total is None or total == count, 'evidence count changed during pagination')
                total = count
            else:
                items = data
            require(isinstance(items, list) and len(items) <= 100, 'malformed evidence page')
            rows.extend(items)
            if len(items) < 100 or (total is not None and len(rows) == total):
                require(total is None or len(rows) == total, 'incomplete evidence pagination')
                return rows
        raise QualificationError('evidence pagination limit reached')

    def commit(self, sha):
        return self._get(f'commits/{sha}')

    def runs(self, sha):
        return self._pages(f'actions/runs?head_sha={sha}', 'workflow_runs')

    def run(self, run_id):
        return self._get(f'actions/runs/{run_id}')

    def jobs(self, run_id, attempt):
        return self._pages(f'actions/runs/{run_id}/attempts/{attempt}/jobs', 'jobs')

    def artifacts(self, run_id):
        return self._pages(f'actions/runs/{run_id}/artifacts', 'artifacts')

    def artifact_bytes(self, artifact_id):
        return self._get(f'actions/artifacts/{artifact_id}/zip', limit=MAX_ARCHIVE, binary=True)

    def refs(self, tag):
        result = self._get('git/matching-refs/tags/' + quote(tag, safe=''))
        require(isinstance(result, list) and len(result) <= 1000, 'unbounded matching refs')
        return result

    def releases(self):
        return self._pages('releases')

    def release_assets(self, release_id):
        return self._pages(f'releases/{release_id}/assets')

    def tag(self, sha):
        return self._get(f'git/tags/{sha}')


def stamp(value):
    require(isinstance(value, str) and len(value) <= 40, 'missing execution timestamp')
    try:
        result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise QualificationError('invalid execution timestamp') from exc
    require(result.tzinfo is not None, 'execution timestamp has no timezone')
    return result


def run_identity(run, repo, sha):
    require(isinstance(run, dict), 'malformed workflow run')
    require(positive_int(run.get('id')) and positive_int(run.get('workflow_id')) and
            positive_int(run.get('run_attempt')), 'invalid workflow/run/attempt identity')
    require(run.get('head_sha') == sha, 'workflow source SHA mismatch')
    for key in ('repository', 'head_repository'):
        identity = run.get(key)
        require(isinstance(identity, dict) and identity.get('full_name') == repo and
                positive_int(identity.get('id')), 'foreign repository or fork evidence')
    require(run['repository']['id'] == run['head_repository']['id'], 'repository ID mismatch')
    require(run.get('event') in CANONICAL_EVENTS, 'PR preview or unsupported workflow event')
    stamp(run.get('run_started_at'))
    return (run['id'], run['workflow_id'], run.get('path'), run['head_sha'], run['run_attempt'],
            run['event'], run['repository']['id'], run['head_repository']['id'],
            run.get('status'), run.get('conclusion'), run.get('run_started_at'))


def select_runs(rows, policy, repo, sha):
    require(isinstance(rows, list) and len(rows) <= MAX_PAGES * 100, 'invalid workflow run list')
    selected, seen = {}, set()
    for run in rows:
        require(isinstance(run, dict) and isinstance(run.get('path'), str) and
                isinstance(run.get('event'), str), 'malformed workflow run list')
        if run.get('path') not in policy or run.get('event') not in CANONICAL_EVENTS:
            continue
        run_identity(run, repo, sha)
        require(run['id'] not in seen, 'duplicate workflow run identity')
        seen.add(run['id'])
        path = run['path']
        previous = selected.get(path)
        if previous:
            require(previous['workflow_id'] == run['workflow_id'], f'{path}: ambiguous workflow identity')
        if previous is None or run['id'] > previous['id']:
            selected[path] = copy.deepcopy(run)
    require(len({run['repository']['id'] for run in selected.values()}) <= 1,
            'workflow runs disagree about repository identity')
    return selected


def qualified_jobs(api, run, expected, sha):
    jobs = api.jobs(run['id'], run['run_attempt'])
    require(isinstance(jobs, list) and len(jobs) <= MAX_PAGES * 100, 'invalid jobs evidence')
    require(all(isinstance(job, dict) and isinstance(job.get('name'), str) and job['name'] and
                positive_int(job.get('id')) and positive_int(job.get('run_id')) and
                positive_int(job.get('run_attempt')) for job in jobs), 'malformed job identity')
    require(len({job['id'] for job in jobs}) == len(jobs), 'duplicate job identity')
    result, seen = {}, set()
    for name, critical in expected.items():
        matches = [j for j in jobs if isinstance(j, dict) and j.get('name') == name]
        require(len(matches) == 1, f'{name}: missing or ambiguous job')
        job = matches[0]
        require(positive_int(job.get('id')) and job['id'] not in seen, f'{name}: ambiguous job ID')
        seen.add(job['id'])
        require(job.get('run_id') == run['id'] and job.get('run_attempt') == run['run_attempt'] and
                job.get('head_sha') == sha and
                job.get('run_url') == f'https://api.github.com/repos/{api.repo}/actions/runs/{run["id"]}',
                f'{name}: job does not belong to exact source/run/attempt')
        require(job.get('status') == 'completed' and job.get('conclusion') == 'success',
                f'{name}: mandatory job is {job.get("status")}/{job.get("conclusion")}')
        require(stamp(run['run_started_at']) <= stamp(job.get('started_at')) <= stamp(job.get('completed_at')),
                f'{name}: invalid job execution interval')
        steps = job.get('steps')
        require(isinstance(steps, list) and len(steps) <= 200, f'{name}: missing/bounded steps')
        for label in critical:
            matches = [s for s in steps if isinstance(s, dict) and s.get('name') == label]
            require(len(matches) == 1, f'{name}: missing or ambiguous critical step {label}')
            step = matches[0]
            require(step.get('status') == 'completed' and step.get('conclusion') == 'success',
                    f'{name}: critical step did not succeed: {label}')
        result[name] = job
    return result


def bindiff_report(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_ARCHIVE, 'native artifact exceeds size limit')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            require(len(members) <= 100 and len({m.filename for m in members}) == len(members),
                    'ambiguous native artifact members')
            reports = [m for m in members if m.filename == 'bindiff.json']
            require(len(reports) == 1, 'native artifact has no unique root bindiff.json')
            member = reports[0]
            require(not member.is_dir() and not stat.S_ISLNK(member.external_attr >> 16) and
                    member.file_size <= MAX_REPORT, 'invalid native status member')
            with archive.open(member) as stream:
                report = strict_json(stream.read(MAX_REPORT + 1), MAX_REPORT)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as exc:
        raise QualificationError('unreadable native status artifact') from exc
    require(isinstance(report, dict) and report.get('engine') == 'bindiff' and
            report.get('status') == 'passed' and report.get('mocked') is False,
            'BinDiff native status is absent, blocked, failed or mocked')
    checks = report.get('checks')
    require(isinstance(checks, dict) and BINDIFF_CHECKS <= checks.keys() and len(checks) <= 100,
            'BinDiff native subchecks are incomplete')
    require(all(isinstance(value, dict) and value.get('status') == 'passed' for value in checks.values()),
            'BinDiff native subcheck is blocked or failed')


def native_artifacts(api, run, jobs, sha):
    artifacts = api.artifacts(run['id'])
    require(isinstance(artifacts, list) and len(artifacts) <= 1000, 'invalid native artifacts list')
    receipt = []
    for platform, job_platform in (('linux', 'ubuntu-22.04'), ('windows', 'windows-latest')):
        name = f'live-bindiff-{platform}'
        matches = [a for a in artifacts if isinstance(a, dict) and a.get('name') == name]
        require(len(matches) == 1, f'{name}: missing or ambiguous native artifact')
        artifact = matches[0]
        require(positive_int(artifact.get('id')) and artifact.get('expired') is False and
                positive_int(artifact.get('size_in_bytes')) and artifact['size_in_bytes'] <= MAX_ARCHIVE,
                f'{name}: expired or oversized native artifact')
        owner = artifact.get('workflow_run')
        require(isinstance(owner, dict) and owner.get('id') == run['id'] and owner.get('head_sha') == sha and
                owner.get('repository_id') == run['repository']['id'] and
                owner.get('head_repository_id') == run['head_repository']['id'],
                f'{name}: foreign artifact ownership')
        job = jobs[f'live BinDiff ({job_platform})']
        require(stamp(job['started_at']) <= stamp(artifact.get('created_at')) <= stamp(job['completed_at']),
                f'{name}: artifact is not from the selected job attempt')
        bindiff_report(api.artifact_bytes(artifact['id']))
        receipt.append({'id': artifact['id'], 'name': name, 'job_id': job['id']})
    return receipt


def release_destination(api, tag, sha, assets):
    require(isinstance(tag, str) and len(tag) <= 64 and NAME_RE.fullmatch(tag), 'invalid release tag')
    require(isinstance(assets, set) and 0 < len(assets) <= 512 and
            all(isinstance(name, str) and NAME_RE.fullmatch(name) for name in assets), 'invalid release assets')
    refs = api.refs(tag)
    require(isinstance(refs, list) and all(isinstance(ref, dict) and isinstance(ref.get('ref'), str) and
                                         isinstance(ref.get('object'), dict) for ref in refs), 'invalid tag refs')
    matches = [ref for ref in refs if isinstance(ref, dict) and ref.get('ref') == f'refs/tags/{tag}']
    require(len(matches) <= 1, 'ambiguous release tag')
    if matches:
        target, seen = matches[0].get('object'), set()
        for _ in range(MAX_TAG_DEPTH):
            require(isinstance(target, dict) and isinstance(target.get('sha'), str) and
                    SHA_RE.fullmatch(target['sha']), 'invalid tag target')
            if target.get('type') == 'commit':
                require(target['sha'] == sha, 'release tag does not peel to TARGET_SHA')
                break
            require(target.get('type') == 'tag' and target['sha'] not in seen, 'cyclic or unsupported tag target')
            seen.add(target['sha'])
            annotated = api.tag(target['sha'])
            require(isinstance(annotated, dict) and annotated.get('sha') == target['sha'], 'tag object SHA mismatch')
            target = annotated.get('object')
        else:
            raise QualificationError('annotated tag depth limit reached')
    releases = api.releases()
    require(isinstance(releases, list) and all(isinstance(release, dict) and
            isinstance(release.get('tag_name'), str) and positive_int(release.get('id'))
            for release in releases), 'invalid releases evidence')
    require(len({release['id'] for release in releases}) == len(releases), 'duplicate release identity')
    existing = [r for r in releases if isinstance(r, dict) and r.get('tag_name') == tag]
    require(len(existing) <= 1, 'ambiguous existing release')
    if existing:
        release = existing[0]
        require(matches and release.get('prerelease') is True and release.get('draft') is False,
                'existing release is not a published prerelease on the exact tag')
        require(positive_int(release.get('id')), 'missing release identity')
        remote = api.release_assets(release['id'])
        require(isinstance(remote, list) and all(isinstance(a, dict) and isinstance(a.get('name'), str)
                                               for a in remote), 'unreadable existing asset list')
        require(len({a['name'] for a in remote}) == len(remote), 'ambiguous existing release assets')
        require(not assets.intersection(a['name'] for a in remote), 'existing release asset collision; no overwrite')
    return {'tag': tag, 'tag_exists': bool(matches), 'release_exists': bool(existing), 'assets': sorted(assets)}


def qualify(api, *, sha, current_run, profile, platforms, tag, assets, current_attempt=1):
    report = {'policy_version': POLICY_VERSION, 'qualified': False, 'repository': api.repo,
              'head_sha': sha, 'publisher_run_id': current_run, 'publisher_attempt': current_attempt,
              'blockers': [], 'runs': []}
    try:
        require(isinstance(sha, str) and SHA_RE.fullmatch(sha), 'full lowercase source SHA required')
        require(positive_int(current_run) and positive_int(current_attempt), 'invalid publisher run/attempt')
        policy = requirements(profile, platforms)
        commit = api.commit(sha)
        require(isinstance(commit, dict) and commit.get('sha') == sha and isinstance(commit.get('commit'), dict),
                'authoritative commit identity missing')
        message = commit['commit'].get('message')
        require(isinstance(message, str), 'authoritative commit message missing')
        require('[no release]' not in message, 'actual commit contains [no release]')
        selected = select_runs(api.runs(sha), policy, api.repo, sha)
        publisher = PREFIX + ('qa-windows.yml' if profile == 'desktop' else 'backend-bundle.yml')
        for path, expected in policy.items():
            try:
                require(path in selected, f'{path}: missing canonical exact-source run')
                run = selected[path]
                identity = run_identity(run, api.repo, sha)
                require(run_identity(api.run(run['id']), api.repo, sha) == identity,
                        f'{path}: run/attempt changed before verification')
                if path == publisher:
                    require(run['id'] == current_run and run['run_attempt'] == current_attempt,
                            f'{path}: publisher artifacts belong to another run/attempt')
                    require(run.get('status') == 'in_progress' and run.get('conclusion') is None,
                            f'{path}: publisher is not the active current run')
                else:
                    require(run.get('status') == 'completed' and run.get('conclusion') == 'success',
                            f'{path}: workflow is {run.get("status")}/{run.get("conclusion")}')
                jobs = qualified_jobs(api, run, expected, sha)
                receipt = {'path': path, 'id': run['id'], 'attempt': run['run_attempt'],
                           'workflow_id': run['workflow_id'], 'jobs': [
                               {'id': job['id'], 'name': name} for name, job in jobs.items()]}
                if path.endswith('/live-bindiff.yml'):
                    receipt['artifacts'] = native_artifacts(api, run, jobs, sha)
                report['runs'].append(receipt)
            except QualificationError as exc:
                report['blockers'].append(f'{path}: {exc}'[:1000])
        report['destination'] = release_destination(api, tag, sha, assets)
        # Detect a rerun/new canonical run which arrived during the reads. Never reuse a stale pass.
        latest = select_runs(api.runs(sha), policy, api.repo, sha)
        require(set(latest) == set(selected), 'workflow selection changed during verification')
        for path, run in selected.items():
            identity = run_identity(run, api.repo, sha)
            require(run_identity(latest[path], api.repo, sha) == identity and
                    run_identity(api.run(run['id']), api.repo, sha) == identity,
                    f'{path}: run/attempt changed during verification')
        report['qualified'] = not report['blockers']
    except (QualificationError, KeyError, TypeError) as exc:
        report['blockers'].append(str(exc)[:1000] or 'malformed evidence')
    return report


def checked_source(root, sha):
    require(isinstance(sha, str) and SHA_RE.fullmatch(sha), 'full lowercase source SHA required')
    actual = command(['git', '--no-replace-objects', 'rev-parse', '--verify', 'HEAD'], cwd=root).decode().strip()
    require(actual == sha, 'checked-out HEAD differs from requested source SHA')
    try:
        command(['git', 'diff', '--quiet', 'HEAD', '--'], cwd=root)
    except QualificationError as exc:
        raise QualificationError('checked-out source tree has tracked changes or cannot be verified') from exc
    message = command(['git', '--no-replace-objects', 'show', '-s', '--format=%B', 'HEAD'], cwd=root).decode('utf-8')
    require('[no release]' not in message, 'actual checked-out commit contains [no release]')


def asset_names(directory):
    require(directory.is_dir(), 'release asset directory is missing')
    entries = list(directory.iterdir())
    require(0 < len(entries) <= 512 and all(p.is_file() and not p.is_symlink() for p in entries),
            'release assets must be a bounded list of regular files')
    return {p.name for p in entries}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--head', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--attempt', required=True, type=int)
    parser.add_argument('--profile', required=True, choices=('desktop', 'bundle'))
    parser.add_argument('--platforms', choices=('both', 'windows', 'linux'), default='both')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--assets-dir', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args(argv)
    try:
        checked_source(Path(__file__).resolve().parents[1], args.head)
        api = GitHubAPI(args.repo)
        platforms = ('windows', 'linux') if args.platforms == 'both' else (args.platforms,)
        report = qualify(api, sha=args.head, current_run=args.run_id, current_attempt=args.attempt,
                         profile=args.profile, platforms=platforms, tag=args.tag, assets=asset_names(args.assets_dir))
    except (QualificationError, OSError, UnicodeError) as exc:
        report = {'policy_version': POLICY_VERSION, 'qualified': False, 'repository': args.repo,
                  'head_sha': args.head, 'publisher_run_id': args.run_id, 'publisher_attempt': args.attempt,
                  'blockers': [str(exc)[:1000]]}
    raw = json.dumps(report, indent=2, ensure_ascii=True) + '\n'
    try:
        args.report.write_text(raw, encoding='utf-8')
        if report['qualified'] and args.github_output:
            with args.github_output.open('a', encoding='utf-8') as output:
                output.write('release_exists=' + str(report['destination']['release_exists']).lower() + '\n')
    except OSError:
        report['qualified'] = False
        report['blockers'].append('cannot persist the qualification receipt or workflow output')
        raw = json.dumps(report, indent=2, ensure_ascii=True) + '\n'
        try:
            args.report.write_text(raw, encoding='utf-8')
        except OSError:
            pass  # The failed write is still recorded on stdout; publication remains blocked.
        print(raw, end='')
        return 1
    print(raw, end='')
    return 0 if report['qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
