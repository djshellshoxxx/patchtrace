"""H7 native primary-environment and raw-cache qualification; never executes target DLLs.

Runs the production default backend twice. A small isolated Python entry observes
the actual primary child's environment, then dispatches the real ghidriff module
with exactly the original engine arguments. The supplied child environment is
never modified. Unit controls of this harness are not native qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import secrets
import sys
import tempfile
import threading
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path

from patchtrace import backend, jobs
from patchtrace.service import ProjectService

SENTINELS = {
    'GITHUB_TOKEN': 'patchtrace-authored-h7-not-a-credential',
    'AWS_SECRET_ACCESS_KEY': 'patchtrace-authored-h7-not-an-access-key',
    'JAVA_TOOL_OPTIONS': '-Dpatchtrace.h7.authored=java-tool-options',
    '_JAVA_OPTIONS': '-Dpatchtrace.h7.authored=java-options',
    'JDK_JAVA_OPTIONS': '-Dpatchtrace.h7.authored=jdk-java-options',
}
CHILD_PROBE = '''import json, os, runpy, sys
from pathlib import Path
names = ''' + repr(tuple(SENTINELS)) + '''
present = {key.casefold() for key in os.environ}
record = {'schema': 'patchtrace/h7-child/1', 'attempt': sys.argv[2], 'pid': os.getpid(),
          'sentinel_absent': {name: name.casefold() not in present for name in names}}
with Path(sys.argv[1]).open('x', encoding='utf-8') as handle:
    json.dump(record, handle, sort_keys=True)
if not all(record['sentinel_absent'].values()):
    raise SystemExit('H7 authored sentinel was retained; native module was not entered')
sys.argv = ['ghidriff', *sys.argv[3:]]
runpy.run_module('ghidriff', run_name='__main__', alter_sys=True)
'''


class QualificationFailure(RuntimeError):
    """A required observation failed; messages contain no environment values."""


class QualificationBlocked(RuntimeError):
    """A missing prerequisite prevents native qualification."""


def file_sha256(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def child_receipt(path: Path, attempt: str) -> dict:
    try:
        with path.open('rb') as stream:
            payload = stream.read(8193)
        if len(payload) > 8192:
            raise ValueError
        row = json.loads(payload)
        if (not isinstance(row, dict) or set(row) != {'schema', 'attempt', 'pid', 'sentinel_absent'}
                or row['schema'] != 'patchtrace/h7-child/1' or row['attempt'] != attempt
                or type(row['pid']) is not int or row['pid'] <= 0
                or not isinstance(row['sentinel_absent'], dict)
                or set(row['sentinel_absent']) != set(SENTINELS)
                or any(value is not True for value in row['sentinel_absent'].values())):
            raise ValueError
        return row
    except (OSError, ValueError, TypeError):
        raise QualificationFailure('primary child receipt is missing, stale, or invalid') from None


class PrimaryProbe:
    """Observe backend launches without changing their environment or engine arguments."""

    def __init__(self, directory: Path, delegate, observations: list[dict]):
        self.directory, self.delegate, self.observations = directory, delegate, observations
        self.primary_calls = 0

    def run(self, argv, **options):
        if any(os.environ.get(name) != value for name, value in SENTINELS.items()):
            raise QualificationFailure('authored parent sentinels are not armed')
        environment = options.get('env')
        if not isinstance(environment, Mapping):
            raise QualificationFailure('explicit child environment is unavailable')
        present = {name.casefold() for name in environment}
        observation = {'sentinel_absent': {name: name.casefold() not in present for name in SENTINELS}}
        self.observations.append(observation)
        if not all(observation['sentinel_absent'].values()):
            raise QualificationFailure('authored sentinel retained in the actual launch environment')
        arguments = list(argv)
        isolated = arguments[1:4] == ['-I', '-X', 'utf8']
        primary = isolated and arguments[4:6] == ['-m', 'ghidriff']
        if primary:
            observation['kind'] = 'primary'
            self.primary_calls += 1
            attempt = secrets.token_hex(16)
            receipt = self.directory / f'primary-{self.primary_calls}-{attempt}.json'
            arguments = [*arguments[:4], '-c', CHILD_PROBE, str(receipt), attempt, *arguments[6:]]
        elif isolated and arguments[4:5] == ['-c']:
            observation['kind'] = 'dependency-probe'
        elif len(arguments) == 2 and arguments[1] == '-version':
            observation['kind'] = 'java-version'
        else:
            raise QualificationFailure('unexpected backend launch shape cannot be qualified')
        result = self.delegate(arguments, **options)
        observation['returncode'] = result.returncode
        observation['supervision_stopped'] = result.reason is not None
        if primary:
            observation['child'] = child_receipt(receipt, attempt)
        return result


@contextmanager
def observe_primary(directory: Path, observations: list[dict]):
    previous = {name: os.environ.get(name) for name in SENTINELS}
    original_runner = backend.run_process
    probe = PrimaryProbe(directory, original_runner, observations)
    try:
        os.environ.update(SENTINELS)
        backend.run_process = probe.run
        yield probe
    finally:
        backend.run_process = original_runner
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def normalized_matches_digest(matches) -> str:
    records = []
    for match in matches:
        row = match.model_dump(mode='json')
        for key in ('id', 'run_id'):
            row.pop(key, None)
        for side in ('older', 'newer'):
            for function in row[side]:
                for key in ('id', 'run_id', 'artifact_id'):
                    function.pop(key, None)
        records.append(json.dumps(row, sort_keys=True, separators=(',', ':')))
    return hashlib.sha256(json.dumps(sorted(records), separators=(',', ':')).encode()).hexdigest()


def analyse(older: Path, newer: Path, root: Path, config: backend.BackendConfig) -> dict:
    with ProjectService.create(older, newer, 'H7 native environment and cache check', root) as service:
        path, run = backend.run_comparison(config, service.project, root, threading.Event(), lambda event: None)
        if run.status != 'completed':
            raise QualificationFailure('native primary comparison did not complete')
        service.apply_analysis(path, run)
        if not service.project.matches:
            raise QualificationFailure('native primary comparison produced no normalized matches')
        return {'run_id': run.id, 'cache_hit': 'cache_origin' in run.settings,
                'raw_sha256': file_sha256(root / run.raw_path),
                'matches_sha256': normalized_matches_digest(service.project.matches),
                'match_count': len(service.project.matches),
                'versions': {name: run.settings.get(name, 'unknown') for name in
                             ('java_runtime_version', 'ghidra_version', 'pyghidra_version', 'python_version')},
                'ghidriff_version': run.backend_version}


def require_cache_reuse(first: dict, second: dict, primary_calls: int) -> None:
    if first['cache_hit'] or not second['cache_hit']:
        raise QualificationFailure('fresh native run and subsequent raw-cache hit were not both observed')
    if primary_calls != 1:
        raise QualificationFailure('expected exactly one actual primary launch across fresh and cached runs')
    if any(first[key] != second[key] for key in ('raw_sha256', 'matches_sha256', 'match_count')):
        raise QualificationFailure('raw-cache reuse changed raw bytes or normalized matches')


def qualify(args, record: dict) -> None:
    if not re.fullmatch('[0-9a-fA-F]{40}', args.source_sha or ''):
        raise QualificationBlocked('exact source commit identity is unavailable')
    if platform.system() not in ('Linux', 'Windows'):
        raise QualificationBlocked('this native qualifier requires Linux or Windows')
    if not args.old.is_file() or not args.new.is_file():
        raise QualificationBlocked('authored fixture pair is unavailable')
    if not (args.ghidra_dir / 'Ghidra' / 'application.properties').is_file():
        raise QualificationBlocked('pinned Ghidra installation is unavailable')
    if importlib.util.find_spec('ghidriff') is None:
        raise QualificationBlocked('native ghidriff dependency is unavailable')
    if os.environ.get('PATCHTRACE_CHILD_ENV') == 'inherit':
        raise QualificationBlocked('explicit inheritance opt-out prevents default-policy qualification')
    record['fixture_sha256'] = {'older': file_sha256(args.old), 'newer': file_sha256(args.new)}
    if record['fixture_sha256']['older'] == record['fixture_sha256']['newer']:
        raise QualificationFailure('qualification requires the distinct authored fixture pair')
    with tempfile.TemporaryDirectory(prefix='patchtrace-h7-') as directory:
        work = Path(directory).resolve()
        config = backend.BackendConfig(sys.executable, str(args.ghidra_dir.resolve()), 900,
                                       cache_dir=str(work / 'cache'))
        if config.restrict_env is not True:
            raise QualificationFailure('the actual backend default does not restrict its environment')
        with observe_primary(work, record['observations']) as probe:
            first = analyse(args.old.resolve(), args.new.resolve(), work / 'fresh', config)
            record['fresh'] = first
            second = analyse(args.old.resolve(), args.new.resolve(), work / 'cached', config)
            record['cached'] = second
            require_cache_reuse(first, second, probe.primary_calls)
        kinds = {row['kind'] for row in record['observations']}
        if not {'primary', 'dependency-probe', 'java-version'} <= kinds:
            raise QualificationFailure('native primary/dependency/JVM observations are incomplete')


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old', type=Path, required=True)
    parser.add_argument('--new', type=Path, required=True)
    parser.add_argument('--ghidra-dir', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source-sha', default=os.environ.get('GITHUB_SHA'))
    args = parser.parse_args(argv)
    source_sha = args.source_sha if re.fullmatch('[0-9a-fA-F]{40}', args.source_sha or '') else None
    record = {'schema': 'patchtrace/h7-native/1', 'mocked': False, 'status': 'blocked',
              'reason': 'qualification has not completed', 'source_sha': source_sha,
              'platform': platform.system(), 'python': platform.python_version(),
              'source_sha256': {'backend': file_sha256(Path(backend.__file__)),
                                'jobs': file_sha256(Path(jobs.__file__)),
                                'qualifier': file_sha256(Path(__file__)),
                                'child_entry': hashlib.sha256(CHILD_PROBE.encode()).hexdigest()},
              'sentinel_names': list(SENTINELS), 'observations': []}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    try:
        qualify(args, record)
        record['status'], record['reason'] = 'passed', 'native child isolation and raw-cache reuse observed'
    except QualificationBlocked as exc:
        record['status'], record['reason'] = 'blocked', str(exc)
    except QualificationFailure as exc:
        record['status'], record['reason'] = 'failed', str(exc)
    except Exception as exc:
        # Keep arbitrary third-party/native exception text and environment values out of the receipt.
        record['status'], record['reason'] = 'failed', f'qualification raised {type(exc).__name__}'
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f'H7 native qualification {record["status"]}: {record["reason"]}')
    return {'passed': 0, 'failed': 1, 'blocked': 2}[record['status']]


if __name__ == '__main__':
    sys.exit(main())
