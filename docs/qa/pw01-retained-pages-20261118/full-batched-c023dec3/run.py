"""Sequential, immutable-input qualification receipts; never modifies repository sources."""
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
import tomllib
import xml.etree.ElementTree as ET

ROOT = Path('/workspace/scratch/e83fbf4505c3/qualification-pw01-batched-c023dec3')
OUT = Path(__file__).resolve().parent
PYTHON = '/workspace/scratch/3a6632a6e5ff/venv/bin/python'
COMMIT = 'c023dec36a464c3e7e1a8689f52a22263f0c24c5'
TREE = 'd390d0f2f77b34cdb0a265b9bfb33e06d4428e09'
TIMEOUT_SECONDS = 1800
ENV = dict(os.environ, PYTHONPATH='src', QT_QPA_PLATFORM='offscreen', PYTHONUNBUFFERED='1')


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    temporary.replace(path)


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def junit_summary(path):
    if not path.is_file():
        return None
    root = ET.parse(path).getroot()
    suites = list(root.iter('testsuite'))
    result = {name: sum(int(suite.get(name, '0')) for suite in suites)
              for name in ('tests', 'failures', 'errors', 'skipped')}
    result['passed'] = result['tests'] - result['failures'] - result['errors'] - result['skipped']
    result['duration_seconds'] = sum(float(suite.get('time', '0')) for suite in suites)
    result['sha256'] = digest(path)
    return result


def run_one(label, argv, *, files=None, junit=None):
    started_at, started = now(), time.monotonic()
    log_path = OUT / f'{label}.log'
    receipt_path = OUT / f'{label}.json'
    receipt = {'label': label, 'source_commit': COMMIT, 'source_tree': TREE,
               'cwd': str(ROOT), 'argv': argv, 'environment_overrides': {
                   'PYTHONPATH': 'src', 'QT_QPA_PLATFORM': 'offscreen', 'PYTHONUNBUFFERED': '1'},
               'started_at': started_at, 'timeout_seconds': TIMEOUT_SECONDS,
               'log': str(log_path), 'status': 'RUNNING'}
    if files is not None:
        receipt['files'] = files
        receipt['file_count'] = len(files)
    if junit is not None:
        receipt['junit'] = str(junit)
    write_json(receipt_path, receipt)
    print(json.dumps({'event': 'started', 'label': label, 'file_count': len(files or ())}), flush=True)
    peak_rss_kib, timed_out = 0, False
    with log_path.open('wb') as log:
        child = subprocess.Popen(argv, cwd=ROOT, env=ENV, stdout=log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        receipt['pid'] = child.pid
        write_json(receipt_path, receipt)
        while child.poll() is None:
            try:
                status = Path(f'/proc/{child.pid}/status').read_text()
                for line in status.splitlines():
                    if line.startswith(('VmRSS:', 'VmHWM:')):
                        peak_rss_kib = max(peak_rss_kib, int(line.split()[1]))
            except (FileNotFoundError, ProcessLookupError):
                pass
            if time.monotonic() - started >= TIMEOUT_SECONDS:
                timed_out = True
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                break
            time.sleep(1)
        code = child.wait()
    receipt.update(finished_at=now(), elapsed_seconds=round(time.monotonic() - started, 3),
                   returncode=code, shell_exit_code=code if code >= 0 else 128 - code,
                   timed_out=timed_out, peak_rss_kib=peak_rss_kib,
                   log_bytes=log_path.stat().st_size, log_sha256=digest(log_path))
    if code < 0:
        receipt['termination_signal'] = -code
    if junit is not None:
        try:
            receipt['junit_summary'] = junit_summary(junit)
        except (ET.ParseError, OSError, ValueError) as exc:
            receipt['junit_summary'] = None
            receipt['junit_parse_error'] = str(exc)
        complete = not timed_out and code in (0, 1) and receipt['junit_summary'] is not None
    else:
        complete = not timed_out and code >= 0 and code < 128
    receipt['complete'] = complete
    receipt['status'] = 'PASS' if complete and code == 0 else 'FAIL' if complete else 'INCOMPLETE'
    write_json(receipt_path, receipt)
    print(json.dumps({'event': 'finished', 'label': label, 'status': receipt['status'],
                      'exit': receipt['shell_exit_code'], 'elapsed_seconds': receipt['elapsed_seconds']}), flush=True)
    return receipt


def main():
    assert sys.executable == PYTHON
    assert git('rev-parse', 'HEAD') == COMMIT
    assert git('rev-parse', 'HEAD^{tree}') == TREE
    assert not git('status', '--porcelain')
    assert not ENV.get('PYTEST_ADDOPTS'), 'Unexpected PYTEST_ADDOPTS must be reviewed before full coverage.'
    assert not (OUT / 'manifest.json').exists(), 'Preserve the previous qualification run.'
    config = tomllib.loads((ROOT / 'pyproject.toml').read_text())['tool']['pytest']['ini_options']
    assert config['testpaths'] == ['tests'] and 'python_files' not in config and 'addopts' not in config
    patterns = ('test_*.py', '*_test.py')
    found = subprocess.check_output(['rg', '--files', 'tests', '-g', patterns[0], '-g', patterns[1]],
                                    cwd=ROOT, text=True).splitlines()
    files = sorted(found)
    tracked = git('ls-files', 'tests').splitlines()
    expected = sorted(p for p in tracked if any(fnmatch.fnmatch(Path(p).name, pattern) for pattern in patterns))
    assert files == expected and len(files) == len(set(files)) == 845
    assert {str(Path(p).parent) for p in files} == {'tests', 'tests/stress'}
    batches, offset = [], 0
    quotient, remainder = divmod(len(files), 12)
    for index in range(12):
        size = quotient + (index < remainder)
        batches.append(files[offset:offset + size])
        offset += size
    assert [f for batch in batches for f in batch] == files
    (OUT / 'test-files.txt').write_text('\n'.join(files) + '\n', encoding='utf-8')
    manifest = {'source_commit': COMMIT, 'source_tree': TREE, 'cwd': str(ROOT), 'created_at': now(),
                'python': PYTHON, 'python_version': sys.version, 'platform': platform.platform(),
                'versions': {name: importlib.metadata.version(name) for name in ('pytest', 'pytest-qt', 'PySide6', 'pydantic')},
                'file_count': len(files), 'batch_count': len(batches), 'test_files_sha256': digest(OUT / 'test-files.txt'),
                'configuration': config, 'collection_hooks': 'No ignore/custom collection hooks in either conftest.',
                'config_sha256': {p: digest(ROOT / p) for p in ('pyproject.toml', 'tests/conftest.py', 'tests/stress/conftest.py')},
                'timeout_seconds_per_batch': TIMEOUT_SECONDS, 'batches': batches,
                'scope': 'All configured pytest files in fixed sequential processes. Hosted whole-process QA and Qt-repeat remain required.'}
    write_json(OUT / 'manifest.json', manifest)
    results = []
    for index, batch in enumerate(batches, 1):
        label = f'batch-{index:02d}'
        junit = OUT / f'{label}.xml'
        argv = [PYTHON, '-m', 'pytest', '-q', f'--junitxml={junit}', *batch]
        result = run_one(label, argv, files=batch, junit=junit)
        results.append(result)
        write_json(OUT / 'progress.json', {'source_commit': COMMIT, 'completed_batches': len(results),
                                         'expected_batches': len(batches), 'last_batch': result['label'],
                                         'results': results, 'status': 'RUNNING'})
    checks = [run_one('ruff', [PYTHON, '-m', 'ruff', 'check', 'src', 'tests', 'tools']),
              run_one('schema-check', [PYTHON, 'tools/generate_kbc_schemas.py', '--check']),
              run_one('diff-check', ['git', 'diff', '--check'])]
    after = git('status', '--porcelain')
    all_complete = all(result['complete'] for result in results)
    total = {name: sum((result.get('junit_summary') or {}).get(name, 0) for result in results)
             for name in ('tests', 'passed', 'failures', 'errors', 'skipped')}
    summary = {'source_commit': COMMIT, 'source_tree': TREE, 'finished_at': now(),
               'file_count': len(files), 'batch_count': len(batches), 'all_batches_complete': all_complete,
               'totals': total if all_complete else None, 'observed_partial_totals': None if all_complete else total,
               'batches': results, 'checks': checks, 'post_run_git_status': after,
               'post_run_head': git('rev-parse', 'HEAD'), 'post_run_tree': git('rev-parse', 'HEAD^{tree}'),
               'status': 'PASS' if all_complete and all(r['status'] == 'PASS' for r in (*results, *checks)) and not after
                         else 'FAIL' if all_complete else 'INCOMPLETE',
               'scope': manifest['scope']}
    write_json(OUT / 'summary.json', summary)
    print(json.dumps({'event': 'qualification_finished', 'status': summary['status'],
                      'all_batches_complete': all_complete, 'totals': summary['totals']}), flush=True)


if __name__ == '__main__':
    main()
