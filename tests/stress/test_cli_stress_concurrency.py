"""QA-CLI: concurrent CLI invocations against one project store (single-writer rule, SPEC-07 persistence).

Outcomes of a race are not fixed, so the race test asserts invariants only: every process ends with a contract exit
code and no traceback, every `--json` run prints one document, and the store opens and passes its own checks."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from cli_stress_support import SRC, assert_clean, json_documents, make_sample, run_main

from patchtrace import cli
from patchtrace.persistence import ProjectStore
from patchtrace.service import ProjectService

PROCESS_TIMEOUT = 120
WRITERS = 4


def _spawn(argv, cwd):
    env = dict(os.environ, PYTHONPATH=str(SRC), QT_QPA_PLATFORM='offscreen', PYTHONDONTWRITEBYTECODE='1')
    return subprocess.Popen([sys.executable, '-m', 'patchtrace', *argv], cwd=str(cwd), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')


def test_writer_is_refused_while_another_process_holds_the_store(tmp_path, capsys):
    root = make_sample(tmp_path / 'case')
    holder = ProjectService.open(root)
    try:
        for argv in (['rank', root, '--json'], ['flags', root, '--json']):
            code, out, err = run_main(argv, capsys)
            assert_clean(code, out, err)
            assert code == cli.ENVIRONMENT, (argv[0], code, err[-300:])
            documents = json_documents(out)
            assert len(documents) == 1 and documents[0]['status'] == 'failed'
            assert 'locked' in documents[0]['error']
    finally:
        holder.close()
    code, out, err = run_main(['rank', root, '--json', '--dry-run'], capsys)
    assert code == cli.OK, err[-300:]


def test_concurrent_cli_processes_leave_the_store_consistent(tmp_path):
    root = make_sample(tmp_path / 'case')
    before = ProjectStore(root)
    try:
        revision_before = before.load().revision
        history_before = len(before.history())
    finally:
        before.close()

    verbs = [['rank'] if index % 2 == 0 else ['flags'] for index in range(WRITERS)]
    processes = [_spawn([*verb, str(root), '--json'], tmp_path) for verb in verbs]
    results = []
    try:
        for process in processes:
            stdout, stderr = process.communicate(timeout=PROCESS_TIMEOUT)
            results.append((process.returncode, stdout, stderr))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()

    for code, stdout, stderr in results:
        assert_clean(code, stdout, stderr)
        assert code in {cli.OK, cli.ENVIRONMENT, cli.NO_RESULTS, cli.RUNTIME}, (code, stderr[-300:])
        documents = json_documents(stdout)
        assert len(documents) == 1, stdout[:300]
        assert documents[0]['contract'] == 'enrichment-cli/1'

    store = ProjectStore(root)
    try:
        project = store.load()
        assert project.revision == revision_before, 'identical rankings must not bump the revision'
        assert store.connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert len(store.history()) == history_before
    finally:
        store.close()


def test_stale_lock_file_contents_do_not_block_a_new_writer(tmp_path, capsys):
    """A killed writer leaves its pid and token in the lock file; the kernel lock is what counts, not the text."""
    root = make_sample(tmp_path / 'case')
    (root / '.patchtrace.lock').write_text(json.dumps({'pid': 999999, 'host': 'gone', 'token': 'stale'}) + '\n',
                                           encoding='utf-8', newline='\n')
    code, out, err = run_main(['rank', root, '--json', '--dry-run'], capsys)
    assert_clean(code, out, err)
    assert code == cli.OK, err[-300:]
    assert len(json_documents(out)) == 1


def test_parallel_read_only_probes_do_not_interfere(tmp_path):
    """Probe verbs touch no project; many at once must each finish with a document and no shared-state error."""
    processes = [_spawn(['backend', 'status', '--json'], tmp_path) for _ in range(3)]
    try:
        outputs = [process.communicate(timeout=PROCESS_TIMEOUT) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()
    for process, (stdout, stderr) in zip(processes, outputs, strict=True):
        assert_clean(process.returncode, stdout, stderr)
        assert len(json_documents(stdout)) == 1
    assert len({output[0] for output in outputs}) == 1, 'identical probes must report identical documents'
