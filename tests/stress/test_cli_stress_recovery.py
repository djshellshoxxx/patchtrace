"""QA-CLI: recovery of the project store after a writer is killed mid-write, and refusal of damaged stores.

The kill is real (SIGKILL of a child process) and the child is parked at a known point inside the write, announced
on its stdout, so no fixed sleep is needed. A watchdog timer bounds the wait if the child never reaches that point."""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading

import pytest
from cli_stress_support import SRC, assert_clean, json_documents, make_sample, run_main

from patchtrace import cli
from patchtrace.persistence import ProjectStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

WATCHDOG_SECONDS = 60

SAVE_CHILD = r'''
import sys, threading
from patchtrace import persistence
from patchtrace.service import ProjectService

def park(self, current_sha, project_id=None):
    # Inside the save transaction: rows are written, COMMIT has not run.
    sys.stdout.write("PARKED\n")
    sys.stdout.flush()
    threading.Event().wait()

persistence.ProjectStore._prune_history = park
service = ProjectService.open(sys.argv[1])
project = service.project
service.store.save(project.model_copy(update={"name": "killed mid-write"}))
'''

CREATE_CHILD = r'''
import sys, threading
from pathlib import Path
from patchtrace import service as service_module

def park(*args):
    # The database and its tables are committed; no snapshot exists yet.
    sys.stdout.write("PARKED\n")
    sys.stdout.flush()
    threading.Event().wait()

service_module.inspect_artifact = park
service_module.ProjectService.create(Path(sys.argv[2]), Path(sys.argv[3]), "never", Path(sys.argv[1]))
'''


def _kill_while_parked(code: str, *args) -> None:
    """Start `code`, wait until it reports PARKED, then SIGKILL it. The watchdog kills it if it never parks."""
    env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONDONTWRITEBYTECODE='1')
    process = subprocess.Popen([sys.executable, '-c', code, *map(str, args)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding='utf-8', env=env)
    watchdog = threading.Timer(WATCHDOG_SECONDS, process.kill)
    watchdog.start()
    try:
        announced = process.stdout.readline()
        assert announced.strip() == 'PARKED', process.stderr.read()[-2000:]
        process.kill()  # SIGKILL on POSIX, TerminateProcess on Windows: no cleanup code runs in the child
    finally:
        watchdog.cancel()
        process.wait(timeout=WATCHDOG_SECONDS)
        process.stdout.close()
        process.stderr.close()
    assert process.returncode != 0


def _database(root):
    return root / 'project.sqlite3'


def test_sigkill_inside_save_keeps_the_committed_snapshot(tmp_path, capsys):
    root = make_sample(tmp_path / 'case')
    before = ProjectService.open(root)
    try:
        revision, history_rows, name = before.project.revision, len(before.store.history()), before.project.name
    finally:
        before.close()

    _kill_while_parked(SAVE_CHILD, root)

    recovered = ProjectService.open(root)  # the kernel released the killed writer's lock
    try:
        assert recovered.project.revision == revision
        assert recovered.project.name == name
        assert len(recovered.store.history()) == history_rows, 'the uncommitted history row must not survive'
        assert recovered.store.connection.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    finally:
        recovered.close()
    code, out, err = run_main(['rank', root, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.OK, err[-300:]
    assert len(json_documents(out)) == 1


def test_sigkill_during_creation_is_recycled_by_the_next_create(tmp_path):
    pair = (tmp_path / 'older.dll', tmp_path / 'newer.dll')
    pair[0].write_bytes(synthetic_pe(0))
    pair[1].write_bytes(synthetic_pe(1))
    root = tmp_path / 'case'

    _kill_while_parked(CREATE_CHILD, root, *pair)
    assert _database(root).is_file(), 'the killed creation leaves a database without a snapshot'
    store = ProjectStore(root)
    try:
        with pytest.raises(ValueError, match='^PT-STORAGE: project snapshot is missing'):
            store.load()
    finally:
        store.close()

    with ProjectService.create(*pair, 'Retry', root) as created:
        assert created.project.name == 'Retry'


def test_torn_database_is_refused_with_a_document_not_a_traceback(tmp_path, capsys):
    root = make_sample(tmp_path / 'case')
    data = _database(root).read_bytes()
    _database(root).write_bytes(data[: len(data) // 3])  # a torn write: only the first third reached the disk
    code, out, err = run_main(['rank', root, '--json'], capsys)
    assert_clean(code, out, err)
    assert code == cli.ENVIRONMENT, err[-300:]
    documents = json_documents(out)
    assert len(documents) == 1 and documents[0]['status'] == 'failed'
    assert documents[0]['error'].startswith('PT-')


def test_garbage_database_is_refused_with_a_pt_code(tmp_path):
    root = make_sample(tmp_path / 'case')
    _database(root).write_bytes(os.urandom(4096))
    with pytest.raises(ValueError, match=r'^PT-'):
        ProjectService.open(root)


def _tamper(root, sql: str, *params) -> None:
    connection = sqlite3.connect(_database(root))
    try:
        with connection:
            connection.execute(sql, params)
    finally:
        connection.close()


@pytest.mark.parametrize(('sql', 'params', 'prefix'), [
    ("UPDATE current_snapshot SET payload = replace(payload, '\"name\"', '\"nAme\"') WHERE singleton = 1", (),
     'PT-STORAGE: project snapshot hash failed'),
    ('DELETE FROM current_snapshot', (), 'PT-STORAGE: project snapshot is missing'),
    ('PRAGMA user_version = 99', (), 'PT-SCHEMA: unsupported database version 99'),
], ids=['payload-bit-flip', 'snapshot-row-deleted', 'future-schema-version'])
def test_tampered_store_is_refused_with_its_contract_code(tmp_path, sql, params, prefix):
    root = make_sample(tmp_path / 'case')
    _tamper(root, sql, *params)
    with pytest.raises(ValueError) as refused:
        ProjectService.open(root)
    assert str(refused.value).startswith(prefix), str(refused.value)
