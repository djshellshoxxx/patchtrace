"""Synthetic Diaphora result databases for tests (SPEC-DA-01). NOT produced by Diaphora: the table shapes follow the
upstream `save_results()` layout recorded in the spec, so these prove parser behaviour only, never live compatibility."""
from __future__ import annotations

import sqlite3
from pathlib import Path

RESULT_COLUMNS = '(type TEXT, line INTEGER, address TEXT, name TEXT, address2 TEXT, name2 TEXT, ratio TEXT, ' \
                 'nodes1 INTEGER, nodes2 INTEGER, description TEXT)'
UNMATCHED_COLUMNS = '(type TEXT, line INTEGER, address TEXT, name TEXT)'


def make_result(path: Path, results=(), unmatched=(), *, version='3.4.3', config=True, extra_sql=()) -> Path:
    db = sqlite3.connect(path)
    if config:
        db.execute('CREATE TABLE config (main_db TEXT, diff_db TEXT, version TEXT, date TEXT)')
        db.execute('INSERT INTO config VALUES (?,?,?,?)', ('C:\\secret-host\\old.sqlite', 'C:\\secret-host\\new.sqlite',
                                                           version, '2026-10-14'))
    db.execute(f'CREATE TABLE results {RESULT_COLUMNS}')
    db.execute(f'CREATE TABLE unmatched {UNMATCHED_COLUMNS}')
    for i, row in enumerate(results):
        db.execute('INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?,?)', (row[0], i, *row[1:]))
    for i, row in enumerate(unmatched):
        db.execute('INSERT INTO unmatched VALUES (?,?,?,?)', (row[0], i, *row[1:]))
    for sql in extra_sql:
        db.execute(sql)
    db.commit()
    db.close()
    return path


def row(category='best', a1='180001000', n1='old_fn', a2='180001010', n2='new_fn', ratio='0.980', nodes1=5, nodes2=6,
        description='Same name'):
    return (category, a1, n1, a2, n2, ratio, nodes1, nodes2, description)
