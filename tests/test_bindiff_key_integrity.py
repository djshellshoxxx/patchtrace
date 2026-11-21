"""Authored SQLite controls for identity keys and algorithm provenance."""
from __future__ import annotations

import sqlite3

import pytest
from bindiff_builder import NEW, OLD, build
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.secondary import bindiff
from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError


def _algorithms_without_constraints(path, rows):
    with sqlite3.connect(path) as db:
        db.execute('DROP TABLE functionalgorithm')
        db.execute('CREATE TABLE functionalgorithm (id, name)')
        db.executemany('INSERT INTO functionalgorithm VALUES (?, ?)', rows)


@pytest.mark.parametrize('prefix', [
    'CREATE\nVIRTUAL', 'CREATE\tVIRTUAL', 'CREATE /**/ VIRTUAL', 'CREATE' + ' ' * 32 + 'VIRTUAL',
])
@pytest.mark.parametrize('forged_rootpage', [False, True])
def test_obfuscated_virtual_schema_is_refused(tmp_path, prefix, forged_rootpage):
    path = build(tmp_path / 'virtual.BinDiff')
    with sqlite3.connect(path) as db:
        db.execute('CREATE VIRTUAL TABLE vt USING rtree(id,a,b)')
        # An untrusted database need not retain SQLite's normalized CREATE spelling.
        db.execute('PRAGMA writable_schema=ON')
        db.execute("UPDATE sqlite_master SET sql=replace(sql,'CREATE VIRTUAL',?) WHERE name='vt'", (prefix,))
        assert db.execute("SELECT rootpage FROM sqlite_master WHERE name='vt'").fetchone() == (0,)
        if forged_rootpage:
            db.execute("UPDATE sqlite_master SET rootpage=2 WHERE name='vt'")
    with sqlite3.connect(path) as db:
        assert ('main', 'vt', 'virtual') in [row[:3] for row in db.execute('PRAGMA main.table_list')]
    with pytest.raises(SecondaryError, match='virtual table') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'


def test_unavailable_sqlite_classifier_fails_closed(tmp_path, monkeypatch):
    path = build(tmp_path / 'unsupported.BinDiff')
    before = path.read_bytes()
    connect = sqlite3.connect

    class WithoutTableList(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == 'PRAGMA main.table_list':
                # SQLite silently returns no rows for an unknown PRAGMA.
                return super().execute('SELECT 1 WHERE 0')
            return super().execute(sql, *args, **kwargs)

    monkeypatch.setattr(bindiff.sqlite3, 'connect',
                        lambda *a, **kw: connect(*a, **kw, factory=WithoutTableList))
    with pytest.raises(SecondaryError, match='schema classification') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-UNSUPPORTED'
    assert path.read_bytes() == before


@pytest.mark.parametrize('argument, expected', [(None, sqlite3.SQLITE_OK), ('function', sqlite3.SQLITE_DENY)])
def test_classifier_authorizer_allows_only_argument_free_inventory(argument, expected):
    assert bindiff._authorizer(sqlite3.SQLITE_PRAGMA, 'table_list', argument, 'main', None) == expected


@pytest.mark.parametrize('second_name', ['original', 'contradicting'])
@pytest.mark.parametrize('reverse', [False, True])
def test_duplicate_algorithm_id_is_refused_in_every_row_order(tmp_path, second_name, reverse):
    path = build(tmp_path / 'duplicate.BinDiff')
    rows = [(7, 'original'), (3, 'other'), (7, second_name)]
    _algorithms_without_constraints(path, list(reversed(rows)) if reverse else rows)
    with pytest.raises(SecondaryError, match='duplicate functionalgorithm id') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'


@pytest.mark.parametrize('key', [None, 7.0, '7', b'7'])
def test_noninteger_algorithm_definition_is_refused(tmp_path, key):
    path = build(tmp_path / 'algorithm-type.BinDiff')
    _algorithms_without_constraints(path, [(key, 'invalid'), (3, 'other')])
    with pytest.raises(SecondaryError, match='functionalgorithm id must be an integer') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'


@pytest.mark.parametrize('key', [7.0, '7', b'7', None])
def test_noninteger_function_algorithm_reference_is_refused(tmp_path, key):
    path = build(tmp_path / 'reference-type.BinDiff')
    with sqlite3.connect(path) as db:
        # Remove affinity so REAL and TEXT values remain distinguishable from INTEGER.
        db.execute('ALTER TABLE function RENAME TO original_function')
        columns = db.execute('PRAGMA table_info(original_function)').fetchall()
        names = [row[1] for row in columns]
        db.execute('CREATE TABLE function (' + ','.join(names) + ')')
        db.execute('INSERT INTO function SELECT * FROM original_function')
        db.execute('DROP TABLE original_function')
        db.execute('UPDATE function SET algorithm=? WHERE id=1', (key,))
    with pytest.raises(SecondaryError, match='function.algorithm must be an integer') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'


@pytest.mark.parametrize('table,column', [('file', 'id'), ('metadata', 'file1'), ('metadata', 'file2')])
def test_noninteger_pair_reference_is_refused(tmp_path, table, column):
    path = build(tmp_path / 'pair-type.BinDiff')
    with sqlite3.connect(path) as db:
        db.execute(f'ALTER TABLE {table} RENAME TO original_pair')
        columns = db.execute('PRAGMA table_info(original_pair)').fetchall()
        names = [row[1] for row in columns]
        db.execute(f'CREATE TABLE {table} (' + ','.join(names) + ')')
        db.execute(f'INSERT INTO {table} SELECT * FROM original_pair')
        db.execute('DROP TABLE original_pair')
        db.execute(f'UPDATE {table} SET {column}=CAST({column} AS REAL)')
    with pytest.raises(SecondaryError) as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'


def test_unconstrained_unique_integer_keys_preserve_unknown_algorithm_names(tmp_path):
    path = build(tmp_path / 'unique.BinDiff')
    _algorithms_without_constraints(path, [(7, 'future algorithm'), (3, 'other')])
    result = import_bindiff(path, OLD, NEW)
    assert [match.algorithm for match in result.matches] == ['future algorithm', 'other']


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(ident=st.integers(-(2**31), 2**31 - 1), same_name=st.booleans())
def test_duplicate_algorithm_key_property(tmp_path_factory, ident, same_name):
    path = build(tmp_path_factory.mktemp('algorithm-fuzz') / 'x.BinDiff', functions=[])
    _algorithms_without_constraints(path, [(ident, 'one'), (ident, 'one' if same_name else 'two')])
    with pytest.raises(SecondaryError, match='duplicate functionalgorithm id') as error:
        import_bindiff(path, OLD, NEW)
    assert error.value.code == 'PT-SECONDARY-INPUT'
