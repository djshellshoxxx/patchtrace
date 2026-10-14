"""SPEC-29 §7.2 / P4: the `.BinDiff` importer treats the database as hostile.

Triggers, views and virtual tables are rejected outright (a view named like a required table must not be
read), connections run with trusted_schema=OFF, defensive mode and a SELECT-only authorizer, and random
byte corruption never escapes as a raw sqlite3 exception.
"""
from __future__ import annotations

import sqlite3

import pytest
from bindiff_builder import NEW, OLD, build
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.secondary import bindiff
from patchtrace.secondary.bindiff import import_bindiff
from patchtrace.secondary.contracts import SecondaryError


@pytest.mark.parametrize('extra, needle', [
    (('CREATE TRIGGER t AFTER INSERT ON file BEGIN DELETE FROM function; END',), 'trigger'),
    (('CREATE VIEW v AS SELECT * FROM function',), 'view'),
    (('CREATE VIRTUAL TABLE vt USING rtree(id, a, b)',), 'virtual table'),
])
def test_schema_objects_beyond_plain_tables_are_rejected(tmp_path, extra, needle):
    with pytest.raises(SecondaryError, match=needle) as info:
        import_bindiff(build(tmp_path / 'x.BinDiff', extra=extra), OLD, NEW)
    assert info.value.code == 'PT-SECONDARY-INPUT'


def test_view_named_like_required_table_is_rejected_not_read(tmp_path):
    path = build(tmp_path / 'x.BinDiff', extra=(
        'ALTER TABLE function RENAME TO real_function',
        'CREATE VIEW function AS SELECT * FROM real_function',
    ))
    with pytest.raises(SecondaryError, match='view'):
        import_bindiff(path, OLD, NEW)


def test_plain_indexes_on_real_tables_are_allowed(tmp_path):
    path = build(tmp_path / 'x.BinDiff', extra=('CREATE INDEX i ON function(address1)',))
    assert len(import_bindiff(path, OLD, NEW).matches) == 2


def test_connection_is_hardened(tmp_path, monkeypatch):
    seen = {}
    real = bindiff._read

    def spy(db, *args, **kwargs):
        seen['trusted_schema'] = db.execute('PRAGMA trusted_schema').fetchone()[0]
        seen['query_only'] = db.execute('PRAGMA query_only').fetchone()[0]
        if hasattr(db, 'getconfig') and hasattr(sqlite3, 'SQLITE_DBCONFIG_DEFENSIVE'):
            seen['defensive'] = db.getconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE)
        return real(db, *args, **kwargs)

    monkeypatch.setattr(bindiff, '_read', spy)
    monkeypatch.setattr(bindiff, '_authorizer', lambda *a: sqlite3.SQLITE_OK)  # let the spy's PRAGMAs run
    import_bindiff(build(tmp_path / 'x.BinDiff'), OLD, NEW)
    assert seen['trusted_schema'] == 0 and seen['query_only'] == 1
    assert seen.get('defensive', True) in (True, 1)


@pytest.mark.parametrize('action, args', [
    (sqlite3.SQLITE_READ, ('function', 'name1', 'main', None)),
    (sqlite3.SQLITE_SELECT, (None, None, None, None)),
    (sqlite3.SQLITE_FUNCTION, (None, 'count', None, None)),
])
def test_authorizer_allows_reads_of_fixed_tables(action, args):
    assert bindiff._authorizer(action, *args) == sqlite3.SQLITE_OK


@pytest.mark.parametrize('action, args', [
    (sqlite3.SQLITE_ATTACH, ('x.db', None, None, None)),
    (sqlite3.SQLITE_PRAGMA, ('writable_schema', None, None, None)),
    (sqlite3.SQLITE_INSERT, ('function', None, 'main', None)),
    (sqlite3.SQLITE_CREATE_TRIGGER, ('t', 'function', 'main', None)),
    (sqlite3.SQLITE_READ, ('evil', 'x', 'main', None)),
    (sqlite3.SQLITE_FUNCTION, (None, 'load_extension', None, None)),
])
def test_authorizer_denies_everything_else(action, args):
    assert bindiff._authorizer(action, *args) == sqlite3.SQLITE_DENY


def test_read_through_triggered_view_name_is_denied_by_authorizer(tmp_path):
    # Layer 2 on its own: even if the schema check were bypassed, reading an unknown table is denied.
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE evil(x)')
    db.set_authorizer(bindiff._authorizer)
    with pytest.raises(sqlite3.DatabaseError):
        db.execute('SELECT x FROM evil').fetchall()
    db.close()


def test_expected_hashes_override_pairs_file_hash_with_bound_ids(tmp_path):
    # Asserted (non-SHA-256) bindings: BinDiff copies BinExport executable_id into file.hash, so the importer
    # compares with the bound ids while the set keeps the project artifact hashes.
    md5_old, md5_new = '1' * 32, '2' * 32
    path = build(tmp_path / 'x.BinDiff', hashes=(md5_old, md5_new))
    result = import_bindiff(path, OLD, NEW, expected_hashes=(md5_old, md5_new))
    assert (result.older_sha256, result.newer_sha256) == (OLD, NEW)
    with pytest.raises(SecondaryError) as info:
        import_bindiff(path, OLD, NEW, expected_hashes=(md5_new, md5_old))
    assert info.value.code == 'PT-SECONDARY-ORIENTATION'


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_byte_mutations_raise_secondary_error_never_raw_sqlite(tmp_path_factory, data):
    base = build(tmp_path_factory.mktemp('fuzz') / 'x.BinDiff').read_bytes()
    blob = bytearray(base)
    for _ in range(data.draw(st.integers(1, 8))):
        index = data.draw(st.integers(0, len(blob) - 1))
        blob[index] = data.draw(st.integers(0, 255))
    target = tmp_path_factory.mktemp('fuzz') / 'm.BinDiff'
    target.write_bytes(bytes(blob))
    try:
        import_bindiff(target, OLD, NEW)
    except SecondaryError:
        pass
