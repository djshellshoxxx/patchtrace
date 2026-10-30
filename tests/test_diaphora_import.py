"""SPEC-DA-01 Mode A: guard, parser, address mapping, provenance. Synthetic databases only (see diaphora_support)."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading

import pytest
from diaphora_support import make_result, row

from patchtrace.diaphora import address_map, provenance, result_import, sqlite_guard
from patchtrace.diaphora.address_map import ImageMap
from patchtrace.diaphora.contracts import DiaphoraDiffManifest, DiaphoraError, DiaphoraMatchSet

OLDER, NEWER = 'a' * 64, 'b' * 64
MAP = ImageMap(0x180000000, 0x2000)


def do_import(path, **kw):
    args = dict(older_sha256=OLDER, newer_sha256=NEWER, trust='user-attested', older_map=MAP, newer_map=MAP)
    args.update(kw)
    return result_import.import_result(path, **args)


def code_of(call):
    with pytest.raises(DiaphoraError) as exc:
        call()
    return exc.value.code


# ---- guard ----------------------------------------------------------------------------------

def test_not_sqlite_and_empty_and_link_are_refused(tmp_path):
    junk = tmp_path / 'junk.diaphora'
    junk.write_bytes(b'not a database' * 100)
    assert code_of(lambda: result_import.inspect_result(junk)) == 'PT-DIAPHORA-DB'
    empty = tmp_path / 'empty.diaphora'
    empty.write_bytes(b'')
    assert code_of(lambda: result_import.inspect_result(empty)) == 'PT-DIAPHORA-DB'
    assert code_of(lambda: result_import.inspect_result(tmp_path / 'missing')) == 'PT-DIAPHORA-INPUT'
    real = make_result(tmp_path / 'r.diaphora', [row()])
    if os.name != 'nt':
        link = tmp_path / 'link.diaphora'
        link.symlink_to(real)
        assert code_of(lambda: result_import.inspect_result(link)) == 'PT-DIAPHORA-INPUT'


def test_oversize_is_refused_before_parsing(tmp_path, monkeypatch):
    path = make_result(tmp_path / 'r.diaphora', [row()])
    monkeypatch.setattr(sqlite_guard, 'MAX_DB_BYTES', 1024)
    assert code_of(lambda: result_import.inspect_result(path)) == 'PT-DIAPHORA-LIMIT'


def test_missing_table_or_column_is_explicit(tmp_path):
    path = tmp_path / 'r.diaphora'
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE results (type TEXT, address TEXT)')
    db.commit()
    db.close()
    assert code_of(lambda: result_import.inspect_result(path)) == 'PT-DIAPHORA-DB'
    path2 = tmp_path / 'r2.diaphora'
    db = sqlite3.connect(path2)
    db.execute('CREATE TABLE results (type TEXT, line INTEGER, address TEXT, name TEXT, address2 TEXT, name2 TEXT, '
               'ratio TEXT, nodes1 INTEGER, nodes2 INTEGER, description TEXT)')
    db.commit()
    db.close()
    assert code_of(lambda: result_import.inspect_result(path2)) == 'PT-DIAPHORA-DB'     # unmatched missing


def test_connection_cannot_attach_write_or_run_pragmas(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row()])
    with sqlite_guard.open_snapshot(path) as snap:
        for sql in (f"ATTACH DATABASE '{tmp_path / 'x.db'}' AS x", 'DELETE FROM results', 'PRAGMA journal_mode=WAL',
                    "SELECT load_extension('x')", 'CREATE TABLE t(a)'):
            with pytest.raises(sqlite3.Error):
                snap.conn.execute(sql)
        assert snap.count('results') == 1
    assert not (tmp_path / 'x.db').exists()


def test_time_budget_interrupts_a_runaway_query(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row(a1=f'18000{i:04x}') for i in range(300)])
    with sqlite_guard.open_snapshot(path) as snap:
        with pytest.raises(sqlite3.DatabaseError):          # recursive CTEs are denied outright
            snap.conn.execute('WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c')
        snap._deadline[0] = 0.0                              # a legal but huge cross join is stopped by the budget
        with pytest.raises(sqlite3.OperationalError):
            snap.conn.execute('SELECT count(*) FROM results a, results b, results c, results d').fetchone()


def test_snapshot_is_private_and_removed(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row()])
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with sqlite_guard.open_snapshot(path) as snap:
        assert snap.sha256 == before
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before        # input untouched


def test_cancel_before_copy(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row()])
    flag = threading.Event()
    flag.set()
    assert code_of(lambda: result_import.import_result(
        path, older_sha256=OLDER, newer_sha256=NEWER, trust='user-attested', older_map=MAP, newer_map=MAP,
        cancel=flag)) == 'PT-DIAPHORA-CANCEL'


# ---- parser ---------------------------------------------------------------------------------

def test_inspect_counts_and_never_reports_paths(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row('best'), row('partial', a1='180001100', a2='180001110'),
                                                  row('multimatch', a1='180001200', a2='180001210')],
                       [('primary', '180002000', 'only_old'), ('secondary', '180002100', 'only_new')])
    info = result_import.inspect_result(path)
    assert info.counts == {'best': 1, 'partial': 1, 'unreliable': 0, 'multimatch': 1} and info.unmatched == 2
    assert info.version == '3.4.3' and 'results' in info.tables
    assert 'secret-host' not in repr(info)


def test_full_import_maps_rvas_and_orientation(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row()], [('primary', '180001800', 'only_old'),
                                                         ('secondary', '180001900', 'only_new')])
    result = do_import(path)
    assert isinstance(result, DiaphoraMatchSet) and result.engine_version == '3.4.3'
    match = result.matches[0]
    assert (match.older_rva, match.newer_rva, match.address_status) == (0x1000, 0x1010, 'verified-rva')
    assert (match.ratio_milli, match.ratio_transform, match.ratio_text) == (980, 'direct', '0.980')
    assert [(u.side, u.rva) for u in result.unmatched] == [('older', 0x1800), ('newer', 0x1900)]
    assert 'secret-host' not in result.model_dump_json()
    assert DiaphoraMatchSet.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize('ratio, milli, transform', [
    ('1.01', 1000, 'capped-bonus'), ('1', 1000, 'direct'), ('0', 0, 'direct'), ('', None, 'unavailable'),
    ('nan', None, 'unavailable'), ('inf', None, 'unavailable'), ('-0.5', None, 'unavailable'),
    ('7.5', None, 'unavailable'), ('abc', None, 'unavailable'), (None, None, 'unavailable'),
])
def test_ratio_is_preserved_and_never_invented(tmp_path, ratio, milli, transform):
    path = make_result(tmp_path / 'r.diaphora', [row(ratio=ratio)])
    match = do_import(path).matches[0]
    assert (match.ratio_milli, match.ratio_transform) == (milli, transform)
    assert match.ratio_text == ('' if ratio is None else ratio)


def test_capped_ratio_adds_a_limitation(tmp_path):
    result = do_import(make_result(tmp_path / 'r.diaphora', [row(ratio='1.01')]))
    assert any('exceeded 1.0' in text for text in result.limitations)


@pytest.mark.parametrize('bad', [row('great'), row(a1='zz'), row(a2='180001010; DROP TABLE results'), row(a1=''),
                                 row(n1='x\x00y'), row(a1='1' * 17), row(nodes1='many')])
def test_hostile_rows_fail_closed(tmp_path, bad):
    path = make_result(tmp_path / 'r.diaphora', [bad])
    assert code_of(lambda: do_import(path)) in {'PT-DIAPHORA-INPUT', 'PT-DIAPHORA-LIMIT'}


def test_sql_looking_names_are_plain_text(tmp_path):
    name = "x'); DROP TABLE results;--"
    result = do_import(make_result(tmp_path / 'r.diaphora', [row(n1=name, description='<script>alert(1)</script>')]))
    assert result.matches[0].older_name == name and result.matches[0].heuristic == '<script>alert(1)</script>'


def test_unknown_unmatched_side_and_oversize_text(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [], [('both', '180002000', 'x')])
    assert code_of(lambda: do_import(path)) == 'PT-DIAPHORA-INPUT'
    path = make_result(tmp_path / 'r2.diaphora', [row(n1='n' * 5000)])
    assert code_of(lambda: do_import(path)) == 'PT-DIAPHORA-LIMIT'


def test_duplicates_are_counted_and_multimatch_alternatives_kept(tmp_path):
    rows = [row(), row(ratio='0.5'), row('multimatch', a2='180001020'), row('multimatch', a2='180001030')]
    result = do_import(make_result(tmp_path / 'r.diaphora', rows))
    assert result.duplicate_rows == 1 and len(result.matches) == 3
    assert [m.category for m in result.matches].count('multimatch') == 2


def test_row_budget(tmp_path, monkeypatch):
    path = make_result(tmp_path / 'r.diaphora', [row(a1=f'18000{i:04x}') for i in range(5)])
    monkeypatch.setattr(result_import, 'MAX_MATCH_ROWS', 4)
    assert code_of(lambda: do_import(path)) == 'PT-DIAPHORA-LIMIT'
    assert code_of(lambda: result_import.inspect_result(path)) == 'PT-DIAPHORA-LIMIT'


def test_config_table_is_optional(tmp_path):
    result = do_import(make_result(tmp_path / 'r.diaphora', [row()], config=False))
    assert result.engine_version == 'unknown'


# ---- addresses ------------------------------------------------------------------------------

def test_parse_ea():
    assert address_map.parse_ea('0x401000') == 0x401000 and address_map.parse_ea(' 00401000 ') == 0x401000
    for bad in ('', 'xyz', '0x', '1' * 17, None, 12):
        with pytest.raises(DiaphoraError):
            address_map.parse_ea(bad)


def test_image_map_statuses():
    m = ImageMap(0x180000000, 0x2000)
    assert m.rva(0x180001000) == (0x1000, 'verified-rva')
    assert m.rva(0x180002000)[1] == 'external-ea-only'          # one past the image
    assert m.rva(0x1000)[1] == 'ambiguous'                      # could be an RVA of a rebased database
    assert m.rva(0x7FF000000000)[1] == 'external-ea-only'
    assert ImageMap(None, None).rva(0x180001000)[1] == 'ambiguous'
    assert ImageMap(0, 0x2000).rva(0x1000) == (0x1000, 'verified-rva')
    assert address_map.combine('verified-rva', 'ambiguous') == 'ambiguous'
    assert address_map.combine('external-ea-only', 'verified-rva') == 'external-ea-only'


def test_unmappable_rows_stay_visible_not_verified(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row(a1='10000000', a2='10000010')])
    match = do_import(path).matches[0]
    assert match.address_status == 'external-ea-only' and match.older_rva is None
    assert any('never count as agreeing' in text for text in do_import(path).limitations)


# ---- provenance -----------------------------------------------------------------------------

def manifest(**kw):
    base = dict(contract='diaphora-diff/1', orientation='older->newer', older_binary_sha256=OLDER,
                newer_binary_sha256=NEWER, result_sha256='c' * 64)
    return DiaphoraDiffManifest(**{**base, **kw})


def test_bind_matrix():
    assert provenance.bind(manifest(), False, 'c' * 64, OLDER, NEWER) == 'manifest-bound'
    assert provenance.bind(None, True, 'c' * 64, OLDER, NEWER) == 'user-attested'
    assert code_of(lambda: provenance.bind(None, False, 'c' * 64, OLDER, NEWER)) == 'PT-DIAPHORA-PROVENANCE'
    assert code_of(lambda: provenance.bind(manifest(result_sha256='d' * 64), False, 'c' * 64, OLDER, NEWER)) \
        == 'PT-DIAPHORA-PROVENANCE'
    assert code_of(lambda: provenance.bind(manifest(older_binary_sha256=NEWER, newer_binary_sha256=OLDER),
                                           False, 'c' * 64, OLDER, NEWER)) == 'PT-DIAPHORA-ORIENTATION'
    assert code_of(lambda: provenance.bind(manifest(newer_binary_sha256='e' * 64), False, 'c' * 64, OLDER, NEWER)) \
        == 'PT-DIAPHORA-PAIR'


def test_load_manifest_strict(tmp_path):
    good = tmp_path / 'm.json'
    good.write_text(manifest().model_dump_json())
    assert provenance.load_manifest(good).older_binary_sha256 == OLDER
    for text in ('{', json.dumps({**json.loads(manifest().model_dump_json()), 'extra': 1}), '[]',
                 json.dumps({**json.loads(manifest().model_dump_json()), 'older_binary_sha256': 'XY'})):
        bad = tmp_path / 'bad.json'
        bad.write_text(text)
        assert code_of(lambda bad=bad: provenance.load_manifest(bad)) == 'PT-DIAPHORA-PROVENANCE'
    big = tmp_path / 'big.json'
    big.write_text(' ' * (provenance.MANIFEST_LIMIT + 1))
    assert code_of(lambda: provenance.load_manifest(big)) == 'PT-DIAPHORA-PROVENANCE'


def test_result_changed_after_binding_is_refused(tmp_path):
    path = make_result(tmp_path / 'r.diaphora', [row()])
    with pytest.raises(DiaphoraError) as exc:
        do_import(path, expected_result_sha256='f' * 64)
    assert exc.value.code == 'PT-DIAPHORA-PROVENANCE'
