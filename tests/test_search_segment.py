from __future__ import annotations

import os
import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from patchtrace.search import paths, segment
from patchtrace.search.errors import SearchError
from patchtrace.search.limits import APPLICATION_ID, DEFAULT_LIMITS, SearchLimits
from patchtrace.search.normalize import fold
from patchtrace.search.query import match_substring, match_words, parse_query
from patchtrace.search.segment import SegmentDoc, build_segment, open_segment, try_open
from patchtrace.search.tokenize import code_idents, name_words

DIGEST = '0123456789abcdef'
UTC = '2026-10-14T08:00:00Z'
ALL_SETS = ('code', 'name', 'text')
NAMES = ['RtlCopyMemory', 'ProbeForRead', 'FUN_140001a40', 'NtQuerySystemInformation', 'École']


def make_docs(count: int = 5) -> list[SegmentDoc]:
    docs = []
    for i in range(count):
        name = NAMES[i % len(NAMES)] + (str(i) if i >= len(NAMES) else '')
        body = f'if (ProbeForRead(p, n)) {name}(d, p, n); // {i}'
        docs.append(SegmentDoc(
            kind='function', side='newer' if i % 2 else 'older', subject=f'f:{i}', display=name, ref=i, rva=0x1000 + i,
            value_sha='b' * 64 if i == 0 else None, name_raw=fold(name), name_words=name_words(name),
            code_body=body, code_idents=code_idents(body), text_title=name, text_body=f'note about {name}'))
    return docs


def build(directory: Path, docs=None, sets=ALL_SETS, digest=DIGEST, **kwargs):
    kwargs.setdefault('built_utc', UTC)
    return build_segment(directory, 'fn', digest, make_docs() if docs is None else docs, sets, **kwargs)


def listing(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir())


def rowids(conn: sqlite3.Connection, table: str, expression: str) -> list[int]:
    sql = f'SELECT rowid FROM {table} WHERE {table} MATCH ? ORDER BY rowid'
    return [row[0] for row in conn.execute(sql, (expression,))]


@pytest.fixture
def directory(tmp_path) -> Path:
    return tmp_path / 'índice dir' / 'proj'  # space and non-ASCII: the URI open must cope on Windows


@pytest.fixture
def published(directory) -> Path:
    return build(directory).path


def test_build_publishes_one_digest_named_file(directory):
    info = build(directory)
    assert listing(directory) == [f'fn-{DIGEST}.sqlite3'] and info.path == directory / f'fn-{DIGEST}.sqlite3'
    assert (info.group, info.digest16, info.tables, info.docs, info.truncated) == ('fn', DIGEST, ALL_SETS, 5, False)
    assert info.built_utc == UTC and info.sqlite_version == sqlite3.sqlite_version and info.size_bytes > 0


def test_open_reads_meta_and_identity_pragmas(published):
    with open_segment(published) as seg:
        assert seg.info == segment.SegmentInfo(
            'fn', DIGEST, ALL_SETS, 5, seg.info.size_bytes, False, UTC, sqlite3.sqlite_version, published)
        with pytest.raises(sqlite3.DatabaseError):
            seg.conn.execute('PRAGMA application_id')  # the authorizer allows no PRAGMA reads but data_version
    raw = sqlite3.connect(published)
    assert raw.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID
    assert raw.execute('PRAGMA user_version').fetchone()[0] == 1
    raw.close()


def test_queries_run_against_every_table_and_rowid_is_doc_id(published):
    with open_segment(published) as seg:
        db = seg.conn
        assert rowids(db, 'fts_name', match_words(parse_query('copy'), 'fts_name')) == [1]
        assert rowids(db, 'tri_name', match_substring(parse_query('opymem'))) == [1]
        assert rowids(db, 'fts_name', match_words(parse_query('ecole'), 'fts_name')) == [5]
        assert rowids(db, 'fts_code', match_words(parse_query('probe'), 'fts_code', ('idents',))) == [1, 2, 3, 4, 5]
        assert rowids(db, 'fts_text', match_words(parse_query('"note about rtlcopymemory"'), 'fts_text')) == [1]
        row = db.execute('SELECT kind, side, subject, display, ref, rva, flags, value_sha FROM doc WHERE id = 1').fetchone()
        assert row == ('function', 'older', 'f:0', 'RtlCopyMemory', 0, 0x1000, 0, 'b' * 64)
        assert db.execute('SELECT count(*) FROM doc WHERE value_sha = ?', ('b' * 64,)).fetchone() == (1,)
        found = db.execute("SELECT snippet(fts_code, 0, char(2), char(3), '...', 8), bm25(fts_code) FROM fts_code "
                           "WHERE fts_code MATCH '\"rtlcopymemory\"'").fetchall()
        assert found and '\x02RtlCopyMemory\x03' in found[0][0] and found[0][1] < 0


def test_only_the_requested_table_sets_exist(directory):
    name_only = [replace(d, code_body=None, code_idents='', text_title=None, text_body='') for d in make_docs()]
    info = build(directory, docs=name_only, sets=('name',))
    with open_segment(info.path) as seg:
        tables = {r[0] for r in seg.conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert {'fts_name', 'tri_name', 'doc', 'meta'} <= tables and 'fts_code' not in tables and 'fts_text' not in tables
        assert seg.info.tables == ('name',)


def test_docs_without_text_for_a_table_are_still_listed(directory):
    plain = SegmentDoc(kind='build', side=None, subject='pe', display='machine x64', ref=0)
    info = build(directory, docs=[plain], sets=('text',))
    with open_segment(info.path) as seg:
        assert seg.conn.execute('SELECT count(*) FROM doc').fetchone() == (1,)
        assert seg.conn.execute('SELECT count(*) FROM fts_text').fetchone() == (0,)


def test_build_is_deterministic_for_equal_input(tmp_path):
    first, second = build(tmp_path / 'a'), build(tmp_path / 'b')
    assert first.path.read_bytes() == second.path.read_bytes()
    assert first.docs == second.docs == 5


def test_doc_order_is_index_order(directory):
    docs = list(reversed(make_docs()))
    with open_segment(build(directory, docs=docs).path) as seg:
        assert [r[0] for r in seg.conn.execute('SELECT subject FROM doc ORDER BY id')] == [f'f:{i}' for i in (4, 3, 2, 1, 0)]


def test_hostile_text_is_escaped_before_it_is_indexed(directory):
    hostile = '\x02hit\x03 ‮evil\x00 \ud800'
    doc = SegmentDoc(kind='string', side='newer', subject='s', display=hostile, extra=hostile, ref=0, text_title=hostile,
                     text_body=hostile + '\nline two', code_body=None)
    with open_segment(build(directory, docs=[doc], sets=('text',)).path) as seg:
        row = seg.conn.execute('SELECT display, extra FROM doc').fetchone()
        title, body = seg.conn.execute('SELECT title, body FROM fts_text').fetchone()
        for value in (*row, title, body):
            assert not set(value) & {'\x02', '\x03', '\x00', '‮', '\ud800'}
        assert '\\x02hit\\x03' in row[0] and body.endswith('\nline two')


def test_text_is_capped(directory):
    limits = replace(DEFAULT_LIMITS, field_bytes=100)
    doc = SegmentDoc(kind='note', side=None, subject='n' * 200, display='d' * 500, ref=0, text_title='t' * 1000, text_body='b' * 1000)
    with open_segment(build(directory, docs=[doc], sets=('text',), limits=limits).path) as seg:
        subject, display = seg.conn.execute('SELECT subject, display FROM doc').fetchone()
        title, body = seg.conn.execute('SELECT title, body FROM fts_text').fetchone()
        assert (len(subject), len(display), len(title), len(body)) == (64, 200, 100, 100) and title.endswith('...')


def test_max_docs_marks_the_segment_truncated(directory):
    limits = replace(DEFAULT_LIMITS, cancel_check_docs=2)
    info = build(directory, docs=make_docs(7), max_docs=5, limits=limits)
    assert (info.docs, info.truncated) == (5, True)
    exact = build(directory, docs=make_docs(5), max_docs=5, limits=limits, digest='1' * 16)
    assert (exact.docs, exact.truncated) == (5, False)
    with open_segment(info.path) as seg:
        assert seg.info.truncated and seg.conn.execute('SELECT count(*) FROM doc').fetchone() == (5,)


# ------------------------------------------------------------------------------------ crash points

def test_cancel_removes_the_staging_file_and_publishes_nothing(directory):
    calls = []

    def cancel() -> bool:
        calls.append(1)
        return len(calls) == 2

    with pytest.raises(SearchError) as err:
        build(directory, docs=make_docs(10), cancel=cancel, limits=replace(DEFAULT_LIMITS, cancel_check_docs=3))
    assert err.value.code == 'PT-SEARCH-CANCEL' and err.value.exit_code == 5 and len(calls) == 2
    assert listing(directory) == []


def test_deadline_is_checked_with_the_injected_clock(directory):
    ticks = iter(range(0, 10_000, 100))
    with pytest.raises(SearchError) as err:
        build(directory, clock=lambda: next(ticks), limits=replace(DEFAULT_LIMITS, segment_build_s=150.0, cancel_check_docs=2))
    assert err.value.code == 'PT-SEARCH-TIMEOUT' and err.value.recoverable
    assert listing(directory) == []


def test_a_failing_source_leaves_no_staging_or_partial_file(directory):
    def failing():
        yield from make_docs(3)
        raise RuntimeError('adapter died')

    with pytest.raises(RuntimeError):
        build(directory, docs=failing(), limits=replace(DEFAULT_LIMITS, cancel_check_docs=1))
    assert listing(directory) == []


@pytest.mark.parametrize('bad', [
    dict(kind='bogus'), dict(side='both'), dict(value_sha='XYZ'), dict(ref=-1), dict(rva=-1), dict(rva=1 << 63),
    dict(flags=-1), dict(code_body='x')], ids=['kind', 'side', 'sha', 'ref', 'rva-neg', 'rva-big', 'flags', 'table-missing'])
def test_invalid_documents_are_source_errors(directory, bad):
    fields = dict(code_body=None, code_idents='', text_title=None, text_body='') | bad
    doc = replace(make_docs(1)[0], **fields)
    with pytest.raises(SearchError) as err:
        build(directory, docs=[doc], sets=('name',))
    assert err.value.code == 'PT-SEARCH-SOURCE'
    assert listing(directory) == []


def test_empty_or_unknown_table_sets_are_refused(directory):
    for sets in ((), ('names',)):
        with pytest.raises(SearchError):
            build(directory, sets=sets)


def test_size_limit_removes_the_staging_file(directory):
    with pytest.raises(SearchError) as err:
        build(directory, limits=replace(DEFAULT_LIMITS, bytes_per_project=1000))
    assert err.value.code == 'PT-SEARCH-LIMIT' and listing(directory) == []


def test_failed_replace_without_a_valid_file_is_a_recoverable_store_error(directory, monkeypatch):
    def deny(*_):
        raise PermissionError('locked')

    monkeypatch.setattr(segment.os, 'replace', deny)
    with pytest.raises(SearchError) as err:
        build(directory)
    assert err.value.code == 'PT-SEARCH-STORE' and err.value.recoverable
    assert listing(directory) == []


def test_equal_existing_file_wins_even_while_open(directory, published, monkeypatch):
    before = published.read_bytes()
    with open_segment(published) as reader:
        def forbidden(*_):
            raise AssertionError('an equal published file must not be replaced')

        monkeypatch.setattr(segment.os, 'replace', forbidden)
        info = build(directory, docs=make_docs(5))
        assert info.path == published and info.docs == 5
        assert reader.conn.execute('SELECT count(*) FROM doc').fetchone() == (5,)
    assert published.read_bytes() == before and listing(directory) == [published.name]


def test_failed_replace_is_tolerated_when_an_equal_file_appeared(directory, monkeypatch):
    real_replace = os.replace

    def lose_the_race(src, dst):
        monkeypatch.setattr(segment.os, 'replace', real_replace)
        build(directory)  # another process published the same digest first
        raise PermissionError('locked')  # then ours fails the way an open handle does on Windows

    monkeypatch.setattr(segment.os, 'replace', lose_the_race)
    info = build(directory, built_utc='2026-10-15T00:00:00Z')
    assert info.docs == 5 and info.built_utc == UTC and listing(directory) == [f'fn-{DIGEST}.sqlite3']


def test_a_corrupt_file_at_the_target_name_is_replaced(directory):
    target = paths.segment_path(directory, 'fn', DIGEST)
    directory.mkdir(parents=True)
    target.write_bytes(b'garbage' * 100)
    info = build(directory)
    assert info.path == target
    with open_segment(target) as seg:
        assert seg.info.docs == 5


def test_concurrent_builds_of_different_digests_do_not_collide(directory):
    results, errors = [], []

    def worker(digest: str) -> None:
        try:
            results.append(build(directory, digest=digest).digest16)
        except Exception as exc:  # pragma: no cover - failure path of the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f'{i:016x}',)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors and sorted(results) == [f'{i:016x}' for i in range(4)] and len(listing(directory)) == 4


# ------------------------------------------------------------------------------------ hardened open

DENIED = [
    "INSERT INTO doc(id, kind, subject, display, extra, ref, flags) VALUES (99, 'note', 's', 'd', '', 0, 0)",
    "UPDATE doc SET display = 'x'", 'DELETE FROM doc', 'DROP TABLE doc', 'CREATE TABLE evil(x)',
    "CREATE TRIGGER t AFTER INSERT ON doc BEGIN SELECT 1; END", "ATTACH DATABASE ':memory:' AS other",
    'PRAGMA writable_schema=1', 'PRAGMA journal_mode=DELETE', 'PRAGMA query_only=0',
    "SELECT load_extension('nothing')", 'SELECT random()', 'SELECT hex(1)', 'SELECT sqlite_version()',
    "INSERT INTO fts_name(fts_name) VALUES ('rebuild')", "INSERT INTO fts_name(fts_name, rank) VALUES ('merge', 2)",
    'VACUUM', 'REINDEX', 'ANALYZE', 'SELECT * FROM pragma_table_info(\'doc\')']


@pytest.mark.parametrize('sql', DENIED, ids=[f'deny{i}' for i in range(len(DENIED))])
def test_authorizer_denies_everything_outside_the_allow_list(published, sql):
    with open_segment(published) as seg, pytest.raises(sqlite3.DatabaseError):
        seg.conn.execute(sql).fetchall()


def test_authorizer_allows_the_documented_functions_and_data_version(published):
    with open_segment(published) as seg:
        db = seg.conn
        assert db.execute("SELECT count(*), lower('AB'), length('abc'), instr('abc', 'c'), char(65)").fetchone() == (1, 'ab', 3, 3, 'A')
        assert db.execute('PRAGMA data_version').fetchone() is not None
        assert db.execute("SELECT highlight(fts_name, 0, '[', ']') FROM fts_name WHERE fts_name MATCH '\"rtl\"'").fetchall()
        assert db.execute('SELECT count(*) FROM sqlite_master').fetchone()[0] > 5


def test_open_is_read_only_and_leaves_no_sidecar_files(directory, published):
    before = published.read_bytes()
    with open_segment(published) as seg:
        seg.conn.execute('SELECT * FROM doc').fetchall()
    assert published.read_bytes() == before and listing(directory) == [published.name]


def test_quick_check_runs_once_per_file_version(published):
    key = (str(published), published.stat().st_size, published.stat().st_mtime_ns)
    segment._VERIFIED.discard(key)
    open_segment(published).close()
    assert key in segment._VERIFIED
    size = len(segment._VERIFIED)
    open_segment(published).close()
    assert len(segment._VERIFIED) == size


def test_interrupt_stops_a_running_query(published):
    with open_segment(published) as seg:
        seg.interrupt()  # idle interrupt is a no-op and must not break the next statement
        assert seg.conn.execute('SELECT count(*) FROM doc').fetchone() == (5,)


# ------------------------------------------------------------------------------------ corruption

def corrupt_copy(source: Path, mutate) -> Path:
    target = source.with_name('copy') / source.name
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(mutate(bytearray(source.read_bytes())))
    return target


def many_docs_segment(directory: Path) -> Path:
    return build(directory, docs=make_docs(3000), limits=replace(DEFAULT_LIMITS, cancel_check_docs=500)).path


def smash(page: int):
    def mutate(data: bytearray) -> bytearray:
        size = int.from_bytes(data[16:18], 'big') or 65536
        data[page * size:(page + 1) * size] = b'\xff' * size
        return data
    return mutate


@pytest.mark.parametrize('name,mutate', [
    ('truncated', lambda d: d[:len(d) // 2]), ('empty', lambda d: bytearray()), ('header-only', lambda d: d[:100]),
    ('not-sqlite', lambda d: bytearray(b'x' * 5000)), ('text-page', smash(3)), ('later-page', smash(40)),
    ('zeroed-tail', lambda d: d[:len(d) // 2] + bytearray(len(d) - len(d) // 2))],
    ids=['truncated', 'empty', 'header', 'not-sqlite', 'page3', 'page40', 'zeroed'])
def test_corrupt_files_are_refused_with_a_recoverable_store_error(directory, name, mutate):
    bad = corrupt_copy(many_docs_segment(directory), mutate)
    with pytest.raises(SearchError) as err:
        open_segment(bad)
    assert err.value.code == 'PT-SEARCH-STORE' and err.value.recoverable and err.value.exit_code == 3


def test_try_open_discards_a_corrupt_file_and_ignores_a_missing_one(directory, published):
    assert try_open(directory / 'fn-ffffffffffffffff.sqlite3') is None
    bad = corrupt_copy(published, lambda d: d[:len(d) // 2])
    assert try_open(bad) is None and not bad.exists()
    with try_open(published) as seg:
        assert seg.info.docs == 5


def tamper(source: Path, sql: str, name: str | None = None) -> Path:
    target = source.with_name('tamper') / (name or source.name)
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(source.read_bytes())
    db = sqlite3.connect(target)
    db.executescript(sql)
    db.commit()
    db.close()
    return target


@pytest.mark.parametrize('sql', [
    "UPDATE meta SET value = 'search-segment/2' WHERE key = 'contract'",
    "UPDATE meta SET value = 'xx' WHERE key = 'group'", "UPDATE meta SET value = '9' WHERE key = 'builder_version'",
    "UPDATE meta SET value = 'deadbeefdeadbeef' WHERE key = 'tokenizer_digest'",
    "UPDATE meta SET value = 'name' WHERE key = 'tables'", "UPDATE meta SET value = 'many' WHERE key = 'docs'",
    "DELETE FROM meta WHERE key = 'built_utc'", "INSERT INTO meta VALUES ('extra', '1')",
    'PRAGMA application_id = 1', 'PRAGMA user_version = 2',
    'CREATE TABLE evil(x)', 'CREATE VIEW v AS SELECT 1', 'CREATE TRIGGER t AFTER INSERT ON doc BEGIN SELECT 1; END',
    'CREATE INDEX evil_idx ON doc(ref)', 'DROP INDEX doc_value_sha',
    "CREATE VIRTUAL TABLE fts_extra USING fts5(x)"],
    ids=['contract', 'group', 'builder', 'tokenizer', 'tables', 'docs', 'missing-key', 'extra-key', 'appid', 'userver',
         'table', 'view', 'trigger', 'index', 'dropped-index', 'virtual'])
def test_tampered_files_are_refused(published, sql):
    with pytest.raises(SearchError) as err:
        open_segment(tamper(published, sql))
    assert err.value.code == 'PT-SEARCH-STORE'


def test_a_segment_renamed_to_another_digest_is_refused(published):
    renamed = tamper(published, 'SELECT 1', name=f'fn-{"f" * 16}.sqlite3')
    with pytest.raises(SearchError):
        open_segment(renamed)


def test_an_oversize_file_is_refused_before_it_is_opened(published):
    with pytest.raises(SearchError):
        open_segment(published, SearchLimits(bytes_per_project=1000))


# ------------------------------------------------------------------------------------ digests

def test_digests_depend_on_every_input():
    base = segment.segment_digest('fn', ALL_SETS, {'diff_id': 'a'})
    assert len(base) == 16 and base == segment.segment_digest('fn', ('text', 'code', 'name'), {'diff_id': 'a'})
    assert base != segment.segment_digest('raw', ALL_SETS, {'diff_id': 'a'})
    assert base != segment.segment_digest('fn', ('name',), {'diff_id': 'a'})
    assert base != segment.segment_digest('fn', ALL_SETS, {'diff_id': 'b'})
    assert segment.tokenizer_digest(('name',)) != segment.tokenizer_digest(('code',))


def test_digest_includes_the_sqlite_major_minor(monkeypatch):
    before = segment.segment_digest('fn', ALL_SETS, 1)
    monkeypatch.setattr(segment.sqlite3, 'sqlite_version', '9.99.1')
    assert segment.segment_digest('fn', ALL_SETS, 1) != before
    monkeypatch.setattr(segment.sqlite3, 'sqlite_version', '9.99.7')
    assert segment.segment_digest('fn', ALL_SETS, 1) == segment.segment_digest('fn', ALL_SETS, 1)


# ------------------------------------------------------------------------------------ garbage collection

def touch(path: Path, age: float, now: float, size: int = 10) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b'x' * size)
    os.utime(path, (now - age, now - age))


def test_gc_removes_only_old_unexpected_derived_files(directory):
    now, old, young = 1_000_000.0, 3600.0, 5.0
    names = {
        'keep': f'fn-{DIGEST}.sqlite3', 'old_extra': f'fn-{"1" * 16}.sqlite3', 'young_extra': f'fn-{"2" * 16}.sqlite3',
        'old_staging': '.staging-aaa', 'young_staging': '.staging-bbb', 'old_probe': '.write-test-ccc',
        'stranger': 'notes.txt', 'wal': f'fn-{"3" * 16}.sqlite3-wal'}
    ages = {'keep': old, 'old_extra': old, 'young_extra': young, 'old_staging': old, 'young_staging': young,
            'old_probe': old, 'stranger': old, 'wal': old}
    for key, name in names.items():
        touch(directory / name, ages[key], now)
    removed = segment.collect_garbage(directory, [('fn', DIGEST)], now=now)
    assert removed == tuple(sorted([names['old_extra'], names['old_staging'], names['old_probe']]))
    assert listing(directory) == sorted(set(names.values()) - set(removed))


def test_gc_tolerates_a_missing_directory_and_locked_files(tmp_path, monkeypatch):
    assert segment.collect_garbage(tmp_path / 'absent', []) == ()
    now = 1_000_000.0
    touch(tmp_path / '.staging-x', 3600, now)

    def locked(self, *a, **k):
        raise PermissionError('in use')

    monkeypatch.setattr(Path, 'unlink', locked)
    assert segment.collect_garbage(tmp_path, [], now=now) == ()


def test_trim_cache_empties_least_recent_closed_projects_first(tmp_path):
    now = 1_000_000.0
    cache = tmp_path / 'cache'
    projects = {}
    for index, age in enumerate((300.0, 200.0, 100.0, 50.0)):
        project = paths.project_dir(cache, f'proj-{index}')
        touch(paths.segment_path(project, 'fn', DIGEST), age, now, size=1000)
        projects[index] = project
    touch(projects[0] / 'readme.txt', 300, now, size=10)  # a stranger keeps its directory alive
    limits = replace(DEFAULT_LIMITS, cache_bytes=2500)
    emptied = segment.trim_cache(cache, active=projects[1], limits=limits)
    assert emptied == (projects[2].name,) and projects[3].exists()
    assert projects[1].exists() and (projects[1] / f'fn-{DIGEST}.sqlite3').exists()
    assert not (projects[0] / f'fn-{DIGEST}.sqlite3').exists() and (projects[0] / 'readme.txt').exists()


def test_trim_cache_does_nothing_under_the_limit_or_without_a_cache(tmp_path):
    assert segment.trim_cache(tmp_path / 'absent') == ()
    project = paths.project_dir(tmp_path, 'p')
    touch(paths.segment_path(project, 'fn', DIGEST), 10, 1_000_000.0)
    assert segment.trim_cache(tmp_path) == () and project.exists()
