"""K2: the companion workspace store (KB-integration-plan 7.3, 7.4). Synthetic fixtures; offline; no project needed."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import NOW, import_fixture, no_sockets  # noqa: F401

from patchtrace.kbcorrelation.contracts import AnalystDecision, Attempt, InvestigationRevision, Lead
from patchtrace.kbcorrelation.limits import KbcLimits
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore, default_workspace
from patchtrace.kbcorrelation.workflow import Event

pytestmark = pytest.mark.usefixtures('no_sockets')

INV = '00000000-0000-4000-8000-0000000000b1'
FIXTURE = 'cvrf-2099-Feb.json'


def revision_one(inv: str = INV) -> InvestigationRevision:
    return InvestigationRevision(investigation_id=inv, revision=1,
                                 lead=Lead(kind='kb', value=h.KB_CLIENT, raw='kb5099001'), state='NEW')


@pytest.fixture
def ws(tmp_path):
    with WorkspaceStore(tmp_path / 'kb') as store:
        yield store


def add_fixture(store: WorkspaceStore, name: str = FIXTURE):
    doc = import_fixture(name)
    assert store.add_document(doc, h.read_fixture_bytes(name))
    return doc


@pytest.mark.parametrize(('environ', 'expected'), [
    ({'LOCALAPPDATA': 'L', 'XDG_DATA_HOME': 'X'}, Path('L') / 'PatchTrace' / 'kb'),
    ({'XDG_DATA_HOME': 'X'}, Path('X') / 'PatchTrace' / 'kb'),
    ({}, Path('H') / '.local' / 'share' / 'PatchTrace' / 'kb'),
], ids=['localappdata', 'xdg', 'home'])
def test_default_workspace_is_local_never_roaming(environ, expected):
    assert default_workspace(environ, Path('H')) == expected


def test_a_new_workspace_has_user_version_1_and_the_planned_tables(ws, tmp_path):
    names = {r[0] for r in ws.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {'meta', 'docs', 'coverage', 'segments', 'kbs', 'cves', 'products', 'edges', 'investigations',
            'revisions', 'attempts', 'decisions'} <= names
    assert ws.db.execute('PRAGMA user_version').fetchone()[0] == 1
    assert (tmp_path / 'kb' / 'kbc.sqlite3').is_file()


def test_open_without_create_refuses_a_missing_workspace(tmp_path):
    with pytest.raises(KbcStoreError) as caught:
        WorkspaceStore(tmp_path / 'absent', create=False)
    assert caught.value.code == 'PT-KBC-STORAGE'


def test_documents_are_stored_once_with_compact_edges_and_lookups(ws):
    doc = add_fixture(ws)
    assert ws.add_document(doc, h.read_fixture_bytes(FIXTURE)) is False
    assert ws.sources() == (doc.source,)
    rows = ws.edges_for_kb(h.KB_CLIENT)
    assert {r['cve'] for r in rows} >= {h.CVE_A}
    assert all(r['kb'] == h.KB_CLIENT and r['doc_id'] == doc.doc_id for r in rows)
    assert {r['cve'] for r in ws.edges_for_cve(h.CVE_A)} == {h.CVE_A}
    assert len(ws.edges_for_cve(h.CVE_A)) + len(ws.edges_for_cve(h.CVE_B)) + len(
        ws.edges_for_cve(h.CVE_MENTION)) == len(doc.edges)
    assert ws.segments(doc.doc_id)['vulnerabilities'] == doc.vulnerabilities


def test_load_index_answers_like_the_in_memory_index(ws):
    doc = add_fixture(ws)
    from patchtrace.kbcorrelation.index import ReverseIndex
    direct = ReverseIndex()
    direct.add(doc)
    loaded = ws.load_index()
    a = direct.lookup_kb(h.KB_CLIENT, now=NOW)
    b = loaded.lookup_kb(h.KB_CLIENT, now=NOW)
    assert (a.status, [e.edge_id for e in a.edges]) == (b.status, [e.edge_id for e in b.edges])
    assert loaded.edge_set_digest() == direct.edge_set_digest()


def test_a_damaged_object_fails_closed_and_is_never_trusted(ws):
    doc = add_fixture(ws)
    ws.object_path(doc.source.sha256).write_bytes(b'not gzip')
    with pytest.raises(KbcStoreError) as caught:
        ws.load_index()
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_bytes_must_match_their_hash_before_anything_is_written(ws):
    doc = import_fixture(FIXTURE)
    with pytest.raises(KbcStoreError) as caught:
        ws.add_document(doc, b'{}')
    assert caught.value.code == 'PT-KBC-VERIFY'
    assert ws.sources() == () and ws.unreferenced_objects() == ()


def test_the_object_budget_is_enforced(tmp_path):
    with WorkspaceStore(tmp_path / 'kb', limits=KbcLimits(workspace_objects_bytes=10)) as small:
        with pytest.raises(KbcStoreError) as caught:
            small.add_document(import_fixture(FIXTURE), h.read_fixture_bytes(FIXTURE))
    assert caught.value.code == 'PT-KBC-LIMIT'


def test_an_unreferenced_object_is_listed_not_deleted(ws):
    raw = h.read_fixture_bytes(FIXTURE)
    sha = h.sha256_hex(raw)
    ws.write_object(sha, raw)
    assert ws.unreferenced_objects() == (sha,)
    assert ws.object_path(sha).is_file()


def test_coverage_round_trips(ws):
    doc = add_fixture(ws)
    from patchtrace.kbcorrelation.index import ReverseIndex
    index = ReverseIndex()
    index.add(doc)
    coverage = index.coverage(now=NOW)
    ws.put_coverage(coverage)
    ws.put_coverage(coverage)
    assert ws.get_coverage(coverage.coverage_id) == coverage
    assert ws.get_coverage('0' * 64) is None


def test_a_newer_store_opens_read_only_and_every_write_fails_closed(tmp_path):
    with WorkspaceStore(tmp_path / 'kb') as ws:
        add_fixture(ws)
        ws.create_investigation(revision_one())
    raw = sqlite3.connect(tmp_path / 'kb' / 'kbc.sqlite3')
    raw.execute('PRAGMA user_version=2')
    raw.commit()
    raw.close()
    with WorkspaceStore(tmp_path / 'kb') as newer:
        assert newer.read_only
        assert len(newer.sources()) == 1 and newer.current_revision(INV).revision == 1
        for write in (lambda: newer.add_document(import_fixture('cvrf-2099-Feb-neg.json'),
                                                 h.read_fixture_bytes('cvrf-2099-Feb-neg.json')),
                      lambda: newer.create_investigation(revision_one('00000000-0000-4000-8000-0000000000b2')),
                      lambda: newer.journal_put('x', 'intent', {})):
            with pytest.raises(KbcStoreError) as caught:
                write()
            assert caught.value.code == 'PT-KBC-STORAGE' and not caught.value.recoverable
    version = sqlite3.connect(tmp_path / 'kb' / 'kbc.sqlite3').execute('PRAGMA user_version').fetchone()[0]
    assert version == 2  # never downgraded


def test_revisions_advance_by_compare_and_swap_and_history_is_append_only(ws):
    first = revision_one()
    ws.create_investigation(first)
    second = ws.apply(first, Event('lead_parsed', 1))
    assert ws.current_revision(INV) == second
    assert [r.revision for r in ws.revisions(INV)] == [1, 2]
    with pytest.raises(KbcStoreError) as stale:
        ws.apply(first, Event('lead_parsed', 1))  # the caller still holds revision 1
    assert stale.value.code == 'PT-KBC-STALE'
    with pytest.raises(KbcStoreError) as lost:
        ws.append_revision(second.model_copy(update={'revision': 3, 'parent': 2}), expected_current=1)
    assert lost.value.code == 'PT-KBC-STATE'
    for sql in ("UPDATE revisions SET body='{}'", 'DELETE FROM revisions'):
        with pytest.raises(sqlite3.DatabaseError, match='append-only'):
            ws.db.execute(sql)


def test_two_connections_cannot_both_win_the_same_revision(tmp_path):
    with WorkspaceStore(tmp_path / 'kb') as a, WorkspaceStore(tmp_path / 'kb') as b:
        first = revision_one()
        a.create_investigation(first)
        winner = a.apply(first, Event('lead_parsed', 1))
        assert b.current_revision(INV) == winner
        with pytest.raises(KbcStoreError) as caught:
            b.apply(first, Event('lead_parsed', 1))
        assert caught.value.code == 'PT-KBC-STALE'
        assert len(b.revisions(INV)) == 2


def test_a_corrupt_revision_row_is_detected_by_its_hash(ws):
    ws.create_investigation(revision_one())
    ws.db.execute('DROP TRIGGER revisions_update')
    ws.db.execute("UPDATE revisions SET body=replace(body, 'NEW', 'ANALYZED')")
    with pytest.raises(KbcStoreError) as caught:
        ws.current_revision(INV)
    assert caught.value.code == 'PT-KBC-VERIFY'


def test_investigation_count_is_limited_and_a_duplicate_is_refused(tmp_path):
    with WorkspaceStore(tmp_path / 'kb', limits=KbcLimits(investigations=1)) as ws:
        ws.create_investigation(revision_one())
        with pytest.raises(KbcStoreError) as full:
            ws.create_investigation(revision_one('00000000-0000-4000-8000-0000000000b3'))
        assert full.value.code == 'PT-KBC-LIMIT'
    with WorkspaceStore(tmp_path / 'kb2') as ws:
        ws.create_investigation(revision_one())
        with pytest.raises(KbcStoreError) as dup:
            ws.create_investigation(revision_one())
        assert dup.value.code == 'PT-KBC-STATE'


def test_attempts_and_decisions_are_append_only_and_ordered(ws):
    ws.create_investigation(revision_one())
    ws.append_attempt(INV, Attempt(op='search', stage='done', result='ok', created_at=NOW))
    ws.append_attempt(INV, Attempt(op='attach', stage='interrupted:intent', result='cancelled', created_at=NOW))
    decision = AnalystDecision(op='choose-product', prior='NEEDS_PRODUCT', next='PRODUCT_SELECTED',
                               reason='client build', created_at=NOW)
    ws.append_decision(INV, decision)
    assert [a.op for a in ws.attempts(INV)] == ['search', 'attach']
    assert ws.decisions(INV) == (decision,)
    with pytest.raises(sqlite3.DatabaseError, match='append-only'):
        ws.db.execute('DELETE FROM attempts')
    with pytest.raises(sqlite3.DatabaseError, match='append-only'):
        ws.db.execute('UPDATE decisions SET body=body')


def test_domain_modules_still_import_no_qt_or_network():
    import ast
    import inspect

    from patchtrace.kbcorrelation import recovery, store, workflow
    banned = {'PySide6', 'PyQt5', 'PyQt6', 'urllib', 'socket', 'http', 'requests'}
    for module in (store, recovery, workflow):
        names = set()
        for node in ast.walk(ast.parse(inspect.getsource(module))):
            if isinstance(node, ast.Import):
                names |= {a.name.split('.')[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names.add(node.module.split('.')[0])
        assert not names & banned, module.__name__
