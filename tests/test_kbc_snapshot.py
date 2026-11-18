"""KBB-01: the snapshot the holder of an open project takes for ``kb leads`` (store-threading-spec section 4a).

``kb leads`` opens the project by directory, which a second holder cannot do. The holder (the desktop) instead reads
the stored rows on its own thread (``read_snapshot``) and any thread builds the same report from them
(``leads_from_snapshot``). These tests hold a real project open, as the desktop does, and compare with the directory
read. Offline and synthetic: fixture evidence, not a live run. The dock side is in ``tests/test_ui_kb_panel.py``.
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import pickle
import threading

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import Kb
from kbc_k4a_support import analysed_project, apply_diff, attached_project

from patchtrace.enrichment import pipeline, views
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.kbcorrelation.cli_leads import (
    CONTEXT_KIND,
    ENGINE_KINDS,
    RealEngine,
    SnapshotEngine,
    SnapshotRows,
    leads_from_snapshot,
    leads_report,
    read_snapshot,
)
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import RealProjectPort, SnapshotProjectPort
from patchtrace.persistence import ProjectStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')
CVE_A = 'CVE-2099-20001'


@pytest.fixture
def kb(tmp_path, capsys):
    return Kb(tmp_path, capsys)


@contextlib.contextmanager
def held(project):
    """The project kept open, as the desktop window keeps it."""
    service = ProjectService.open(project)
    try:
        yield service
    finally:
        service.close()


def on_another_thread(work):
    """``work()`` on a thread that did not open the project; its value, or its error raised here."""
    box = {}

    def run():
        try:
            box['value'] = work()
        except BaseException as exc:  # noqa: BLE001 - handed to the calling thread
            box['error'] = exc
    thread = threading.Thread(target=run)
    thread.start()
    thread.join(60)
    assert not thread.is_alive()
    if 'error' in box:
        raise box['error']
    return box['value']


def ranked(kb, tmp_path, capsys):
    return analysed_project(kb, tmp_path, capsys)


def never_ranked(kb, tmp_path, capsys):
    return analysed_project(kb, tmp_path, capsys, rank=False)


def ranking_behind(kb, tmp_path, capsys):
    """Ranked, then analysed again: the stored ranking belongs to an earlier run."""
    project = analysed_project(kb, tmp_path, capsys)
    apply_diff(project, tmp_path)
    return project


def no_analysis(kb, tmp_path, capsys):
    return attached_project(kb, tmp_path)


STATES = [pytest.param(ranked, id='ranked'), pytest.param(never_ranked, id='never-ranked'),
          pytest.param(ranking_behind, id='ranking-behind'), pytest.param(no_analysis, id='no-analysis')]


# ---- the same answer as the directory read ------------------------------------------------------------------------

@pytest.mark.parametrize('build', STATES)
def test_leads_from_a_snapshot_on_another_thread_equal_kb_leads_by_directory(build, kb, tmp_path, capsys):
    project = build(kb, tmp_path, capsys)
    service = KbService(kb.workspace, kb.env)
    expected = leads_report(service, RealEngine(), str(project))  # nothing holds the project yet
    with held(project) as owner:
        snapshot = read_snapshot(owner)
        actual = on_another_thread(lambda: leads_from_snapshot(service, snapshot))
        with pytest.raises(KbcStoreError) as refused:  # by directory a held project stays refused, as before
            RealEngine().read(str(project))
    assert actual == expected and actual is not None
    assert refused.value.code == 'PT-KBC-STORAGE'
    assert actual.state == ('ready' if build is ranked else 'no-comparison')
    if build is ranked:
        assert [g.group for g in actual.groups] == [CVE_A] and actual.unattributed


def test_the_options_of_kb_leads_reach_the_snapshot_report(kb, tmp_path, capsys):
    project = ranked(kb, tmp_path, capsys)
    service = KbService(kb.workspace, kb.env)
    expected = leads_report(service, RealEngine(), str(project), cve=CVE_A, limit=1)
    with held(project) as owner:
        snapshot = read_snapshot(owner)
    actual = leads_from_snapshot(service, snapshot, cve=CVE_A, limit=1)
    assert actual == expected and [g.group for g in actual.groups] == [CVE_A]
    assert actual != leads_from_snapshot(service, snapshot)  # the options did narrow the report


@pytest.mark.parametrize('build', STATES)
def test_the_engine_view_of_a_snapshot_equals_the_directory_read_with_its_reason(build, kb, tmp_path, capsys):
    project = build(kb, tmp_path, capsys)
    by_directory = RealEngine()
    expected = by_directory.read(str(project))
    with held(project) as owner:
        engine = SnapshotEngine(read_snapshot(owner))
        actual = on_another_thread(lambda: engine.read(''))
    assert actual == expected and engine.note == by_directory.note
    assert (actual is not None) == (build is ranked)
    if build is ranking_behind:
        assert engine.note.startswith('Stored ranking is stale')  # an earlier run's ranking is never served


def test_a_project_with_no_context_and_no_ranking_has_no_report(kb, tmp_path):
    owner = ProjectService.sample(tmp_path / 'case')
    try:
        assert leads_from_snapshot(KbService(kb.workspace, kb.env), read_snapshot(owner)) is None
    finally:
        owner.close()


def test_snapshot_rows_are_stale_exactly_as_the_store_says(kb, tmp_path, capsys):
    project = ranking_behind(kb, tmp_path, capsys)
    with held(project) as owner:
        store, rows = EnrichmentStore(owner.store), SnapshotRows(read_snapshot(owner))
        now = pipeline.guard_for(owner.project)
        earlier = store.entries('pipeline')[0].guard
        other = Guard(now.project_id, 'another-run', now.raw_sha256, now.input_digest)
        assert earlier != now
        for kind in (CONTEXT_KIND, *ENGINE_KINDS):
            for current in (None, now, earlier, other):
                assert rows.entries(kind, current) == store.entries(kind, current), (kind, current)
        assert [e.stale for e in rows.entries('pipeline', now)] == [True]
        assert [e.stale for e in rows.entries('pipeline', earlier)] == [False]


# ---- what a snapshot is -------------------------------------------------------------------------------------------

def test_a_snapshot_is_a_value_that_holds_no_handle_and_outlives_a_commit(kb, tmp_path, capsys):
    project = ranked(kb, tmp_path, capsys)
    service = KbService(kb.workspace, kb.env)
    with held(project) as owner:
        snapshot = read_snapshot(owner)
        assert snapshot == read_snapshot(owner)
        assert pickle.dumps(snapshot)  # a connection, lock or service inside it could not be pickled
        with pytest.raises(dataclasses.FrozenInstanceError):
            snapshot.rows = ()
        before = leads_from_snapshot(service, snapshot)
        owner.annotate(owner.project.matches[0].id, 'reviewed while the dock was loading')
        # A commit replaces the service's project; the one the snapshot holds is never edited.
        assert owner.project is not snapshot.project and len(owner.project.annotations) == 1
        assert not snapshot.project.annotations
        assert leads_from_snapshot(service, snapshot) == before


def test_taking_a_snapshot_opens_nothing_computes_nothing_and_writes_nothing(kb, tmp_path, capsys, monkeypatch):
    project = ranked(kb, tmp_path, capsys)
    with held(project) as owner:
        called = []

        def refuse(name):
            def spy(*_args, **_kwargs):
                called.append(name)
                raise AssertionError(f'{name} while taking a snapshot')
            return spy
        monkeypatch.setattr(ProjectService, 'open', classmethod(refuse('ProjectService.open')))
        monkeypatch.setattr(ProjectStore, '__init__', refuse('ProjectStore'))
        # The owner's thread is held for the row reads only: what grows with the comparison is left to the reader.
        monkeypatch.setattr(pipeline, 'load_default', refuse('load_default'))
        monkeypatch.setattr(pipeline, 'guard_for', refuse('guard_for'))
        monkeypatch.setattr(views, 'build_views', refuse('build_views'))
        digest = hashlib.sha256((project / 'project.sqlite3').read_bytes()).hexdigest()
        snapshot = read_snapshot(owner)
        assert called == []
        assert hashlib.sha256((project / 'project.sqlite3').read_bytes()).hexdigest() == digest
    assert [kind for kind, _ in snapshot.rows] == [CONTEXT_KIND, *ENGINE_KINDS]
    assert all(len(snapshot.entries(kind)) == 1 for kind in (CONTEXT_KIND, *ENGINE_KINDS))


def test_a_snapshot_refuses_rows_it_did_not_take(kb, tmp_path, capsys):
    project = ranked(kb, tmp_path, capsys)
    with held(project) as owner:
        snapshot = read_snapshot(owner)
    for refused in (lambda: snapshot.entries('wil'), lambda: SnapshotRows(snapshot).entries('wil')):
        with pytest.raises(KbcStoreError) as error:  # not "no rows": the kind was never read
            refused()
        assert error.value.code == 'PT-KBC-STATE'


def test_the_snapshot_port_serves_the_stored_context_rows_and_refuses_the_rest(kb, tmp_path, capsys):
    project = ranked(kb, tmp_path, capsys)
    by_directory = RealProjectPort()
    project_id = by_directory.open_project(str(project))
    expected = by_directory.list_rows(project_id, CONTEXT_KIND)
    with held(project) as owner:
        snapshot = read_snapshot(owner)
    port = SnapshotProjectPort(snapshot.project.id, {CONTEXT_KIND: snapshot.entries(CONTEXT_KIND)})
    assert port.open_project('anywhere') == project_id == snapshot.project.id
    assert port.list_rows(project_id, CONTEXT_KIND) == expected and len(expected) == 1
    key = next(iter(expected))
    assert port.get_row(project_id, CONTEXT_KIND, key) == expected[key]
    assert port.get_row(project_id, CONTEXT_KIND, 'absent') is None
    refusals = {
        'another project': (lambda: port.list_rows('another-project', CONTEXT_KIND), 'PT-KBC-STATE'),
        'a kind not taken': (lambda: port.list_rows(project_id, 'ranking'), 'PT-KBC-STATE'),
        'create': (lambda: port.create_project('old', 'new', directory='d'), 'PT-KBC-UNSUPPORTED'),
        'write': (lambda: port.put_row(project_id, CONTEXT_KIND, key, b'{}'), 'PT-KBC-UNSUPPORTED'),
    }
    for name, (call, code) in refusals.items():
        with pytest.raises(KbcStoreError) as error:
            call()
        assert error.value.code == code, name


def test_snapshot_project_cannot_be_changed_by_in_place_owner_edit(tmp_path):
    owner = ProjectService.sample(tmp_path / 'case')
    try:
        snapshot = read_snapshot(owner)
        old_name = snapshot.project.artifacts[0].name
        owner.project.artifacts[0].name = 'changed after capture'
        assert snapshot.project.artifacts[0].name == old_name
        assert snapshot.project is not owner.project
    finally:
        owner.close()


def test_oversized_rows_are_refused_before_loading_payloads(kb, tmp_path, capsys, monkeypatch):
    from patchtrace.kbcorrelation import cli_leads
    project = ranked(kb, tmp_path, capsys)
    with held(project) as owner:
        monkeypatch.setattr(cli_leads, 'SNAPSHOT_ROWS', 0)
        monkeypatch.setattr(EnrichmentStore, 'entries', lambda *_: pytest.fail('payload read before size refusal'))
        with pytest.raises(KbcStoreError, match='desktop snapshot limit'):
            read_snapshot(owner)


def test_oversized_project_is_refused_before_copy(tmp_path, monkeypatch):
    from patchtrace.kbcorrelation import cli_leads
    owner = ProjectService.sample(tmp_path / 'case')
    try:
        monkeypatch.setattr(cli_leads, 'SNAPSHOT_NODES', 1)
        with pytest.raises(KbcStoreError, match='desktop snapshot limit'):
            read_snapshot(owner)
    finally:
        owner.close()
