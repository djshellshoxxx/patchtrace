"""Internal held capability through the real KB route; authored PE data, no native execution."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import ssl  # noqa: F401  # Load before the existing socket-denial fixture.
import threading
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import kbc_helpers as h
import pytest
from held_input_support import authored_pair, deny_source_opens
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import FixedClock, write_pair
from kbc_saved_scope_support import add, document, seeded

from patchtrace import ingestion
from patchtrace.input_readers import InputReadError, PairInputReaders
from patchtrace.kbcorrelation import service as service_module
from patchtrace.kbcorrelation import store as store_module
from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import ContextBundle
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError, ProjectAttachment, WorkspaceStore
from patchtrace.persistence import ProjectStore
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


def pair(readers):
    return PairInputReaders(readers.older, readers.newer, readers.checkpoint)


def service(tmp_path, **options):
    return wiring.build_service(tmp_path / 'workspace', clock=FixedClock(), **options)


def rows(svc):
    with WorkspaceStore(svc.root) as ws:
        return '\n'.join(ws.db.iterdump())


def fail(error):
    def raise_error(*args, **kwargs):
        raise error
    return raise_error


def test_public_route_uses_held_reads_and_same_accounting_then_reopens_copies(tmp_path, monkeypatch):
    svc = service(tmp_path)
    root = tmp_path / 'project'
    connection_threads, core_bytes = [], []
    real_connect, real_read = sqlite3.connect, ingestion._read

    def connect(*args, **kwargs):
        connection_threads.append(threading.get_ident())
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, 'connect', connect)
    with authored_pair(tmp_path / 'inputs', padding=8192) as (paths, readers):
        supplied = pair(readers)
        expected = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]

        def read(stream, size, checkpoint=None):
            assert checkpoint is None or checkpoint is readers.checkpoint
            data = real_read(stream, size, checkpoint)
            if checkpoint is not None:
                core_bytes.append(len(data))
            return data

        monkeypatch.setattr(ingestion, '_read', read)
        deny_source_opens(monkeypatch, paths)
        result = svc.import_pair('new', *map(str, paths), str(root), input_readers=supplied)
        assert result.exit == 0 and result.result['project']['state'] == 'attached'
        for lease in (readers.older, readers.newer):
            assert lease.opened == lease.closed == 4  # inspection, intent, create, core copy
            assert not lease.active and os.fstat(lease.fd).st_size == lease.captured[2]
        assert sum(count for _, count in readers.checkpoint.counts) == sum(core_bytes) + sum(
            lease.bytes_read for lease in (readers.older, readers.newer))
        assert readers.checkpoint.reserved_output == 123456
        with WorkspaceStore(svc.root) as ws:
            [(unused_op, state, body)] = ws.journal_ops()
            assert state == 'done'
            assert not {'input_readers', 'checkpoint', 'reader', 'handle'} & body.keys()
    for path in paths:
        path.unlink()
    with ProjectService.open(root, maintenance=False) as reopened:
        assert [artifact.sha256 for artifact in reopened.project.artifacts] == expected
    assert connection_threads and set(connection_threads) == {threading.get_ident()}


def test_ordinary_injected_calls_keep_their_original_shapes(tmp_path, monkeypatch):
    svc = service(tmp_path)
    paths = write_pair(tmp_path / 'inputs')
    seen = []
    real_sha, real_create = store_module._file_sha, ProjectService.create

    def inspect(path, /):
        seen.append('inspect')
        return wiring.inspect_local_file(path)

    def factory(ws, name, /):
        seen.append('factory')
        return wiring.RealProjectPort(ws, name)

    def sha(path, /):
        seen.append('sha')
        return real_sha(path)

    def create(older, newer, name, root, /):
        seen.append('create')
        return real_create(older, newer, name, root)

    monkeypatch.setattr(store_module, '_file_sha', sha)
    monkeypatch.setattr(ProjectService, 'create', create)
    svc = KbService(svc.root, replace(svc.env, inspect=inspect, project=factory))
    result = svc.import_pair('new', *map(str, paths), str(tmp_path / 'project'))
    assert result.exit == 0
    assert seen.count('inspect') == 2 and seen.count('sha') == 4
    assert seen.count('factory') == seen.count('create') == 1


def test_held_dry_run_does_not_create_or_call_project_factory(tmp_path, monkeypatch):
    svc = service(tmp_path)
    svc = KbService(svc.root, replace(svc.env, project=fail(AssertionError('factory during preview'))))
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        deny_source_opens(monkeypatch, paths)
        result = svc.import_pair('new', *map(str, paths), str(tmp_path / 'project'),
                                 input_readers=pair(readers), dry_run=True)
        assert result.exit == 0 and result.result['plan']['network_requests'] == 0
        assert readers.older.opened == readers.newer.opened == 1
        with WorkspaceStore(svc.root) as ws:
            assert ws.journal_ops() == ()
            assert ws.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0] == 0
    assert not (tmp_path / 'project').exists()


@pytest.mark.parametrize('reason', ['cancelled', 'limited', 'changed', 'unavailable', 'invalid'])
def test_original_stop_before_inspection_leaves_workspace_absent(tmp_path, reason):
    svc = service(tmp_path)
    error = InputReadError(reason)
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        supplied = PairInputReaders(readers.older, readers.newer, fail(error))
        with pytest.raises(InputReadError) as caught:
            svc.import_pair('new', *map(str, paths), str(tmp_path / 'project'), input_readers=supplied)
        assert caught.value is error
        assert readers.older.opened == readers.newer.opened == 0
    assert not svc.root.exists() and not (tmp_path / 'project').exists()


def test_held_typeerror_is_not_retried_as_a_path_import(tmp_path):
    svc = service(tmp_path)
    calls = []

    def inspect(path, **kwargs):
        calls.append(kwargs)
        raise TypeError('authored held inspector failure')

    svc = KbService(svc.root, replace(svc.env, inspect=inspect))
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        with pytest.raises(TypeError, match='authored held inspector failure'):
            svc.import_pair('new', *map(str, paths), str(tmp_path / 'project'), input_readers=pair(readers))
        assert calls == [{'reader': readers.older}]
    assert not svc.root.exists()


def test_binding_change_during_index_read_refuses_before_approval(tmp_path, monkeypatch):
    svc, _doc, investigation, _product = seeded(tmp_path)
    before = rows(svc)
    error = InputReadError('changed')
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        original = service_module.load_index

        def load(*args, **kwargs):
            result = original(*args, **kwargs)
            readers.older.check = fail(error)
            return result

        monkeypatch.setattr(service_module, 'load_index', load)
        with pytest.raises(InputReadError) as caught:
            svc.import_pair(investigation, *map(str, paths), str(tmp_path / 'project'), input_readers=pair(readers))
        assert caught.value is error
    assert rows(svc) == before and not (tmp_path / 'project').exists()


@pytest.mark.parametrize('boundary', ['revision', 'pair', 'coverage'])
def test_existing_admission_refusals_still_precede_writes(tmp_path, boundary):
    svc, _doc, investigation, _product = seeded(tmp_path)
    kwargs = {}
    if boundary == 'revision':
        kwargs['expected_revision'] = 999
    elif boundary == 'pair':
        kwargs['expected_pair_id'] = '0' * 64
    else:
        with WorkspaceStore(svc.root) as ws:
            ws.db.execute("UPDATE coverage SET body='{}'")
            ws.db.commit()
    before = rows(svc)
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        with pytest.raises(KbcStoreError) as caught:
            svc.import_pair(investigation, *map(str, paths), str(tmp_path / 'project'),
                             input_readers=pair(readers), **kwargs)
        assert caught.value.code == ('PT-KBC-SCOPE' if boundary == 'coverage' else 'PT-KBC-STALE')
    assert rows(svc) == before and not (tmp_path / 'project').exists()


def test_ordered_advisory_snapshot_drift_during_held_read_is_refused(tmp_path):
    svc, _doc, investigation, _product = seeded(tmp_path)
    with WorkspaceStore(svc.root) as ws:
        captured = tuple(source.model_dump_json() for source in ws.sources())
    mutated = []
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        def change():
            if not mutated:
                add(svc, document('2099-Feb', date='2099-02-13'))
                mutated.append(rows(svc))
        readers.newer.on_read = change
        with pytest.raises(KbcStoreError) as caught:
            svc.import_pair(investigation, *map(str, paths), str(tmp_path / 'project'),
                             input_readers=pair(readers), expected_source_snapshot=captured)
        assert caught.value.code == 'PT-KBC-STALE'
    assert rows(svc) == mutated[0] and not (tmp_path / 'project').exists()


@pytest.mark.parametrize('phase', ['begin', 'create'])
def test_attachment_hash_stop_keeps_original_error_and_owned_state(tmp_path, monkeypatch, phase):
    svc = service(tmp_path)
    error = InputReadError('limited')
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        original = getattr(ProjectAttachment, '_' + phase)
        active = []

        def boundary(*args, **kwargs):
            active.append(True)
            try:
                return original(*args, **kwargs)
            finally:
                active.pop()

        def stop(count, kind):
            if active and count:
                raise error
            return False

        readers.checkpoint.stop = stop
        monkeypatch.setattr(ProjectAttachment, '_' + phase, boundary)
        with pytest.raises(InputReadError) as caught:
            svc.import_pair('new', *map(str, paths), str(tmp_path / 'project'), input_readers=pair(readers))
        assert caught.value is error
        assert all(lease.opened == lease.closed and not lease.active for lease in (readers.older, readers.newer))
    with WorkspaceStore(svc.root) as ws:
        assert [state for _, state, _ in ws.journal_ops()] == ([] if phase == 'begin' else ['intent'])
    assert not (tmp_path / 'project').exists()


@pytest.mark.parametrize('phase', ['copy', 'save', 'precommit'])
def test_core_stop_identity_and_rollback_survive_attachment_wrapper(tmp_path, monkeypatch, phase):
    svc = service(tmp_path)
    error = InputReadError('cancelled')
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        active = []
        if phase == 'copy':
            from patchtrace import service as core
            original = core.inspect_artifact

            def inspect(*args, **kwargs):
                active.append(True)
                return original(*args, **kwargs)

            monkeypatch.setattr(core, 'inspect_artifact', inspect)
        elif phase == 'save':
            original = ProjectStore._verify_files

            def verify(*args, **kwargs):
                active.append(True)
                return original(*args, **kwargs)

            monkeypatch.setattr(ProjectStore, '_verify_files', verify)
        else:
            original = ProjectStore.__init__

            def init(store, *args, **kwargs):
                original(store, *args, **kwargs)
                store.connection.set_trace_callback(lambda sql: active.append(True)
                    if sql.startswith('INSERT INTO current_snapshot') else None)

            monkeypatch.setattr(ProjectStore, '__init__', init)

        def stop(count, kind):
            if active and (count or phase == 'precommit'):
                raise error
            return False

        readers.checkpoint.stop = stop
        root = tmp_path / 'project'
        with pytest.raises(InputReadError) as caught:
            svc.import_pair('new', *map(str, paths), str(root), input_readers=pair(readers))
        assert caught.value is error
        assert not (root / 'project.sqlite3').exists()
        assert not list(root.rglob('*.bin')) and not list(root.rglob('.input-*'))
        assert all(lease.opened == lease.closed and not lease.active for lease in (readers.older, readers.newer))


def test_no_new_checkpoint_after_commit_prevents_created_journal(tmp_path, monkeypatch):
    svc = service(tmp_path)
    error = InputReadError('cancelled')
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        original = ProjectStore.save

        def save(*args, **kwargs):
            result = original(*args, **kwargs)
            readers.checkpoint.stop = fail(error)
            return result

        monkeypatch.setattr(ProjectStore, 'save', save)
        root = tmp_path / 'project'
        result = svc.import_pair('new', *map(str, paths), str(root), input_readers=pair(readers))
        assert result.exit == 0
        with WorkspaceStore(svc.root) as ws:
            [(unused_op, state, body)] = ws.journal_ops()
            assert state == 'done' and body['project_id'] == result.result['project']['project_id']
        with pytest.raises(InputReadError) as caught:
            readers.checkpoint(0)
        assert caught.value is error
        with ProjectService.open(root, maintenance=False) as reopened:
            assert reopened.project.id == body['project_id']


def test_existing_after_create_fault_retains_project_and_intent(tmp_path):
    def fault(point):
        if point == 'after_project_create':
            raise RuntimeError('authored post-create stop')
    svc = service(tmp_path, fault=fault)
    root = tmp_path / 'project'
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        with pytest.raises(RuntimeError, match='authored post-create stop'):
            svc.import_pair('new', *map(str, paths), str(root), input_readers=pair(readers))
        with WorkspaceStore(svc.root) as ws:
            [(unused_op, state, body)] = ws.journal_ops()
            assert state == 'intent' and body['project_id'] is None
    for path in paths:
        path.unlink()
    with ProjectService.open(root, maintenance=False) as reopened:
        assert len(reopened.project.artifacts) == 2


@pytest.mark.parametrize('target', ['inspect', 'hash'])
@pytest.mark.parametrize('bad', [None, '', bytearray(), memoryview(b'a'), b'A' * ((1 << 20) + 1)],
                         ids=['none', 'text', 'empty-bytearray', 'view', 'oversized'])
def test_invalid_held_read_is_refused_once_without_hash_progress(tmp_path, monkeypatch, target, bad):
    reads, hashed = [], []
    path = tmp_path / 'example.sys'

    class Reader:
        def read(self, size):
            reads.append(size)
            assert type(size) is int and 0 < size <= 1 << 20
            assert len(reads) == 1, 'invalid results must not spin'
            return bad

    @contextmanager
    def opened(bound):
        assert Path(bound) == path
        yield Reader()

    provider = SimpleNamespace(check=lambda bound: None, open_reader=opened)
    module = wiring if target == 'inspect' else store_module
    monkeypatch.setattr(module, 'hashlib', SimpleNamespace(sha256=lambda: SimpleNamespace(
        update=hashed.append, hexdigest=lambda: '0' * 64)))
    function = wiring.inspect_local_file if target == 'inspect' else store_module._file_sha
    with pytest.raises(InputReadError) as caught:
        function(str(path), reader=provider)
    assert caught.value.reason == 'invalid' and len(reads) == 1 and not hashed


@pytest.mark.parametrize('factory', [wiring._project_factory, wiring.new_project_factory])
def test_factories_preserve_policy_and_forward_the_same_pair(tmp_path, monkeypatch, factory):
    calls = []

    class Port:
        def __init__(self, *args, **kwargs):
            calls.append((args, kwargs))

    monkeypatch.setattr(wiring, 'RealProjectPort', Port)
    with authored_pair(tmp_path / 'inputs') as (_paths, readers):
        supplied = pair(readers)
        factory(None, 'name', input_readers=supplied)
        factory(None, 'name')
        policy = {'reuse_existing': False} if factory is wiring.new_project_factory else {}
        assert calls == [((None, 'name'), policy | {'input_readers': supplied}), ((None, 'name'), policy)]
        assert calls[0][1]['input_readers'] is supplied


@pytest.mark.parametrize('admission', ['growth', 'superseded', 'empty'])
def test_held_import_retains_finite_scope_and_global_revision_admission(tmp_path, monkeypatch, admission):
    if admission == 'empty':
        svc = service(tmp_path)
        investigation = svc.search(h.KB_CLIENT).result['investigation_id']
        initial = None
        add(svc, document())
    else:
        svc, initial, investigation, _product = seeded(tmp_path, mode='cached')
        if admission == 'growth':
            add(svc, document('2099-Feb', h.CVE_B, date='2099-02-13'))
        else:
            newer = document(date='2099-02-14')
            newer['vulnerabilities'] = []
            add(svc, newer)
    root = tmp_path / 'project'
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        deny_source_opens(monkeypatch, paths)
        result = svc.import_pair(investigation, *map(str, paths), str(root), input_readers=pair(readers))
        assert result.exit == 0
        exported = tmp_path / 'context.json'
        assert svc.export(str(root), str(exported), overwrite=False).exit == 0
        context = ContextBundle.model_validate_json(exported.read_bytes())
        if admission == 'growth':
            assert [source.doc_id for source in context.sources] == [initial.doc_id]
            assert {card.cve for card in context.context.cards} == {h.CVE_A}
        else:
            assert not context.sources and not context.context.cards
        if admission == 'empty':
            assert context.context.coverage[0].scope.doc_ids == ()


@pytest.mark.parametrize('condition', ['live', 'other-path', 'expired'])
def test_same_operation_resume_uses_only_its_bound_readers(tmp_path, monkeypatch, condition):
    svc = service(tmp_path)
    root = tmp_path / 'project'
    original = WorkspaceStore.journal_put
    interrupted = []

    def journal(ws, op, state, body):
        original(ws, op, state, body)
        if state == 'intent' and not interrupted:
            interrupted.append(True)
            raise RuntimeError('authored interruption after intent')

    monkeypatch.setattr(WorkspaceStore, 'journal_put', journal)
    with authored_pair(tmp_path / 'inputs') as (paths, readers):
        supplied = pair(readers)
        error = InputReadError('unavailable' if condition == 'expired' else 'changed')
        bound_check = readers.older.check

        def check(path):
            if Path(path) != paths[0]:
                raise error
            return bound_check(path)

        readers.older.check = check
        deny_source_opens(monkeypatch, paths)
        with pytest.raises(RuntimeError, match='authored interruption after intent'):
            svc.import_pair('new', *map(str, paths), str(root), input_readers=supplied)
        assert not root.exists()
        with WorkspaceStore(svc.root) as ws:
            [(op, state, body)] = ws.journal_ops()
            assert state == 'intent'
            if condition == 'other-path':
                ws.journal_put(op, state, body | {'older_path': str(paths[1])})
            elif condition == 'expired':
                readers.older.check = fail(error)
            port = wiring.RealProjectPort(ws, input_readers=supplied)
            attachment = ProjectAttachment(ws, port, input_readers=supplied)
            if condition == 'live':
                outcome = attachment.resume(op)
                assert outcome.status == 'partial' and outcome.value.state == 'context-pending'
                assert ws.journal_get(op)[0] == 'done'
                with ProjectService.open(root, maintenance=False) as reopened:
                    assert reopened.project.id == outcome.value.project_id
            else:
                with pytest.raises(InputReadError) as caught:
                    attachment.resume(op)
                assert caught.value is error and ws.journal_get(op)[0] == 'intent'
                assert not root.exists()
        assert all(lease.opened == lease.closed and not lease.active for lease in (readers.older, readers.newer))
