"""K2: hard-kill crash consistency of the workspace index and the two-phase project attach (KB-integration-plan 7.3,
7.5, 9 K2 gate). A child process is killed (SIGKILL where it exists, else os._exit) at each named crash point; the
parent then proves the project and the workspace are valid, that repair is idempotent, and that nothing is lost.
Synthetic fixtures; offline; the child never opens a socket."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import import_fixture, no_sockets  # noqa: F401

from patchtrace.kbcorrelation.contracts import InvestigationRevision, Lead
from patchtrace.kbcorrelation.recovery import mark_interrupted, open_operations, pending_context, repair
from patchtrace.kbcorrelation.store import AttachRequest, ProjectAttachment, WorkspaceStore
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')

INV = '00000000-0000-4000-8000-0000000000c1'
PAIR = 'b' * 64
HERE = Path(__file__).resolve().parent
SRC = HERE.parent / 'src'

# Test-side ProjectPort over the real ProjectService and EnrichmentStore (the production binding is slice K3).
# `create_project` is idempotent for an existing project of the same bytes, which resume relies on.
ADAPTER = '''
import hashlib, json, os, signal
from pathlib import Path
from patchtrace.service import ProjectService
from patchtrace.enrichment.storage import EnrichmentStore, Guard

class RealProjectPort:
    def __init__(self, directory):
        self.directory = Path(directory)

    def create_project(self, older_path, newer_path, *, directory):
        root = Path(directory)
        if (root / 'project.sqlite3').is_file():
            service = ProjectService.open(root, maintenance=False)
        else:
            service = ProjectService.create(Path(older_path), Path(newer_path), 'kb', root)
        try:
            side = {a.side: a.sha256 for a in service.project.artifacts}
            return {'project_id': service.store.project_id, 'revision': service.project.revision,
                    'older_sha256': side['older'], 'newer_sha256': side['newer']}
        finally:
            service.close()

    def put_row(self, project_id, kind, key, body):
        service = ProjectService.open(self.directory, maintenance=False)
        try:
            guard = Guard(project_id, 'kb', hashlib.sha256(body).hexdigest(), f'{kind}:{key}')
            EnrichmentStore(service.store).publish(kind, guard, guard, service.project.revision, 'ok',
                                                   json.loads(body), f'{kind}:{key}')
        finally:
            service.close()

    def get_row(self, project_id, kind, key):
        service = ProjectService.open(self.directory, maintenance=False)
        try:
            for entry in EnrichmentStore(service.store).entries(kind):
                if entry.id == f'{kind}:{key}':
                    return json.dumps(entry.body).encode()
            return None
        finally:
            service.close()

def hard_kill():
    if hasattr(signal, 'SIGKILL'):
        os.kill(os.getpid(), signal.SIGKILL)
    os._exit(137)
'''

DRIVER = ADAPTER + '''
import sys
import kbc_helpers as h
from kbc_k1_support import import_fixture
from patchtrace.kbcorrelation.contracts import InvestigationRevision, Lead
from patchtrace.kbcorrelation.store import AttachRequest, ProjectAttachment, WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event
from patchtrace.sample import synthetic_pe

INV, PAIR = %(inv)r, %(pair)r
scenario, root, work = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
crash_at, nth = os.environ.get('KBC_CRASH_AT'), int(os.environ.get('KBC_CRASH_NTH', '1'))
armed, hits = [False], [0]

def fault(point):
    if armed[0] and point == crash_at:
        hits[0] += 1
        if hits[0] == nth:
            hard_kill()

ws = WorkspaceStore(root / 'kb', fault=fault)

def index_two():
    names = ('cvrf-2099-Feb.json', 'cvrf-2099-Feb-neg.json')
    armed[0] = True
    for name in names:
        ws.add_document(import_fixture(name), h.read_fixture_bytes(name))

def attach():
    doc = import_fixture('cvrf-2099-Feb.json')
    ws.add_document(doc, h.read_fixture_bytes('cvrf-2099-Feb.json'))
    older, newer = work / 'old' / 'exampledrv.sys', work / 'new' / 'exampledrv.sys'
    older.parent.mkdir(parents=True, exist_ok=True)
    newer.parent.mkdir(parents=True, exist_ok=True)
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    rev = InvestigationRevision(investigation_id=INV, revision=1, lead=Lead(kind='file', value='exampledrv.sys',
                                                                           raw='exampledrv.sys'), state='NEW')
    ws.create_investigation(rev)
    for kind, fields in (('lead_parsed', {}), ('pair_proposed', {'outcome': 'PAIR_PROPOSED', 'pair_id': PAIR}),
                         ('pair_approved', {}), ('bytes_verified', {'parsed': True, 'both_sides': True})):
        rev = ws.apply(rev, Event(kind, rev.revision, **fields))
    project_dir = work / 'project'
    request = AttachRequest(revision=rev, pair_id=PAIR, older_path=str(older), newer_path=str(newer),
                            older_sha=h.sha256_hex(synthetic_pe(0)), newer_sha=h.sha256_hex(synthetic_pe(1)),
                            directory=str(project_dir), source_shas=(doc.source.sha256,))
    armed[0] = True
    context = ((%(key)r, %(body)r.encode()),) if scenario == 'attach-context' else ()
    result = ProjectAttachment(ws, RealProjectPort(project_dir)).attach(request, context)
    print(result.status)

{'index': index_two, 'attach': attach, 'attach-context': attach}[scenario]()
'''

CONTEXT_KEY = 'ctx-1'
CONTEXT_BODY = json.dumps({'contract': 'kbcorrelation/1', 'note': 'synthetic context'})


def run_child(scenario: str, root: Path, work: Path, crash_at: str | None = None, nth: int = 1):
    env = {**os.environ, 'PYTHONPATH': os.pathsep.join([str(SRC), str(HERE)]), 'PYTHONFAULTHANDLER': '1'}
    env.pop('KBC_CRASH_AT', None)
    if crash_at:
        env.update(KBC_CRASH_AT=crash_at, KBC_CRASH_NTH=str(nth))
    code = DRIVER % {'inv': INV, 'pair': PAIR, 'key': CONTEXT_KEY, 'body': CONTEXT_BODY}
    return subprocess.run([sys.executable, '-c', code, scenario, str(root), str(work)], env=env,
                          capture_output=True, text=True, timeout=120, cwd=str(work), check=False)


def killed(proc) -> bool:
    return proc.returncode in (-9, 137)


def adapter(directory: Path):
    namespace: dict = {}
    exec(ADAPTER, namespace)  # noqa: S102 (test-owned source shared with the child process)
    return namespace['RealProjectPort'](directory)


def edge_count(store: WorkspaceStore) -> int:
    return store.db.execute('SELECT COUNT(*) FROM edges').fetchone()[0]


# ------------------------------------------------------------------------------------------ index crash points

def test_control_run_completes_without_a_crash(tmp_path):
    proc = run_child('attach-context', tmp_path, tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == 'ok'


def test_kill_after_the_first_document_keeps_it_whole_and_import_resumes(tmp_path):
    proc = run_child('index', tmp_path, tmp_path, 'index_after_doc')
    assert killed(proc), proc.stderr
    with WorkspaceStore(tmp_path / 'kb') as ws:
        docs = ws.sources()
        assert [d.release_id for d in docs] == ['2099-Feb']
        expected = import_fixture('cvrf-2099-Feb.json')
        assert edge_count(ws) == len(expected.edges)
        assert ws.load_index().lookup_kb(h.KB_CLIENT, now='2099-02-15T00:00:00Z').status == 'found'
        for name in ('cvrf-2099-Feb.json', 'cvrf-2099-Feb-neg.json'):
            ws.add_document(import_fixture(name), h.read_fixture_bytes(name))  # the retry is idempotent
        assert len(ws.sources()) == 2
        assert ws.unreferenced_objects() == ()


def test_kill_inside_the_document_transaction_leaves_no_partial_rows(tmp_path):
    proc = run_child('index', tmp_path, tmp_path, 'index_before_commit')
    assert killed(proc), proc.stderr
    with WorkspaceStore(tmp_path / 'kb') as ws:
        assert ws.sources() == () and edge_count(ws) == 0
        assert ws.db.execute('SELECT COUNT(*) FROM segments').fetchone()[0] == 0
        assert len(ws.unreferenced_objects()) == 1  # the object was written first; listed, never trusted or deleted
        assert ws.db.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), h.read_fixture_bytes('cvrf-2099-Feb.json'))
        assert ws.unreferenced_objects() == ()


# ------------------------------------------------------------------------------------------ attach crash points

ATTACH_POINTS = [
    ('after_project_create', 1, 'BYTES_VERIFIED'),
    ('before_cas', 1, 'BYTES_VERIFIED'),
    ('after_sidecar_write', 1, 'PROJECT_CREATED'),
    ('attach_before_row', 1, 'PROJECT_CREATED'),
    ('attach_before_row', 2, 'PROJECT_CREATED'),  # between the investigation row and the context row
    ('before_cas', 2, 'PROJECT_CREATED'),  # everything written, final revision not yet committed
]
POINT_IDS = ['after-create', 'cas-1', 'after-sidecar', 'row-1', 'row-2', 'cas-2']


def project_is_valid(directory: Path) -> ProjectService:
    service = ProjectService.open(directory, maintenance=False)
    assert [a.side for a in service.project.artifacts] == ['older', 'newer']
    return service


@pytest.mark.parametrize(('point', 'nth', 'state'), ATTACH_POINTS, ids=POINT_IDS)
def test_hard_kill_leaves_a_valid_project_and_repair_finishes_idempotently(tmp_path, point, nth, state):
    proc = run_child('attach-context', tmp_path, tmp_path, point, nth)
    assert killed(proc), (proc.returncode, proc.stderr)
    project_dir = tmp_path / 'project'
    project_is_valid(project_dir).close()
    with WorkspaceStore(tmp_path / 'kb') as ws:
        assert ws.current_revision(INV).state == state
        assert len(open_operations(ws)) == 1
        port = adapter(project_dir)

        first = repair(ws, port)  # no context rebuilder: the documentary context stays pending, honestly
        assert first.status == 'partial' and first.value[0].state == 'context-pending'
        assert ws.current_revision(INV).state == 'CONTEXT_PENDING'
        assert open_operations(ws) == () and len(pending_context(ws)) == 1
        interrupted = [a for a in ws.attempts(INV) if a.stage.startswith('interrupted:')]
        assert len(interrupted) == 1 and interrupted[0].result == 'cancelled'

        before = (ws.current_revision(INV).revision, len(ws.attempts(INV)))
        again = repair(ws, port)
        assert again.value == first.value
        assert (ws.current_revision(INV).revision, len(ws.attempts(INV))) == before  # idempotent

        rebuilt = repair(ws, port, context_for=lambda op, body: ((CONTEXT_KEY, CONTEXT_BODY.encode()),))
        assert rebuilt.status == 'ok' and rebuilt.value[0].state == 'attached'
        assert ws.current_revision(INV).state == 'CONTEXT_ATTACHED'
        final = ws.current_revision(INV)

    link = rebuilt.value[0]
    assert link.older_sha == h.sha256_hex(synthetic_pe(0))
    row_key = f'{INV}:{link.revision}'
    assert json.loads(port.get_row(link.project_id, 'kb-investigation', row_key))['investigation_id'] == INV
    assert json.loads(port.get_row(link.project_id, 'kb-context', CONTEXT_KEY))['note'] == 'synthetic context'
    assert (project_dir / 'kb' / 'investigations' / f'{INV}-{link.revision}.json').is_file()
    assert len(list((project_dir / 'kb' / 'sources').glob('*.json.gz'))) == 1
    assert final.state == 'CONTEXT_ATTACHED'


def test_the_attached_project_backs_up_and_restores_with_its_kb_sidecars(tmp_path):
    proc = run_child('attach-context', tmp_path, tmp_path)
    assert proc.returncode == 0, proc.stderr
    service = project_is_valid(tmp_path / 'project')
    try:
        copy = service.backup(tmp_path / 'backup')
    finally:
        service.close()
    assert len(list((copy / 'kb' / 'sources').glob('*.json.gz'))) == 1
    assert len(list((copy / 'kb' / 'investigations').glob('*.json'))) == 1
    restored = project_is_valid(copy)
    restored.close()


# ------------------------------------------------------------------------------------------ in-process behaviour

def prepared(tmp_path: Path, **kw):
    """A workspace with one source and a BYTES_VERIFIED investigation over two synthetic files."""
    from patchtrace.kbcorrelation.workflow import Event
    ws = WorkspaceStore(tmp_path / 'kb', **kw)
    doc = import_fixture('cvrf-2099-Feb.json')
    ws.add_document(doc, h.read_fixture_bytes('cvrf-2099-Feb.json'))
    files = h.two_cve_project(tmp_path / 'files')
    rev = InvestigationRevision(investigation_id=INV, revision=1, lead=Lead(kind='file', value='exampledrv.sys',
                                                                           raw='exampledrv.sys'), state='NEW')
    ws.create_investigation(rev)
    for kind, fields in (('lead_parsed', {}), ('pair_proposed', {'outcome': 'PAIR_PROPOSED', 'pair_id': PAIR}),
                         ('pair_approved', {}), ('bytes_verified', {'parsed': True, 'both_sides': True})):
        rev = ws.apply(rev, Event(kind, rev.revision, **fields))
    request = AttachRequest(revision=rev, pair_id=PAIR, older_path=str(files.older_path),
                            newer_path=str(files.newer_path), older_sha=files.older_sha256,
                            newer_sha=files.newer_sha256, directory=str(tmp_path / 'project'),
                            source_shas=(doc.source.sha256,))
    return ws, request


def test_attach_without_context_is_partial_and_attach_again_is_a_no_op(tmp_path):
    ws, request = prepared(tmp_path)
    with ws:
        attachment = ProjectAttachment(ws, adapter(tmp_path / 'project'))
        result = attachment.attach(request)
        assert result.status == 'partial' and result.value.state == 'context-pending'
        assert 'CONTEXT_PENDING' in result.warnings[0]
        revision = ws.current_revision(INV).revision
        assert attachment.attach(request) == result
        assert ws.current_revision(INV).revision == revision


def test_an_input_file_that_changed_after_verification_is_refused_before_any_side_effect(tmp_path):
    ws, request = prepared(tmp_path)
    with ws:
        Path(request.newer_path).write_bytes(b'MZ tampered')
        result = ProjectAttachment(ws, adapter(tmp_path / 'project')).attach(request)
        assert result.status == 'error' and result.issues[0].code == 'PT-KBC-VERIFY'
        assert not (tmp_path / 'project').exists() and ws.journal_ops() == ()
        assert ws.current_revision(INV).state == 'BYTES_VERIFIED'


def test_a_nonempty_project_directory_is_never_adopted_or_touched(tmp_path):
    ws, request = prepared(tmp_path)
    with ws:
        (tmp_path / 'project').mkdir()
        keep = tmp_path / 'project' / 'user-notes.txt'
        keep.write_text('mine', encoding='utf-8')
        result = ProjectAttachment(ws, adapter(tmp_path / 'project')).attach(request)
        assert result.status == 'error' and result.issues[0].code == 'PT-KBC-STORAGE'
        assert keep.read_text(encoding='utf-8') == 'mine' and ws.journal_ops() == ()


def test_a_stale_revision_cannot_attach(tmp_path):
    from patchtrace.kbcorrelation.workflow import Event
    ws, request = prepared(tmp_path)
    with ws:
        ws.apply(request.revision, Event('project_created', request.revision.revision, both_sides=True))
        result = ProjectAttachment(ws, adapter(tmp_path / 'project')).attach(request)
        assert result.status == 'error' and result.issues[0].code == 'PT-KBC-STALE'


def test_a_row_failure_after_project_creation_keeps_the_project_as_context_pending(tmp_path):
    ws, request = prepared(tmp_path)
    port = adapter(tmp_path / 'project')

    def broken(*_args):
        raise OSError('disk full')

    with ws:
        good_put = port.put_row
        port.put_row = broken
        result = ProjectAttachment(ws, port).attach(request)
        assert result.status == 'partial' and result.issues[0].code == 'PT-KBC-STORAGE'
        assert result.value.state == 'context-pending'
        assert ws.current_revision(INV).state == 'CONTEXT_PENDING'
        project_is_valid(tmp_path / 'project').close()
        port.put_row = good_put
        done = repair(ws, port, context_for=lambda op, body: ((CONTEXT_KEY, CONTEXT_BODY.encode()),))
        assert done.status == 'ok' and ws.current_revision(INV).state == 'CONTEXT_ATTACHED'


def test_a_symlinked_sidecar_directory_is_refused(tmp_path):
    if not hasattr(os, 'symlink'):
        pytest.skip('no symlinks')
    ws, request = prepared(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    port = adapter(tmp_path / 'project')
    real_create = port.create_project

    def create_with_trap(*args, **kwargs):
        made = real_create(*args, **kwargs)
        try:
            os.symlink(outside, Path(kwargs['directory']) / 'kb')
        except OSError:
            pytest.skip('symlinks need privileges here')
        return made

    port.create_project = create_with_trap
    with ws:
        result = ProjectAttachment(ws, port).attach(request)
        assert result.status == 'partial' and result.issues[0].code == 'PT-KBC-STORAGE'
        assert list(outside.iterdir()) == []


def test_repair_with_nothing_to_do_is_ok_and_empty(tmp_path):
    with WorkspaceStore(tmp_path / 'kb') as ws:
        assert repair(ws, adapter(tmp_path / 'project')).value == ()
        assert mark_interrupted(ws) == ()
