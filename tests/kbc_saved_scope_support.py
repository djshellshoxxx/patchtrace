"""Authored offline fixtures for saved advisory scope; no native/tool/network work."""
from __future__ import annotations

import hashlib
import json

import kbc_helpers as h
from kbc_k3_support import NOW, FixedClock
from kbc_k5_support import record

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore


def document(month='2099-Jan', cve=h.CVE_A, title='january.sys flaw', *, date='2099-01-13'):
    value = h.cvrf_document([h.vulnerability(
        cve, title, cwe=('CWE-125', 'Out-of-bounds Read'),
        remediations=[h.remediation(2, h.KB_CLIENT, [h.PRODUCT_CLIENT], '26100.9001')],
        product_statuses={'Fixed': [h.PRODUCT_CLIENT]})], release_id=month)
    value['product_tree'][0]['name'] = 'Windows 11 Version 24H2 for x64-based Systems'
    value['document']['current_release_date'] = date
    return value


def add(service, value):
    raw = h.render_json(value)
    doc = import_bytes(raw, now=NOW)
    with WorkspaceStore(service.root, clock=FixedClock()) as store:
        assert store.add_document(doc, raw)
    return doc


def seeded(tmp_path, *, mode='months', fault=None):
    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock(), fault=fault)
    doc = add(service, document())
    options = {}
    if mode == 'months':
        options['months'] = '2099-Jan'
    elif mode in {'files', 'mixed'}:
        path = tmp_path / 'scope.json'
        path.write_text(json.dumps({'months': ['2099-Jan'] if mode == 'mixed' else [],
                                    'doc_ids': [doc.doc_id]}), encoding='utf-8')
        options['scope_file'] = path
    out = service.search(h.KB_CLIENT, **options)
    return service, doc, out.result['investigation_id'], out.result['scopes'][0]['scope_id']


def saved(service, investigation):
    with WorkspaceStore(service.root) as store:
        rev = store.current_revision(investigation)
        return rev, tuple(store.get_coverage(key) for key in rev.coverage_ids)


def bundle(service, investigation):
    with WorkspaceStore(service.root) as store:
        rev = store.current_revision(investigation)
        return service._bundle(store.load_index(service.env.advisory), store, rev,
                               base=rev.revision, pair_id=None, older=None, newer=None)


def file_index(service):
    folder = service.root / wiring.INDEX_DIR
    folder.mkdir(exist_ok=True)
    (folder / 'exampledrv.sys@2099-02-12.json').write_text(json.dumps(record()), encoding='utf-8')


def contents(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()} if root.exists() else {}


def refused_without_writes(call, service, project, monkeypatch):
    """Check writes even if the wrong exception (or no exception) is returned."""
    with WorkspaceStore(service.root) as store:
        before_rows = '\n'.join(store.db.iterdump())
    before_workspace, before_project = contents(service.root), contents(project)
    writes = []
    original = WorkspaceStore._transaction

    def record_write(store, work):
        writes.append(True)
        return original(store, work)

    error = None
    with monkeypatch.context() as patch:
        patch.setattr(WorkspaceStore, '_transaction', record_write)
        try:
            call()
        except Exception as exc:
            error = exc
    with WorkspaceStore(service.root) as store:
        after_rows = '\n'.join(store.db.iterdump())
    assert after_rows == before_rows, 'refusal changed workspace rows, revisions, decisions, attempts or journal'
    assert contents(service.root) == before_workspace, 'refusal changed workspace bytes'
    assert contents(project) == before_project, 'refusal changed project bytes or sidecars'
    assert not writes, 'refusal entered a workspace write transaction'
    assert isinstance(error, KbcStoreError), repr(error)
    assert error.code == 'PT-KBC-SCOPE' and 'repeat the search' in error.message
    return error
