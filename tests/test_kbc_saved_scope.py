"""Saved investigation scope through real service/SQLite/project flows; synthetic and offline."""
from __future__ import annotations

import json

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, write_pair
from kbc_k5_support import record

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import build_bundle
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.kbcorrelation.workflow import Event

pytestmark = pytest.mark.usefixtures('no_sockets')


def _document(month='2099-Jan', cve=h.CVE_A, title='january.sys flaw', *, kb=h.KB_CLIENT,
              fixed='26100.9001', date='2099-01-13'):
    value = h.cvrf_document([h.vulnerability(
        cve, title, cwe=('CWE-125', 'Out-of-bounds Read'),
        remediations=[h.remediation(2, kb, [h.PRODUCT_CLIENT], fixed)],
        product_statuses={'Fixed': [h.PRODUCT_CLIENT]})], release_id=month)
    value['product_tree'][0]['name'] = 'Windows 11 Version 24H2 for x64-based Systems'
    value['document']['current_release_date'] = date
    return value


def _add(service, value):
    raw = h.render_json(value)
    doc = import_bytes(raw, now=NOW)
    with WorkspaceStore(service.root) as ws:
        assert ws.add_document(doc, raw)
    return doc


def _service(tmp_path):
    return wiring.build_service(tmp_path / 'ws', clock=FixedClock())


def _search(service, tmp_path, mode, doc):
    kw = {}
    if mode == 'months':
        kw['months'] = '2099-Jan'
    elif mode in ('files', 'mixed'):
        scope = tmp_path / 'scope.json'
        scope.write_text(json.dumps({'months': ['2099-Jan'] if mode == 'mixed' else [],
                                     'doc_ids': [doc.doc_id]}), encoding='utf-8')
        kw['scope_file'] = scope
    out = service.search(h.KB_CLIENT, **kw)
    return out, out.result['investigation_id'], out.result['scopes'][0]['scope_id']


def _saved(service, inv):
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(inv)
        return rev, tuple(ws.get_coverage(key) for key in rev.coverage_ids)


def _bundle(service, inv):
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(inv)
        return service._bundle(ws.load_index(), ws, rev, base=rev.revision,
                               pair_id=None, older=None, newer=None)


def _save_file_index(service):
    folder = service.root / wiring.INDEX_DIR
    folder.mkdir(exist_ok=True)
    (folder / 'exampledrv.sys@2099-02-12.json').write_text(json.dumps(record()), encoding='utf-8')


@pytest.mark.parametrize('mode', ['months', 'files', 'mixed', 'cached'])
def test_saved_scope_bounds_components_attached_context_and_raw_sources(tmp_path, mode):
    service = _service(tmp_path)
    jan = _add(service, _document())
    feb_value = _document('2099-Feb', h.CVE_B, 'february.sys flaw', date='2099-02-13')
    if mode != 'cached':
        _add(service, feb_value)
    search, inv, product = _search(service, tmp_path, mode, jan)
    assert {e['cve'] for e in search.result['edges']} == {h.CVE_A}
    _, saved = _saved(service, inv)
    before = _bundle(service, inv)
    if mode == 'cached':
        _add(service, feb_value)
    # Reopen the service: this must use persisted coverage, not an in-memory request.
    service = wiring.build_service(service.root, clock=FixedClock())
    assert _bundle(service, inv).context_key == before.context_key
    hints = service.components(inv, product=product, files=['exampledrv.sys'])
    assert {x['basename'] for x in hints.result['hints']} == {'january.sys', 'exampledrv.sys'}
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    assert service.import_pair(inv, str(older), str(newer), str(project)).exit == 0
    explained = service.explain(str(project), None)
    assert {c['cve'] for c in explained.result['cves']} == {h.CVE_A}
    assert explained.result['coverage'] == [c.model_dump(mode='json') for c in saved]
    target = tmp_path / 'context.json'
    assert service.export(str(project), str(target), overwrite=False).exit == 0
    attached = json.loads(target.read_bytes())
    assert {s['doc_id'] for s in attached['sources']} == {jan.doc_id}
    expected = ReverseIndex()
    expected.add(jan)
    assert attached['edge_set_digest'] == expected.edge_set_digest()
    assert {p.name for p in (project / 'kb/sources').glob('*.gz')} == {jan.source.sha256 + '.json.gz'}


@pytest.mark.parametrize('lead', [h.KB_CLIENT, h.CVE_A])
def test_cve_cards_kbs_and_vendor_fixed_build_stay_inside_saved_month(tmp_path, lead):
    service = _service(tmp_path)
    _add(service, _document(fixed='26100.120'))
    feb = _document('2099-Feb', h.CVE_A, 'february.sys flaw', kb=h.KB_SERVER, fixed='26100.9002')
    feb['vulnerabilities'][0]['remediations'].append(h.remediation(2, h.KB_CLIENT, [h.PRODUCT_CLIENT], '26100.9002'))
    _add(service, feb)
    out = service.search(lead, months='2099-Jan')
    inv, product = out.result['investigation_id'], out.result['scopes'][0]['scope_id']
    service.components(inv, product=product, files=['exampledrv.sys'])
    _save_file_index(service)
    result = service.pairs(inv)
    assert {r['kb'] for r in result.result['resolutions']} == {h.KB_CLIENT}
    pair, = result.result['pairs']
    assert pair['fix_boundary'] == 'source-supported'
    bundle = _bundle(service, inv)
    assert [c.title for c in bundle.context.cards] == ['january.sys flaw']


@pytest.mark.parametrize('mode', ['files', 'cached'])
def test_unselected_newer_same_month_revision_neither_replaces_nor_suppresses_selected_snapshot(tmp_path, mode):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _, inv, product = _search(service, tmp_path, mode, jan)
    before = _bundle(service, inv)
    _add(service, _document(title='replacement.sys flaw', kb=h.KB_SERVER, date='2099-02-14'))
    after = _bundle(service, inv)
    assert after == before
    hints = service.components(inv, product=product, files=[])
    assert [x['basename'] for x in hints.result['hints']] == ['january.sys']
    assert [s.doc_id for s in after.sources] == [jan.doc_id]


def test_direct_context_builder_uses_saved_scope_for_lookups_sources_and_digest(tmp_path):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _, inv, _ = _search(service, tmp_path, 'cached', jan)
    rev, coverage = _saved(service, inv)
    _add(service, _document('2099-Feb', h.CVE_B, 'february.sys flaw'))
    with WorkspaceStore(service.root) as ws:
        bundle = build_bundle(investigation_id=inv, base_revision=rev.revision, lead=rev.lead,
                              cves=(h.CVE_A, h.CVE_B), index=ws.load_index(), rules=service.env.rules,
                              now=NOW, coverage=coverage, scope_id=None, pair_id=None,
                              older_sha=None, newer_sha=None)
    assert [c.cve for c in bundle.context.cards] == [h.CVE_A]
    assert [s.doc_id for s in bundle.sources] == [jan.doc_id]
    assert bundle.context.coverage == coverage
    expected = ReverseIndex()
    expected.add(jan)
    assert bundle.edge_set_digest == expected.edge_set_digest()


@pytest.mark.parametrize('damage', ['missing', 'invalid-json', 'wrong-id', 'contradictory-scope',
                                   'multiple-scopes', 'no-coverage', 'missing-source'])
@pytest.mark.parametrize('operation', ['components', 'products', 'pairs', 'import-pair'])
def test_invalid_saved_scope_fails_before_any_service_write(tmp_path, damage, operation):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _, inv, product = _search(service, tmp_path, 'months', jan)
    _save_file_index(service)
    older, newer = write_pair(tmp_path)
    with WorkspaceStore(service.root) as ws:
        rev = ws.current_revision(inv)
        key, = rev.coverage_ids
        if damage == 'missing':
            ws.db.execute('DELETE FROM coverage WHERE coverage_id=?', (key,))
        elif damage in ('invalid-json', 'wrong-id', 'contradictory-scope'):
            body = json.loads(ws.get_coverage(key).model_dump_json())
            if damage == 'wrong-id':
                body['coverage_id'] = 'f' * 64
            elif damage == 'contradictory-scope':
                body['scope']['months'] = ['2099-Feb']
            ws.db.execute('UPDATE coverage SET body=? WHERE coverage_id=?',
                          ('{' if damage == 'invalid-json' else json.dumps(body), key))
        elif damage in ('multiple-scopes', 'no-coverage'):
            ids = ()
            if damage == 'multiple-scopes':
                from patchtrace.kbcorrelation.sources.scope import months_scope
                other = ws.load_index().coverage(months_scope(('2099-Feb',)), now=NOW)
                ws.put_coverage(other)
                ids = tuple(sorted((key, other.coverage_id)))
            ws.apply(rev, Event('search_done', rev.revision, outcome='METADATA_READY',
                                scope_ids=rev.scope_ids, coverage_ids=ids))
        else:
            (ws.root / jan.source.object_path).unlink()
        before = '\n'.join(ws.db.iterdump())
    calls = {'components': lambda: service.components(inv, product=product, files=['user.sys']),
             'products': lambda: service.products(inv),
             'pairs': lambda: service.pairs(inv, product=product, files=['exampledrv.sys']),
             'import-pair': lambda: service.import_pair(inv, str(older), str(newer), str(tmp_path / 'P'))}
    with pytest.raises(KbcStoreError, match='repeat the search') as caught:
        calls[operation]()
    assert caught.value.code == 'PT-KBC-SCOPE'
    assert not (tmp_path / 'P').exists()
    with WorkspaceStore(service.root) as ws:
        assert '\n'.join(ws.db.iterdump()) == before


def test_empty_cached_scope_stays_empty_and_pair_only_still_attaches(tmp_path):
    service = _service(tmp_path)
    out = service.search(h.KB_CLIENT)
    inv = out.result['investigation_id']
    _add(service, _document())
    bundle = _bundle(service, inv)
    assert not bundle.context.cards and not bundle.sources
    assert bundle.context.coverage[0].scope.doc_ids == ()
    assert bundle.edge_set_digest == ReverseIndex().edge_set_digest()
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'pair-only'
    assert service.import_pair('new', str(older), str(newer), str(project)).exit == 0
    assert not service.explain(str(project), None).result['cves']


def test_explicit_repeat_search_can_widen_scope(tmp_path):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _add(service, _document('2099-Feb', h.CVE_B, 'february.sys flaw'))
    _, inv, _ = _search(service, tmp_path, 'months', jan)
    out = service.search(h.KB_CLIENT, months='2099-Jan,2099-Feb', investigation=inv)
    assert {e['cve'] for e in out.result['edges']} == {h.CVE_A, h.CVE_B}
    assert {c.cve for c in _bundle(service, inv).context.cards} == {h.CVE_A, h.CVE_B}


def test_explicit_file_search_selects_older_snapshot_when_newer_already_loaded(tmp_path):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _add(service, _document(kb=h.KB_SERVER, title='replacement.sys flaw', date='2099-02-14'))
    out, inv, _ = _search(service, tmp_path, 'files', jan)
    assert {e['cve'] for e in out.result['edges']} == {h.CVE_A}
    assert [c.title for c in _bundle(service, inv).context.cards] == ['january.sys flaw']


def test_mixed_scope_includes_named_month_and_explicit_document_but_not_intervening_month(tmp_path):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _add(service, _document('2099-Feb', h.CVE_B, 'february.sys flaw'))
    march = _add(service, _document('2099-Mar', h.CVE_MENTION, 'march.sys flaw'))
    scope_file = tmp_path / 'scope.json'
    scope_file.write_text(json.dumps({'months': ['2099-Jan'], 'doc_ids': [march.doc_id]}), encoding='utf-8')
    out = service.search(h.KB_CLIENT, scope_file=scope_file)
    bundle = _bundle(service, out.result['investigation_id'])
    assert {c.cve for c in bundle.context.cards} == {h.CVE_A, h.CVE_MENTION}
    assert {s.doc_id for s in bundle.sources} == {jan.doc_id, march.doc_id}


def test_newly_available_month_requires_repeat_search_without_changing_saved_coverage(tmp_path):
    service = _service(tmp_path)
    _add(service, _document())
    out = service.search(h.KB_CLIENT, months='2099-Jan,2099-Feb')
    inv, product = out.result['investigation_id'], out.result['scopes'][0]['scope_id']
    before = _bundle(service, inv)
    assert before.context.coverage[0].state == 'partial_in_scope'
    _add(service, _document('2099-Feb', h.CVE_B, 'february.sys flaw'))
    with WorkspaceStore(service.root) as ws:
        saved = '\n'.join(ws.db.iterdump())
    with pytest.raises(KbcStoreError, match='repeat the search'):
        service.components(inv, product=product, files=['new.sys'])
    with WorkspaceStore(service.root) as ws:
        assert '\n'.join(ws.db.iterdump()) == saved
    service.search(h.KB_CLIENT, months='2099-Jan,2099-Feb', investigation=inv)
    assert {c.cve for c in _bundle(service, inv).context.cards} == {h.CVE_A, h.CVE_B}


def test_corrupt_captured_scope_blocks_repair_before_attempt_or_project_writes(tmp_path):
    def crash(point):
        if point == 'after_sidecar_write':
            raise RuntimeError('simulated interruption after project creation')

    service = wiring.build_service(tmp_path / 'ws', clock=FixedClock(), fault=crash)
    jan = _add(service, _document())
    _, inv, _ = _search(service, tmp_path, 'months', jan)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'P'
    with pytest.raises(RuntimeError, match='simulated interruption'):
        service.import_pair(inv, str(older), str(newer), str(project))
    service = wiring.build_service(service.root, clock=FixedClock())
    with WorkspaceStore(service.root) as ws:
        key, = ws.current_revision(inv).coverage_ids
        good = ws.get_coverage(key).model_dump_json()
        ws.db.execute('UPDATE coverage SET body=? WHERE coverage_id=?', ('{', key))
        before = '\n'.join(ws.db.iterdump())
    project_before = (project / 'project.sqlite3').read_bytes()
    with pytest.raises(KbcStoreError, match='repeat the search') as caught:
        service.attach(str(project), inv, repair_it=True)
    assert caught.value.code == 'PT-KBC-SCOPE'
    with WorkspaceStore(service.root) as ws:
        assert '\n'.join(ws.db.iterdump()) == before
        ws.db.execute('UPDATE coverage SET body=? WHERE coverage_id=?', (good, key))
    assert (project / 'project.sqlite3').read_bytes() == project_before
    _add(service, _document('2099-Feb', h.CVE_B, 'february.sys flaw'))
    assert service.attach(str(project), inv, repair_it=True).exit == 0
    assert {r['cve'] for r in service.explain(str(project), None).result['cves']} == {h.CVE_A}


def test_direct_context_builder_refuses_missing_scope_for_advisory_lead(tmp_path):
    service = _service(tmp_path)
    jan = _add(service, _document())
    _, inv, _ = _search(service, tmp_path, 'months', jan)
    rev, _ = _saved(service, inv)
    with WorkspaceStore(service.root) as ws, pytest.raises(ValueError, match='saved search coverage'):
        build_bundle(investigation_id=inv, base_revision=rev.revision, lead=rev.lead,
                     cves=(h.CVE_A,), index=ws.load_index(), rules=service.env.rules, now=NOW,
                     coverage=(), scope_id=None, pair_id=None, older_sha=None, newer_sha=None)
