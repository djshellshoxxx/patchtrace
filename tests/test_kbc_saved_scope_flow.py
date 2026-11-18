"""Finite saved scopes through public services, real stores and headless CLI; synthetic only."""
from __future__ import annotations

import copy
import json
import os
import ssl  # noqa: F401  # Import before no_sockets replaces socket.socket.
import subprocess
import sys
from pathlib import Path

import kbc_helpers as h
import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import NOW, FixedClock, write_pair
from kbc_saved_scope_support import add, bundle, document, refused_without_writes, saved, seeded

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.context import ContextBundle, build_bundle
from patchtrace.kbcorrelation.contracts import domain_id
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.sources.scope import corpus_scope, files_scope
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('mode', ['cached', 'files', 'months', 'mixed'])
def test_saved_scope_survives_cache_growth_reopen_import_export_and_actual_cli(tmp_path, mode):
    service, jan, investigation, product = seeded(tmp_path, mode=mode)
    before = bundle(service, investigation)
    _, coverage = saved(service, investigation)
    add(service, document('2099-Feb', h.CVE_B, 'february.sys flaw', date='2099-02-13'))
    service = wiring.build_service(service.root, clock=FixedClock())
    after = bundle(service, investigation)
    assert after == before, 'an unrelated document changed the saved context or its key'
    out = service.components(investigation, product=product, files=['exampledrv.sys'])
    assert {row['basename'] for row in out.result['hints']} == {'january.sys', 'exampledrv.sys'}
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project-Ж'
    assert service.import_pair(investigation, str(older), str(newer), str(project)).exit == 0
    exported = tmp_path / 'context.json'
    assert service.export(str(project), str(exported), overwrite=False).exit == 0
    attached = ContextBundle.model_validate_json(exported.read_bytes())
    assert attached.context.coverage == coverage
    assert [source.doc_id for source in attached.sources] == [jan.doc_id]
    assert attached.edge_set_digest == before.edge_set_digest
    assert {p.name for p in (project / 'kb/sources').glob('*.gz')} == {jan.source.sha256 + '.json.gz'}
    guard = ('import pathlib,socket,sys; '
             'socket.create_connection=lambda *a,**k: (_ for _ in ()).throw(AssertionError("network")); '
             'import patchtrace; '
             f'assert pathlib.Path(patchtrace.__file__).resolve()==pathlib.Path({str(ROOT / "src/patchtrace/__init__.py")!r}); '
             'from patchtrace.cli import main; code=main(sys.argv[1:]); '
             'assert not any(n.startswith("PySide6") for n in sys.modules); sys.exit(code)')
    result = subprocess.run([sys.executable, '-c', guard, 'kb', 'explain', str(project),
                             '--workspace', str(service.root), '--json'], cwd=ROOT,
                            env=dict(os.environ, PYTHONPATH=str(ROOT / 'src'), QT_QPA_PLATFORM='offscreen'),
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and result.stderr == '', result.stderr
    explained = json.loads(result.stdout)['result']
    assert {row['cve'] for row in explained['cves']} == {h.CVE_A}
    assert explained['coverage'] == [item.model_dump(mode='json') for item in coverage]


def test_empty_cached_scope_remains_empty_until_explicit_repeat_search(tmp_path):
    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock())
    out = service.search(h.KB_CLIENT)
    investigation = out.result['investigation_id']
    before = bundle(service, investigation)
    add(service, document())
    assert bundle(service, investigation) == before
    assert not before.sources and not before.context.cards
    assert before.edge_set_digest == ReverseIndex().edge_set_digest()
    service.search(h.KB_CLIENT, investigation=investigation)
    assert {card.cve for card in bundle(service, investigation).context.cards} == {h.CVE_A}


def test_direct_builder_infers_saved_scope_and_uses_one_scoped_edge_digest(tmp_path):
    service, jan, investigation, _product = seeded(tmp_path, mode='cached')
    rev, coverage = saved(service, investigation)
    add(service, document('2099-Feb', h.CVE_B, 'february.sys flaw', date='2099-02-13'))
    with WorkspaceStore(service.root) as store:
        built = build_bundle(investigation_id=investigation, base_revision=rev.revision, lead=rev.lead,
            cves=(h.CVE_A, h.CVE_B), index=store.load_index(), rules=service.env.rules, now=NOW, coverage=coverage,
            scope_id=None, pair_id=None, older_sha=None, newer_sha=None)
    assert [card.cve for card in built.context.cards] == [h.CVE_A]
    assert [source.doc_id for source in built.sources] == [jan.doc_id]
    assert built.context.coverage == coverage
    assert built.edge_set_digest == domain_id('kbc.edgeset', 1, sorted(edge.edge_id for edge in jan.edges))
    assert built.context_key == bundle(service, investigation).context_key


@pytest.mark.parametrize('mode', ['files', 'cached'])
@pytest.mark.parametrize('replacement', ['withdrawn', 'negative', 'new-kb'])
def test_selected_old_sources_do_not_regain_admission_when_new_revision_is_outside_scope(tmp_path, mode, replacement):
    service, jan, investigation, _product = seeded(tmp_path, mode=mode)
    value = document(date='2099-02-14', title='replacement.sys flaw')
    if replacement == 'withdrawn':
        value['vulnerabilities'] = []
    elif replacement == 'negative':
        value['vulnerabilities'][0]['product_statuses'] = {'known_not_affected': [h.PRODUCT_CLIENT]}
    else:
        value['vulnerabilities'][0]['remediations'][0]['description'] = h.KB_SERVER
    newer = add(service, value)
    if replacement == 'negative':
        assert newer.edges and {edge.relation for edge in newer.edges} == {'disputed'}
    with WorkspaceStore(service.root) as store:
        index = store.load_index()
        assert index.active_ids() == {newer.doc_id}
        scope = corpus_scope((jan.doc_id,)) if mode == 'cached' else files_scope((jan.doc_id,))
        lookup = index.lookup_kb(h.KB_CLIENT, scope=scope, now=NOW)
        assert not lookup.edges and {edge.ref.doc_id for edge in lookup.superseded} == {jan.doc_id}
    after = bundle(service, investigation)
    assert not after.context.cards and not after.sources
    assert after.edge_set_digest == ReverseIndex().edge_set_digest()


@pytest.mark.parametrize('kind', ['cached', 'files'])
@pytest.mark.parametrize('zoned', [False, True])
def test_native_ambiguous_admission_uses_global_competitors_before_selected_projection(kind, zoned):
    # Authored edits of a retained factual fixture, not a vendor/native-format qualification.
    positive = json.loads((ROOT / 'tests/fixtures/kbcve/msrc/2024-Aug-CVE-2024-38193.facts.json').read_bytes())
    positive['DocumentTracking']['CurrentReleaseDate'] = '2026-10-28T01:48:49' + ('Z' if zoned else '')
    negative = copy.deepcopy(positive)
    negative['Vulnerability'][0]['Remediations'] = []
    docs = [import_bytes(json.dumps(value).encode(), now=NOW) for value in (positive, negative)]
    index = ReverseIndex()
    for doc in docs:
        index.add(doc)
    assert index.active_ids() == {doc.doc_id for doc in docs}
    assert docs[0].edges and not docs[1].edges
    scope = corpus_scope((docs[0].doc_id,)) if kind == 'cached' else files_scope((docs[0].doc_id,))
    result = index.lookup_cve('CVE-2024-38193', scope=scope, now=NOW)
    assert not result.edges and result.disputed
    assert {edge.ref.doc_id for edge in result.disputed} == {docs[0].doc_id}
    assert any(w.startswith('REVISION_EDGE_CONFLICT:') for w in result.warnings)
    assert any(w.startswith('REVISION_ORDER_UNKNOWN:') for w in result.warnings)


def test_unreadable_unselected_current_source_cannot_restore_an_old_claim(tmp_path, monkeypatch):
    service, _jan, investigation, product = seeded(tmp_path, mode='files')
    withdrawn = document(date='2099-02-14')
    withdrawn['vulnerabilities'] = []
    latest = add(service, withdrawn)
    path = service.root / latest.source.object_path
    good = path.read_bytes()
    path.unlink()
    refused_without_writes(lambda: service.components(investigation, product=product, files=['user.sys']),
                           service, tmp_path / 'not-created', monkeypatch)
    path.write_bytes(good)
    assert not bundle(service, investigation).context.cards


def test_age_alone_preserves_saved_coverage_and_legacy_context_remains_readable(tmp_path):
    service, _jan, investigation, _product = seeded(tmp_path, mode='cached')
    before = bundle(service, investigation)

    class Later:
        def now_utc(self):
            return '2100-01-01T00:00:00Z'

    service = wiring.build_service(service.root, clock=Later())
    assert bundle(service, investigation) == before
    legacy = before.model_dump(mode='json')
    legacy.pop('card_facts')
    legacy['edge_set_digest'] = 'f' * 64  # Old recorded full-index digest is not rewritten on read.
    raw = json.dumps(legacy)
    recorded = ContextBundle.model_validate_json(raw)
    assert recorded.edge_set_digest == 'f' * 64 and not recorded.card_facts
    assert recorded.context == before.context and recorded.context_key == before.context_key


def test_pair_only_context_and_pending_repair_do_not_require_an_advisory_search(tmp_path):
    def interrupt(point):
        if point == 'after_sidecar_write':
            raise RuntimeError('authored pair-only interruption')

    service = wiring.build_service(tmp_path / 'workspace', clock=FixedClock(), fault=interrupt)
    older, newer = write_pair(tmp_path)
    project = tmp_path / 'project'
    with pytest.raises(RuntimeError, match='pair-only interruption'):
        service.import_pair('new', str(older), str(newer), str(project))
    with WorkspaceStore(service.root) as store:
        investigation = store.journal_ops()[0][2]['revision']['investigation_id']
        assert store.current_revision(investigation).coverage_ids == ()
    service = wiring.build_service(service.root, clock=FixedClock())
    add(service, document())
    assert service.attach(str(project), investigation, repair_it=True).exit == 0
    assert not service.explain(str(project), None).result['cves']
