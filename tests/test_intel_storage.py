"""Advisory snapshot storage (SPEC-28 section I) in a real (synthetic sample) project: append-only pointer
rows, hash-verified sidecars, derived staleness, last known-good on failure. Fixtures are SYNTHETIC."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from patchtrace.enrichment.storage import KINDS, EnrichmentStore, Guard
from patchtrace.intelligence.contracts import ArtifactIdentity, IntelError
from patchtrace.intelligence.storage import FACTS_KIND, SOURCE_KIND, AdvisoryStore
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
REV1 = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
REV2 = (FIXTURES / 'synthetic-advisory-rev2.json').read_bytes()


@pytest.fixture
def service(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as svc:
        yield svc


def store_for(service) -> AdvisoryStore:
    return AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id, service.project.revision)


def add(store: AdvisoryStore, raw: bytes, stamp: str = '2099-03-01T00:00:00Z', name: str = 'advisory.json'):
    return store.add(raw, origin='local-import', uri=None, file_name=name, retrieved_at=stamp)


def rows(service, kind):
    return EnrichmentStore(service.store).entries(kind)


def test_reserved_kinds_are_used():
    assert {SOURCE_KIND, FACTS_KIND} <= KINDS


def test_import_writes_exact_bytes_and_small_pointer_rows(service):
    stored = add(store_for(service), REV1)
    sha = hashlib.sha256(REV1).hexdigest()
    assert stored.source.sha256 == sha and stored.facts.cves() == ('CVE-2099-10001', 'CVE-2099-10002')
    assert (service.root / stored.source.raw_path).read_bytes() == REV1  # original bytes preserved exactly
    (source_row,), (facts_row,) = rows(service, SOURCE_KIND), rows(service, FACTS_KIND)
    assert source_row.id.startswith(f'{SOURCE_KIND}:{sha}:') and facts_row.id == f'{FACTS_KIND}:{stored.facts.facts_id}'
    assert len(json.dumps(source_row.body)) < 4096 and len(json.dumps(facts_row.body)) < 4096
    assert facts_row.body['cves'] == ['CVE-2099-10001', 'CVE-2099-10002'] and not source_row.stale


def test_newer_revision_marks_the_older_one_superseded_without_rewriting_rows(service):
    store = store_for(service)
    add(store, REV1)
    before = {e.id: e.body for e in rows(service, SOURCE_KIND) + rows(service, FACTS_KIND)}
    add(store, REV2, stamp='2099-03-02T00:00:00Z')
    advisories, warnings = store.advisories()
    assert warnings == []
    assert [(a.facts.revision, a.superseded) for a in advisories] == [('1', True), ('2', False)]
    after = {e.id: e.body for e in rows(service, SOURCE_KIND) + rows(service, FACTS_KIND)}
    assert all(after[row_id] == body for row_id, body in before.items())  # append-only
    assert len(after) == len(before) + 2


def test_reimport_of_identical_bytes_adds_a_retrieval_not_a_duplicate(service):
    store = store_for(service)
    add(store, REV1)
    again = add(store, REV1, stamp='2099-04-01T00:00:00Z', name='copy.json')
    assert again.retrievals == 2 and again.source.file_name == 'copy.json'
    assert len(rows(service, SOURCE_KIND)) == 2 and len(rows(service, FACTS_KIND)) == 1
    advisories, _ = store.advisories()
    assert len(advisories) == 1


def test_rejected_document_leaves_last_known_good_state(service):
    store = store_for(service)
    add(store, REV1)
    snapshot = sorted(p.relative_to(service.root) for p in (service.root / 'intelligence').rglob('*'))
    bad = json.loads(REV1)
    bad['vulnerabilities'][0]['product_status']['fixed'].append('PT-UNDEFINED')
    with pytest.raises(IntelError) as info:
        add(store, json.dumps(bad).encode())
    assert info.value.code == 'PT-INTEL-VALIDATE'
    with pytest.raises(IntelError):
        add(store, b'{"document": 1, "document": 2}')
    assert sorted(p.relative_to(service.root) for p in (service.root / 'intelligence').rglob('*')) == snapshot
    assert len(rows(service, SOURCE_KIND)) == 1


def test_cancelled_import_writes_nothing(service):
    store = store_for(service)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(IntelError) as info:
        store.add(REV1, origin='local-import', uri=None, file_name='a.json', retrieved_at='2099-03-01T00:00:00Z',
                  cancel=cancel)
    assert info.value.code == 'PT-INTEL-CANCEL'
    assert not (service.root / 'intelligence').exists() and rows(service, SOURCE_KIND) == []


def test_damaged_sidecars_are_detected_and_never_trusted(service):
    store = store_for(service)
    first = add(store, REV1)
    add(store, REV2, stamp='2099-03-02T00:00:00Z')
    facts_file = service.root / 'intelligence' / 'csaf' / 'facts' / f'{first.facts.facts_id}.json'
    facts_file.write_text('{"tampered": true}', encoding='utf-8')
    advisories, warnings = store.advisories()
    assert len(advisories) == 2 and any('recomputed' in w for w in warnings)
    assert next(a for a in advisories if a.facts.revision == '1').facts == first.facts
    (service.root / first.source.raw_path).write_bytes(b'tampered source')
    advisories, warnings = store.advisories()
    assert [a.facts.revision for a in advisories] == ['2']
    assert any('PT-INTEL-INTEGRITY' in w for w in warnings)


def test_advisory_rows_survive_retention(service):
    store = store_for(service)
    add(store, REV1)
    enrichment = EnrichmentStore(service.store)
    started = datetime.now(UTC).isoformat()
    enrichment.apply_retention(Guard(service.project.id, 'run', 'a' * 64, 'b' * 64), started=started)
    assert len(rows(service, SOURCE_KIND)) == 1 and len(rows(service, FACTS_KIND)) == 1


def test_for_cve_filters_and_unknown_cve_is_empty(service):
    store = store_for(service)
    add(store, REV1)
    assert [a.facts.revision for a in store.for_cve('CVE-2099-10002')[0]] == ['1']
    assert store.for_cve('CVE-2099-99999')[0] == []


def test_facts_sidecar_is_deterministic(service, tmp_path):
    first = add(store_for(service), REV1)
    with ProjectService.sample(tmp_path / 'other') as other:
        second = add(store_for(other), REV1, stamp='2099-05-05T00:00:00Z')
        path = f'intelligence/csaf/facts/{first.facts.facts_id}.json'
        assert (service.root / path).read_bytes() == (other.root / path).read_bytes()
    assert first.facts == second.facts


# ---- audit C ------------------------------------------------------------------------------------------------------

def test_c21_a_facts_row_pointing_at_another_sources_facts_is_never_served(service):
    store = store_for(service)
    first = add(store, REV1)
    second = add(store, REV2, stamp='2099-03-02T00:00:00Z')
    rev1_row = next(e for e in rows(service, FACTS_KIND) if e.id == f'{FACTS_KIND}:{first.facts.facts_id}')
    forged = dict(rev1_row.body, facts_id=second.facts.facts_id, source_id=second.source.sha256)
    guard = Guard(service.project.id, rev1_row.guard.run_id, second.source.sha256, rev1_row.guard.input_digest)
    EnrichmentStore(service.store).publish(FACTS_KIND, guard, guard, service.project.revision, 'complete', forged,
                                           f'{FACTS_KIND}:{second.facts.facts_id}')  # valid path, valid hash, wrong file
    advisories, warnings = store.advisories()
    served = next(a for a in advisories if a.source.sha256 == second.source.sha256)
    assert served.facts == second.facts and served.facts.revision == '2'
    assert any('recomputed' in w for w in warnings)


def test_c03_store_applicability_sees_a_newer_revision_that_dropped_the_cve(service):
    store = store_for(service)
    add(store, REV1)
    doc = json.loads(REV2)
    doc['vulnerabilities'] = [v for v in doc['vulnerabilities'] if v['cve'] != 'CVE-2099-10001']
    add(store, json.dumps(doc).encode(), stamp='2099-03-02T00:00:00Z')
    assert [a.facts.revision for a in store.for_cve('CVE-2099-10001')[0]] == ['1']  # only the older one lists it
    older = ArtifactIdentity(side='older', sha256='e' * 64, asserted_product_ids=('PT-101-1',),
                             facts_state='verified-bytes')
    newer = ArtifactIdentity(side='newer', sha256='f' * 64, facts_state='verified-bytes')
    report, warnings = store.applicability('CVE-2099-10001', older, newer)
    assert warnings == [] and report.older.resolution == 'unknown' and len(report.superseded_sources) == 1
    assert any('no longer lists CVE-2099-10001' in note for note in (*report.limitations, *report.older.why))
