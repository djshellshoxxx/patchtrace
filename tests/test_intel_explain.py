"""``intelligence explain`` report builder (SPEC-28 section L) over SYNTHETIC fixtures and the synthetic sample
project. The builder is pure: it joins stored advisories, artifact identities, the CWE profile, hypotheses and
anchors into one ``IntelligenceReport`` and states what is unknown. It never decides between documents silently."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import threading
from pathlib import Path

import pytest

from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.contracts import IntelError, IntelligenceReport
from patchtrace.intelligence.csaf.applicability import resolve
from patchtrace.intelligence.csaf.identity import project_identities, record_only
from patchtrace.intelligence.explain import build_report
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.service import ProjectService

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
CVE = 'CVE-2099-10001'
REV1 = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
REV2 = (FIXTURES / 'synthetic-advisory-rev2.json').read_bytes()
VEX = (FIXTURES / 'synthetic-vex.json').read_bytes()
HOSTILE = (FIXTURES / 'injection' / 'hostile-advisory.json').read_bytes()


@pytest.fixture
def project(tmp_path):
    with ProjectService.sample(tmp_path / 'case') as service:
        store = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                              service.project.revision)
        yield service, store


def add(store: AdvisoryStore, raw: bytes, day: int = 1, name: str = 'advisory.json'):
    return store.add(raw, origin='local-import', uri=None, file_name=name, retrieved_at=f'2099-03-0{day}T00:00:00Z')


def identities(service):
    return project_identities(service.project.artifacts, service.root)


def derived(raw: bytes, **changes) -> bytes:
    """A variant of a fixture: dotted keys replace values (``document.tracking.id``)."""
    doc = json.loads(raw)
    for dotted, value in changes.items():
        node = doc
        *path, leaf = dotted.split('.')
        for key in path:
            node = node[int(key)] if key.isdigit() else node[key]
        node[int(leaf) if leaf.isdigit() else leaf] = value
    return json.dumps(doc).encode()


def test_single_advisory_report_follows_the_contract(project):
    service, store = project
    stored = add(store, REV1)
    advisories, warnings = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))
    assert warnings == [] and isinstance(report, IntelligenceReport) and report.cve == CVE
    (summary,) = report.sources
    assert summary.source.sha256 == hashlib.sha256(REV1).hexdigest() and summary.facts_id == stored.facts.facts_id
    assert summary.superseded is False and summary.cves == ('CVE-2099-10001', 'CVE-2099-10002')
    (fact,) = report.facts
    assert fact.cve == CVE and fact.source_id == summary.source.source_id
    assert (report.applicability.older.resolution, report.applicability.newer.resolution) == ('affected', 'fixed')
    assert report.cwe_profile.status == 'explicit' and report.cwe_profile.classifications[0].cwe_id == 'CWE-191'
    assert [h.rule_id for h in report.hypotheses.hypotheses] == ['R-INTEGER', 'R-MEMORY-WRITE']
    assert {(a.kind, a.value) for a in report.anchors.anchors} >= {('module', 'netstack.sys'), ('feature', 'IPv6')}
    assert report.limitations and 'does not show' in report.limitations[0]
    assert IntelligenceReport.model_validate_json(report.model_dump_json()) == report


def test_the_report_adds_no_claim_beyond_its_parts(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    older, newer = identities(service)
    report = build_report(CVE, advisories, older, newer)
    assert report.applicability == resolve(CVE, [a.facts for a in advisories], older, newer)
    assert report.facts == (advisories[0].facts.vulnerability(CVE),)


def test_report_is_deterministic_and_independent_of_input_order(project):
    service, store = project
    for day, raw in enumerate((REV1, REV2, VEX), start=1):
        add(store, raw, day)
    advisories, _ = store.for_cve(CVE)
    pair = identities(service)
    first = build_report(CVE, advisories, *pair)
    assert build_report(CVE, list(reversed(advisories)), *pair) == first
    assert build_report(CVE, advisories, *pair).model_dump_json() == first.model_dump_json()
    assert [s.source.tracking_id for s in first.sources] == sorted(s.source.tracking_id for s in first.sources)


def test_unknown_cve_or_no_advisory_is_not_found(project):
    service, store = project
    pair = identities(service)
    with pytest.raises(IntelError) as info:
        build_report(CVE, [], *pair)
    assert info.value.code == 'PT-INTEL-NOTFOUND'
    add(store, REV1)
    advisories, _ = store.advisories()
    with pytest.raises(IntelError) as info:
        build_report('CVE-2099-99999', advisories, *pair)
    assert info.value.code == 'PT-INTEL-NOTFOUND'
    for bad in ('not-a-cve', 'CVE-2099-' + chr(0xFF11) * 5, 'cve-2099-10001'):  # fullwidth digits, lower case
        with pytest.raises(IntelError) as info:
            build_report(bad, advisories, *pair)
        assert info.value.code == 'PT-INTEL-INPUT'


def test_swapped_identities_are_refused(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    older, newer = identities(service)
    with pytest.raises(IntelError) as info:
        build_report(CVE, advisories, newer, older)
    assert info.value.code == 'PT-INTEL-INPUT'


def test_unmapped_artifacts_abstain_and_the_report_lists_the_unknowns(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, record_only('older', 'e' * 64, 'unit test'),
                          record_only('newer', 'f' * 64, 'unit test'))
    assert report.applicability.older.resolution == 'unknown' == report.applicability.newer.resolution
    assert any(u.startswith('older artifact: no advisory product') for u in report.unknowns)
    assert any(u.startswith('newer artifact: no advisory product') for u in report.unknowns)
    assert list(report.unknowns) == sorted(set(report.unknowns))


def test_a_recorded_hash_without_verified_bytes_is_called_out(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    older, newer = identities(service)
    weak = (record_only('older', older.sha256, 'bytes not verified'), record_only('newer', newer.sha256, 'x'))
    report = build_report(CVE, advisories, *weak)
    assert report.applicability.older.product_mapping_status == 'candidate'
    assert any('older artifact: artifact bytes were not verified' in u for u in report.unknowns)
    assert any('older artifact: the product mapping is a candidate, not verified' in u for u in report.unknowns)


def test_local_files_are_reported_as_unauthenticated(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))
    assert any('advisory authenticity is unverified' in u for u in report.unknowns)


def test_revisions_and_vex_are_listed_and_contradictions_are_kept(project):
    service, store = project
    for day, raw in enumerate((REV1, REV2, VEX), start=1):
        add(store, raw, day)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))
    assert len(report.sources) == len(report.facts) == 3
    superseded = {(s.source.tracking_id, s.source.revision): s.superseded for s in report.sources}
    assert superseded[('PT-SYNTH_CVE-2099-10001', '1')] is True
    assert superseded[('PT-SYNTH_CVE-2099-10001', '2')] is False
    kinds = {c.kind for c in report.applicability.contradictions}
    assert {'cross-revision', 'vex-vs-advisory'} <= kinds


def test_a_superseded_flag_the_applicability_cannot_see_is_an_unknown(project):
    # The store marks a revision superseded by a newer stored revision that no longer lists the CVE; applicability
    # only sees documents that list it. The report says so instead of showing two answers.
    service, store = project
    add(store, REV1)
    (stored,), _ = store.for_cve(CVE)
    report = build_report(CVE, [dataclasses.replace(stored, superseded=True)], *identities(service))
    assert report.sources[0].superseded is True and report.applicability.sources == (stored.source.sha256,)
    assert any('a newer stored revision no longer lists CVE-2099-10001' in u for u in report.unknowns)


def test_cwe_profile_is_derived_from_a_named_current_document(project):
    service, store = project
    add(store, REV1)
    add(store, REV2, 2)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))
    sha2 = hashlib.sha256(REV2).hexdigest()
    notes = [x for x in report.cwe_profile.limitations if 'CWE profile derived from' in x]
    assert len(notes) == 1 and 'PT-SYNTH_CVE-2099-10001' in notes[0] and 'revision 2' in notes[0]
    assert sha2[:12] in notes[0] and '1 other stored document' in notes[0]


def test_two_current_documents_with_different_cwes_keep_the_disagreement(project):
    service, store = project
    add(store, REV1)
    add(store, derived(REV1, **{'document.tracking.id': 'PT-SYNTH_CVE-2099-10001-B',
                                'vulnerabilities.0.cwe': {'id': 'CWE-787', 'name': 'Out-of-bounds Write'}}), 2)
    advisories, _ = store.for_cve(CVE)
    pair = identities(service)
    report = build_report(CVE, advisories, *pair)
    (disagreement,) = [d for d in report.cwe_profile.disagreements if 'PT-SYNTH_CVE-2099-10001-B' in d]
    assert 'CWE-191' in disagreement and 'CWE-787' in disagreement and 'neither is resolved' in disagreement
    assert build_report(CVE, list(reversed(advisories)), *pair) == report  # the choice never depends on order
    assert len(report.sources) == 2 and all(s.superseded is False for s in report.sources)


def test_vague_text_is_an_explicit_unknown_not_a_guess(project):
    service, store = project
    vague = derived(REV1, **{'vulnerabilities.1.notes.0.text': 'An issue exists in a component.'})
    add(store, vague)
    advisories, _ = store.for_cve('CVE-2099-10002')
    report = build_report('CVE-2099-10002', advisories, *identities(service))
    assert report.cwe_profile.status == 'vague' and report.hypotheses.hypotheses == ()
    assert any('weakness class' in u and 'vague' in u for u in report.unknowns)
    assert any('no usable CWE' in u for u in report.unknowns)


def test_hostile_advisory_text_is_kept_verbatim_and_escaped_only_on_export(project):
    service, store = project
    add(store, HOSTILE)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))
    assert '<img src=x onerror=alert(1)>' in report.facts[0].title
    assert any('javascript:alert(document.cookie)' == r.url for r in report.facts[0].remediations)
    assert any(chr(0x202E) in n.text for n in report.facts[0].notes)


def test_report_carries_no_floating_point_scores(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    report = build_report(CVE, advisories, *identities(service))

    def walk(node):
        if isinstance(node, dict):
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)
        else:
            yield node
    assert not [v for v in walk(report.model_dump(mode='json')) if isinstance(v, float)]


def test_cancellation_is_cooperative(project):
    service, store = project
    add(store, REV1)
    advisories, _ = store.for_cve(CVE)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(IntelError) as info:
        build_report(CVE, advisories, *identities(service), cancel=cancel)
    assert info.value.code == 'PT-INTEL-CANCEL'
