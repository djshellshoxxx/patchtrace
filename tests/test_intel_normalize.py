"""CSAF normalization (SPEC-28 section F) over SYNTHETIC fixtures: product graph, flattened claims, pointers."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path

import pytest

from patchtrace.intelligence.contracts import AdvisoryFacts, AdvisorySource, IntelError
from patchtrace.intelligence.csaf import normalize as n
from patchtrace.intelligence.csaf import validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'


def load(name='synthetic-advisory-rev1.json', raw: bytes | None = None) -> AdvisoryFacts:
    raw = raw if raw is not None else (FIXTURES / name).read_bytes()
    doc, report = validate.load_document(raw)
    return n.normalize(doc, report, hashlib.sha256(raw).hexdigest())


def resolve(doc: dict, pointer: str):
    node = doc
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def test_product_graph_from_branches_full_names_and_relationships():
    facts = load()
    ids = [p.product_id for p in facts.products]
    assert ids == sorted(ids) and len(ids) == 10
    x64_old = facts.product('PT-100-1')
    assert x64_old.definition == 'branch' and x64_old.version_range == '<10.0.22621.4037' and x64_old.version is None
    assert [(s.category, s.name) for s in x64_old.branch_path] == [
        ('vendor', 'PatchTrace Synthetic Fixture Vendor'), ('product_family', 'Example OS'),
        ('product_name', 'Example OS 22H2 for x64-based Systems'), ('product_version_range', '<10.0.22621.4037')]
    assert x64_old.group_ids == ('PT-G-22H2-BEFORE-FIX',)
    assert x64_old.pointer == '/product_tree/branches/0/branches/0/branches/0/branches/0/product'
    assert facts.product('PT-100-2').version == '10.0.22621.4037'
    component = facts.product('PT-801')
    assert component.definition == 'relationship' and component.branch_path == ()
    assert (component.relationship.category, component.relationship.product_reference,
            component.relationship.relates_to_product_reference) == ('default_component_of', 'PT-800', 'PT-100-1')
    driver = facts.product('PT-900')
    assert [(h.file_name, h.sha256) for h in driver.identification.sha256_hashes] == [
        ('netstack.sys', '4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168')]
    assert [(g.group_id, g.product_ids) for g in facts.groups] == [('PT-G-22H2-BEFORE-FIX', ('PT-100-1', 'PT-101-1'))]


def test_multiple_cves_and_claims_carry_exact_pointers():
    raw = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc = json.loads(raw)
    facts = load(raw=raw)
    assert facts.cves() == ('CVE-2099-10001', 'CVE-2099-10002')
    first = facts.vulnerability('CVE-2099-10001')
    assert first.pointer == '/vulnerabilities/0' and first.cwe.id == 'CWE-191'
    assert first.cwe.pointer == '/vulnerabilities/0/cwe'
    claims = {(c.product_id, c.status) for c in first.product_status}
    assert ('PT-100-1', 'known_affected') in claims and ('PT-901', 'fixed') in claims
    for claim in first.product_status:  # every normalized claim points at the exact source value
        assert resolve(doc, claim.pointer) == claim.product_id
    for note in first.notes:
        assert resolve(doc, note.pointer)['text'] == note.text
    remediation = first.remediations[0]
    assert remediation.product_ids == ('PT-801',) and remediation.group_ids == ('PT-G-22H2-BEFORE-FIX',)
    assert remediation.via_groups == ('PT-100-1', 'PT-101-1') and remediation.restart_required == 'machine'
    score = first.scores[0]
    assert (score.cvss_version, score.base_score, score.base_severity) == ('3.1', '9.8', 'CRITICAL')
    assert resolve(doc, score.pointer)['vectorString'] == score.vector
    second = facts.vulnerability('CVE-2099-10002')
    assert second.cwe is None and second.assessment == 'advisory-claim'
    assert {c.status for c in second.product_status} == {'fixed', 'known_affected', 'known_not_affected'}


def test_note_text_is_kept_verbatim_including_markup_and_controls():
    facts = load()
    markup = next(note for note in facts.document_notes if note.category == 'general')
    assert '<script>alert(1)</script>' in markup.text and '‮' in markup.text and '漏洞' in markup.text
    assert markup.title == 'Markup and Unicode <b>title</b>'


def test_normalization_is_deterministic_and_content_addressed():
    first, second = load(), load()
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.facts_id == n.facts_id_for(first.source_id)
    rev2 = load('synthetic-advisory-rev2.json')
    assert rev2.facts_id != first.facts_id and rev2.tracking_id == first.tracking_id and rev2.revision == '2'
    assert AdvisoryFacts.model_validate_json(first.model_dump_json()) == first


def test_pointer_escaping_rfc6901():
    assert n.pointer('', 'a/b', 'm~n', 3) == '/a~1b/m~0n/3'


def test_filename_rule_section_5_1():
    assert n.csaf_filename('PT-SYNTH_CVE-2099-10001') == 'pt-synth_cve-2099-10001.json'
    assert n.csaf_filename('2022_#01-A') == '2022_01-a.json'
    assert n.csaf_filename('Example Company - 2019-YH3234') == 'example_company_-_2019-yh3234.json'


def test_source_record_for_local_and_fetched_bytes():
    raw = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc, _ = validate.load_document(raw)
    local = n.make_source(doc, raw, origin='local-import', uri=None, file_name='synthetic-advisory-rev1.json',
                          retrieved_at='2099-03-01T00:00:00Z')
    assert isinstance(local, AdvisorySource) and local.uri is None
    assert local.authenticity_state == 'unverified-local-file' and local.signature_state == 'not-checked'
    assert local.raw_path == f'intelligence/csaf/sources/{local.sha256}.json'
    assert local.tracking_id == 'PT-SYNTH_CVE-2099-10001' and local.self_urls == (
        'https://example.invalid/patchtrace-synthetic/csaf/2099/pt-synth_cve-2099-10001.json',)
    fetched = n.make_source(doc, raw, origin='https-fetch',
                            uri='https://msrc.microsoft.com/csaf/advisories/2099/pt-synth_cve-2099-10001.json',
                            file_name='pt-synth_cve-2099-10001.json', retrieved_at='2099-03-01T00:00:00Z',
                            authenticity_state='tls-allowlisted-host-hash-match')
    assert fetched.filename_matches_tracking_id is True and fetched.retrieval_id != local.retrieval_id
    with pytest.raises(IntelError):
        n.make_source(doc, raw, origin='local-import', uri=None, file_name='../secret/path.json',
                      retrieved_at='2099-03-01T00:00:00Z')


def test_oversized_identifier_is_rejected_not_truncated():
    doc = json.loads((FIXTURES / 'synthetic-advisory-rev1.json').read_text(encoding='utf-8'))
    doc['product_tree']['full_product_names'][0]['name'] = 'x' * 1001  # Appendix C.3 bound is 1000
    raw = json.dumps(doc).encode()
    parsed, report = validate.load_document(raw)
    with pytest.raises(IntelError) as info:
        n.normalize(parsed, report, hashlib.sha256(raw).hexdigest())
    assert info.value.code == 'PT-INTEL-LIMIT'


def test_cancellation_during_normalization():
    raw = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc, report = validate.load_document(raw)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(IntelError) as info:
        n.normalize(doc, report, hashlib.sha256(raw).hexdigest(), cancel=cancel)
    assert info.value.code == 'PT-INTEL-CANCEL'


def test_vulnerability_without_cve_keeps_its_ids():
    doc = json.loads((FIXTURES / 'synthetic-vex.json').read_text(encoding='utf-8'))
    del doc['vulnerabilities'][0]['cve']
    doc['vulnerabilities'][0]['ids'] = [{'system_name': 'Synthetic tracker', 'text': 'PT-BUG-1'}]
    raw = json.dumps(doc).encode()
    parsed, report = validate.load_document(raw)
    facts = n.normalize(parsed, report, hashlib.sha256(raw).hexdigest())
    item = facts.vulnerabilities[0]
    assert item.cve is None and [(i.system_name, i.text) for i in item.ids] == [('Synthetic tracker', 'PT-BUG-1')]
    assert facts.cves() == ()
    assert [(f.label, f.product_ids) for f in item.flags] == [('vulnerable_code_not_present', ('VEX-1',))]
