"""Search anchors (SPEC-28 section H): labelled hints with source, pointer and quality; never joined to
match results. Inputs are SYNTHETIC fixtures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from patchtrace.intelligence import anchors as an
from patchtrace.intelligence import hypotheses as hy
from patchtrace.intelligence import lexicon as lx
from patchtrace.intelligence.contracts import AnchorSet, ArtifactIdentity, PdbIdentity
from patchtrace.intelligence.csaf import normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'


def load(raw: bytes | None = None):
    raw = raw if raw is not None else (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc, report = validate.load_document(raw)
    return normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())


def anchors(cve: str, docs=None, identities=()) -> AnchorSet:
    docs = docs or [load()]
    item = next(d.vulnerability(cve) for d in docs if d.vulnerability(cve))
    return an.anchors_for(cve, docs, identities, hy.hypotheses_for(lx.classify(item)))


def find(result: AnchorSet, kind: str) -> dict[str, list]:
    out: dict[str, list] = {}
    for anchor in result.anchors:
        if anchor.kind == kind:
            out.setdefault(anchor.value, []).append(anchor)
    return out


def test_module_feature_and_component_anchors_from_advisory_text():
    result = anchors('CVE-2099-10001')
    modules = find(result, 'module')
    note = next(a for a in modules['netstack.sys'] if a.source == 'csaf-note')
    assert (note.quality, note.pointer) == ('explicit', '/vulnerabilities/0/notes/0')
    assert any(a.source == 'csaf-product' and a.pointer.startswith('/product_tree/relationships/')
               for a in modules['netstack.sys'])
    assert 'IPv6' in find(result, 'feature')
    (component,) = find(result, 'component')
    assert component == 'SYNTHETIC Example OS netstack'
    assert all(a.assessment == 'search-hint' for a in result.anchors)


def test_rule_api_anchors_and_pdb_anchor_are_labelled():
    identity = ArtifactIdentity(side='newer', sha256='c' * 64, facts_state='verified-bytes',
                                pdb_identity=PdbIdentity(name='netstack.pdb', guid='0' * 32, age=1))
    result = anchors('CVE-2099-10001', identities=[identity])
    apis = find(result, 'api')
    assert {'memcpy', 'RtlULongSub'} <= set(apis)
    assert all(a.quality == 'rule' and a.source == 'hypothesis-rule' and a.pointer is None
               for values in apis.values() for a in values)
    (pdb,) = find(result, 'pdb')['netstack.pdb']
    assert (pdb.quality, pdb.source) == ('verified-bytes', 'artifact-identity') and 'newer' in pdb.label


def test_second_cve_gets_its_own_anchors():
    result = anchors('CVE-2099-10002')
    assert 'spoolsv.exe' in find(result, 'module') and 'netstack.sys' not in find(result, 'module')
    assert 'Print Spooler' in find(result, 'feature')


def test_markup_never_becomes_an_anchor_and_values_are_plain_text():
    doc = json.loads((FIXTURES / 'synthetic-advisory-rev1.json').read_text(encoding='utf-8'))
    doc['vulnerabilities'][0]['notes'][0]['text'] = ('<img src=x onerror=alert(1)> <script>evil()</script> '
                                                     'Affects <b>evil.dll</b> and "Quoted UI text" in IPv6land.')
    facts = load(json.dumps(doc).encode())
    result = anchors('CVE-2099-10001', docs=[facts])
    values = {a.value for a in result.anchors}
    assert 'evil.dll' in values and 'Quoted UI text' in values
    assert not any('<' in v or '>' in v or 'onerror' in v for v in values)
    assert all(a.pointer != '/vulnerabilities/0/notes/0' for a in find(result, 'feature').get('IPv6', ()))


def test_anchor_set_is_deterministic_bounded_and_never_names_matches():
    first, second = anchors('CVE-2099-10001'), anchors('CVE-2099-10001')
    assert first == second
    keys = [(a.kind, a.value, a.source, a.pointer or '') for a in first.anchors]
    assert keys == sorted(keys) and len({a.anchor_id for a in first.anchors}) == len(first.anchors)
    assert len(first.anchors) <= an.MAX_ANCHORS
    assert 'match' not in json.dumps(json.loads(first.model_dump_json())).lower().replace('no match', '')
