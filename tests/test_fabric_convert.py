"""FAB-2 converters (docs/specs/program-e/FAB-integration-plan.md s9): every K and PIL sample converts to a fabric
anchor that verifies, passes the origin guard and is accepted by the store; refusals are typed and name the missing piece.
Synthetic data only: the K samples come from the synthetic CSAF fixture, the PIL samples from the synergy-1 fixture's
anchor id and candidate key, and every other value is built in code.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import fabric_support as fs
import pytest

from patchtrace.fabric import convert, ids, origins
from patchtrace.fabric.contracts import AnchorQuery, Ref
from patchtrace.fabric.limits import FabricError
from patchtrace.fabric.memory import MemoryAnchorStore
from patchtrace.intelligence import anchors as an
from patchtrace.intelligence import hypotheses as hy
from patchtrace.intelligence import lexicon as lx
from patchtrace.intelligence.contracts import ArtifactIdentity, PdbIdentity
from patchtrace.intelligence.csaf import normalize, validate
from patchtrace.pilot import keys as pilot_keys
from patchtrace.pilot.contracts import PilotAnchor

CVE = 'CVE-2099-10001'
FIXTURE = Path(__file__).parent / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json'
NOTE = '/vulnerabilities/0/notes/0'
KB_BATCH = 'kb-synthetic'
PIL_BATCH = 'pil-synthetic'
REGISTRY = origins.DefaultOriginRegistry()
SIDE = 'newer'
TEXT = 'Ipv6 reassembly fragment length'
CANDIDATE = pilot_keys.candidate_key(fs.OLDER, fs.NEWER, [fs.F_OLD], [fs.F_NEW])
PAIR = fs.pair_ref()


def identity(name: str = 'netstack.pdb') -> ArtifactIdentity:
    return ArtifactIdentity(side=SIDE, sha256='c' * 64, facts_state='verified-bytes',
                            pdb_identity=PdbIdentity(name=name, guid='0' * 32, age=1))


def k_sample():
    """The K anchors of the synthetic advisory (module, feature, component, hypothesis APIs, PDB name), the advisory
    document they point into and the artifact identity the PDB name was verified in."""
    raw = FIXTURE.read_bytes()
    doc, report = validate.load_document(raw)
    facts = normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())
    hints = hy.hypotheses_for(lx.classify(facts.vulnerability(CVE)))
    anchors = an.anchors_for(CVE, [facts], [identity()], hints).anchors
    return anchors, Ref(kind='csaf', id=facts.tracking_id, sha256=facts.source_id), identity()


def k_of(kind: str, value: str, anchors):
    return next(a for a in anchors if a.kind == kind and a.value == value)


def k_note(anchors):
    return next(a for a in anchors if a.kind == 'module' and a.source == 'csaf-note')


def k_quoted(text: str = 'Attackers send a "SYNTHETIC rtl frame" to netstack.sys.'):
    return next(a for a in an.text_anchors(text, 'csaf-note', NOTE) if a.kind == 'string')


# --- K samples ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize('kind, value, fabric_kind, role, side, source', [
    ('module', 'netstack.sys', 'advisory_phrase', 'stated', 'none', 'advisory-text'),
    ('feature', 'IPv6', 'advisory_phrase', 'hint', 'none', 'advisory-text'),
    ('component', 'SYNTHETIC Example OS netstack', 'advisory_phrase', 'hint', 'none', 'advisory-text'),
    ('api', 'memcpy', 'import', 'hint', 'none', 'advisory-text'),
    ('api', 'RtlULongSub', 'import', 'hint', 'none', 'advisory-text'),
    ('pdb', 'netstack.pdb', 'build_fact', 'observed', SIDE, 'pe-self-report'),
], ids=['module', 'feature', 'component', 'api-memcpy', 'api-rtlulongsub', 'pdb'])
def test_each_k_sample_converts_to_the_planned_kind_role_side_and_origin(kind, value, fabric_kind, role, side, source):
    anchors, document, artifact = k_sample()
    converted = convert.from_k_anchor(k_of(kind, value, anchors), batch=KB_BATCH, document=document,
                                      identity=artifact)
    ids.verify_anchor(converted)
    origins.check_origins(converted, REGISTRY)
    assert (converted.kind, converted.role, converted.side) == (fabric_kind, role, side)
    (witness,) = converted.witnesses
    assert (witness.producer, witness.source, witness.origins) == ('kb', source, REGISTRY.tags_for(source))


def test_k_keys_are_the_fabric_keys_of_their_values_and_a_pdb_keeps_its_input_hash():
    anchors, document, artifact = k_sample()
    module = convert.from_k_anchor(k_of('module', 'netstack.sys', anchors), batch=KB_BATCH, document=document)
    assert module.key == ids.string_key('netstack.sys')
    assert dict(module.witnesses[0].facets) == {'basis': 'explicit', 'phrase_kind': 'module'}
    api = convert.from_k_anchor(k_of('api', 'RtlULongSub', anchors), batch=KB_BATCH)
    assert api.key == 'rtlulongsub'
    assert dict(api.witnesses[0].facets) == {'basis': 'rule'}
    pdb = convert.from_k_anchor(k_of('pdb', 'netstack.pdb', anchors), batch=KB_BATCH, identity=artifact)
    assert pdb.key == 'pdb=netstack.pdb'
    assert pdb.witnesses[0].input_sha256 == artifact.sha256 == 'c' * 64
    assert dict(pdb.witnesses[0].facets) == {'basis': 'verified-bytes'}


def test_a_quoted_note_string_becomes_a_string_hint_keyed_by_its_hash():
    _, document, _ = k_sample()
    anchor = convert.from_k_anchor(k_quoted(), batch=KB_BATCH, document=document)
    ids.verify_anchor(anchor)
    origins.check_origins(anchor, REGISTRY)
    assert (anchor.kind, anchor.role, anchor.side, anchor.key) == (
        'string', 'hint', 'none', ids.string_key('SYNTHETIC rtl frame'))


def test_a_json_pointer_keeps_its_advisory_reference_and_a_rule_hint_carries_none():
    anchors, document, _ = k_sample()
    note = convert.from_k_anchor(k_note(anchors), batch=KB_BATCH, document=document)
    assert note.witnesses[0].ref == Ref(kind='csaf', id=document.id, pointer=NOTE, sha256=document.sha256)
    api = convert.from_k_anchor(k_of('api', 'memcpy', anchors), batch=KB_BATCH, document=document)
    assert api.witnesses[0].ref is None


def test_every_sample_verifies_and_the_store_accepts_it():
    anchors, document, artifact = k_sample()
    converted = [convert.from_k_anchor(a, batch=KB_BATCH, document=document, identity=artifact)
                 for a in (*anchors, k_quoted())]
    converted += [convert.from_pilot_anchor(PilotAnchor(anchor_id='cwe:CWE-190', kind='cwe',
                                                        label='CWE-190 integer overflow'), batch=PIL_BATCH)]
    for anchor in converted:
        ids.verify_anchor(anchor)
        origins.check_origins(anchor, REGISTRY)
    store = MemoryAnchorStore()
    report = store.publish('synthetic-fab2', converted)
    assert report.added == len({anchor.anchor_id for anchor in converted})
    assert store.find('synthetic-fab2', AnchorQuery()).total == report.added


@pytest.mark.parametrize('case', ['no-document', 'no-identity', 'other-pdb-name', 'pdb-from-text', 'text-from-identity',
                                  'unknown-kind'])
def test_k_refusals_are_typed_and_name_the_missing_piece(case):
    anchors, document, artifact = k_sample()
    note = k_note(anchors)
    pdb = k_of('pdb', 'netstack.pdb', anchors)
    calls = {
        'no-document': lambda: convert.from_k_anchor(note, batch=KB_BATCH),
        'no-identity': lambda: convert.from_k_anchor(pdb, batch=KB_BATCH),
        'other-pdb-name': lambda: convert.from_k_anchor(pdb, batch=KB_BATCH, identity=identity('other.pdb')),
        'pdb-from-text': lambda: convert.from_k_anchor(pdb.model_copy(update={'source': 'csaf-note'}),
                                                       batch=KB_BATCH, identity=artifact),
        'text-from-identity': lambda: convert.from_k_anchor(note.model_copy(update={'source': 'artifact-identity'}),
                                                            batch=KB_BATCH, document=document),
        'unknown-kind': lambda: convert.from_k_anchor(note.model_copy(update={'kind': 'exploit'}), batch=KB_BATCH,
                                                      document=document),
    }
    expected = {'no-document': ('PT-FAB-INPUT', 'document-required'),
                'no-identity': ('PT-FAB-INPUT', 'identity-required'),
                'other-pdb-name': ('PT-FAB-INTEGRITY', 'pdb-name-mismatch'),
                'pdb-from-text': ('PT-FAB-INPUT', 'k-kind-source'),
                'text-from-identity': ('PT-FAB-INPUT', 'k-kind-source'),
                'unknown-kind': ('PT-FAB-INPUT', 'k-kind')}
    err = pytest.raises(FabricError, calls[case]).value
    assert (err.code, err.reason) == expected[case]


# --- PIL samples --------------------------------------------------------------------------------------------

def test_the_pil_candidate_key_is_the_fabric_key_of_its_pair_record():
    assert ids.pair_key_of(PAIR) == f'pair:{CANDIDATE}'


@pytest.mark.parametrize('anchor, pair, fabric_kind, key, side, role, source', [
    (PilotAnchor(anchor_id=f'fn:{CANDIDATE}', kind='function', label='Ipv6pReassembleFragment',
                 facets=(('class', 'fit'),)), PAIR, 'function', f'pair:{CANDIDATE}', 'both', 'observed', 'pairing'),
    (PilotAnchor(anchor_id='api:RtlSizeTAdd', kind='api', label='RtlSizeTAdd'), None, 'import', 'rtlsizetadd', 'none',
     'hint', 'advisory-text'),
    (PilotAnchor(anchor_id=f'str:{ids.string_key(TEXT)}', kind='string', label=TEXT), None, 'string',
     ids.string_key(TEXT), 'none', 'hint', 'advisory-text'),
    (PilotAnchor(anchor_id='cwe:CWE-190', kind='cwe', label='CWE-190 integer overflow'), None, 'cwe', 'CWE-190',
     'none', 'stated', 'advisory-text'),
    (PilotAnchor(anchor_id='cve:CVE-2099-10001', kind='cve', label='SYNTHETIC CVE context'), None, 'cve',
     'CVE-2099-10001', 'none', 'stated', 'advisory-text'),
], ids=['candidate', 'api-wanted', 'string-hash', 'cwe', 'cve'])
def test_each_pil_sample_converts_to_the_planned_anchor_and_verifies(anchor, pair, fabric_kind, key, side, role,
                                                                    source):
    converted = convert.from_pilot_anchor(anchor, batch=PIL_BATCH, pair=pair)
    ids.verify_anchor(converted)
    origins.check_origins(converted, REGISTRY)
    assert (converted.kind, converted.key, converted.side, converted.role) == (fabric_kind, key, side, role)
    (witness,) = converted.witnesses
    assert (witness.producer, witness.source, witness.label) == ('pil', source, anchor.label)
    assert witness.facets == tuple(sorted(anchor.facets))


@pytest.mark.parametrize('anchor, pair, code, reason', [
    (PilotAnchor(anchor_id='rule:patch-R-1@1', kind='rule', label='rule fit'), None, 'PT-FAB-INPUT', 'pil-kind'),
    (PilotAnchor(anchor_id=f'fn:{CANDIDATE}', kind='function', label='candidate'), None, 'PT-FAB-INPUT',
     'pair-required'),
    (PilotAnchor(anchor_id=f'fn:{CANDIDATE}', kind='function', label='candidate'), fs.pair_ref(older=(0x1004,)),
     'PT-FAB-INTEGRITY', 'pair-key-mismatch'),
    (PilotAnchor(anchor_id=f'str:{ids.string_key("other")}', kind='string', label=TEXT), None, 'PT-FAB-INTEGRITY',
     'string-key-mismatch'),
    (PilotAnchor(anchor_id='cwe:CWE-190', kind='api', label='RtlSizeTAdd'), None, 'PT-FAB-INPUT',
     'anchor-id-kind'),
], ids=['rule-kind', 'candidate-without-pair', 'candidate-other-pair', 'string-wrong-hash', 'prefix-mismatch'])
def test_pil_refusals_are_typed(anchor, pair, code, reason):
    err = pytest.raises(FabricError, convert.from_pilot_anchor, anchor, batch=PIL_BATCH, pair=pair).value
    assert (err.code, err.reason) == (code, reason)
