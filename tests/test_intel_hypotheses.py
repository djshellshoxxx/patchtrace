"""Patch hypotheses (SPEC-28 section H): CWE-family rules are search guidance, never verification.
Inputs are SYNTHETIC fixtures or literal sentences."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from patchtrace.intelligence import hypotheses as hy
from patchtrace.intelligence import lexicon as lx
from patchtrace.intelligence.contracts import CVEFact, CweRef, HypothesisSet, Note, Rule
from patchtrace.intelligence.csaf import normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
SOURCE = 'b' * 64
BANNED = ('verified', 'proves', 'proven', 'confirmed vulnerab', 'is vulnerable', 'exploitable')


def fact(text: str = '', cwe: str | None = None) -> CVEFact:
    return CVEFact(source_id=SOURCE, cve='CVE-2099-30000', pointer='/vulnerabilities/0',
                   cwe=CweRef(id=cwe, name='synthetic', pointer='/vulnerabilities/0/cwe') if cwe else None,
                   notes=(Note(category='description', text=text, pointer='/vulnerabilities/0/notes/0'),) if text else ())


def build(text: str = '', cwe: str | None = None) -> HypothesisSet:
    return hy.hypotheses_for(lx.classify(fact(text, cwe)))


def test_cwe_787_expects_copy_index_store_plus_guard():
    result = build(cwe='CWE-787')
    (h,) = result.hypotheses
    assert (h.cwe_id, h.family, h.basis, h.assessment) == ('CWE-787', 'memory-write', 'explicit-csaf-cwe',
                                                           'rule-hypothesis')
    text = ' '.join(h.expected_operations + h.guards + h.sinks).lower()
    for word in ('copy', 'index', 'store', 'check'):
        assert word in text
    assert h.counterexamples and 'need not follow' in h.caveat
    assert {'memcpy', 'RtlCopyMemory'} <= set(h.api_hints)


@pytest.mark.parametrize('cwe, family, words', [
    ('CWE-416', 'lifetime', ('reference', 'release')),
    ('CWE-287', 'authentication', ('authentication',)),
    ('CWE-190', 'integer', ('overflow-checked',)),
    ('CWE-476', 'null-deref', ('null',)),
    ('CWE-362', 'race', ('lock',)),
])
def test_family_rules(cwe, family, words):
    (h,) = build(cwe=cwe).hypotheses
    assert h.family == family
    blob = ' '.join(h.expected_operations + h.guards).lower()
    assert all(word in blob for word in words), blob


def test_explicit_and_derived_cwes_give_one_hypothesis_per_rule_in_stable_order():
    raw = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc, report = validate.load_document(raw)
    facts = normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())
    result = hy.hypotheses_for(lx.classify(facts.vulnerability('CVE-2099-10001')))
    assert [(h.cwe_id, h.basis) for h in result.hypotheses] == [('CWE-191', 'explicit-csaf-cwe'),
                                                               ('CWE-122', 'curated-vocabulary')]
    assert result == hy.hypotheses_for(lx.classify(facts.vulnerability('CVE-2099-10001')))
    assert len({h.hypothesis_id for h in result.hypotheses}) == 2


def test_missing_or_vague_cwe_gives_explicit_unknown():
    for result in (build(), build('A vulnerability could allow remote code execution.')):
        assert result.hypotheses == ()
        assert result.unknowns and 'no expected patch motif' in result.unknowns[0]


def test_weak_matches_are_not_used():
    result = build('A memory corruption vulnerability exists.')
    assert result.hypotheses == () and any('weak' in u for u in result.unknowns)


def test_unmapped_cwe_is_an_unknown_not_a_guess():
    result = build(cwe='CWE-1021')
    assert result.hypotheses == () and any('CWE-1021' in u and 'no curated rule' in u for u in result.unknowns)


def test_rules_are_valid_versioned_and_cover_every_family():
    assert {rule.family for rule in hy.RULES} == set(lx.FAMILIES)
    for rule in hy.RULES:
        assert isinstance(rule, Rule) and rule.revision >= 1 and rule.counterexamples
        assert all(lx.family(c) == rule.family for c in rule.cwe_patterns)
    assert hy.rules_digest() == hy.rules_digest() and len(hy.rules_digest()) == 64
    assert json.loads(hy.RULES[0].model_dump_json())['contract'] == 'intelligence/1'


def test_no_rule_text_claims_verification():
    for rule in hy.RULES:
        blob = rule.model_dump_json().lower()
        assert not any(word in blob for word in BANNED), (rule.id, blob)
