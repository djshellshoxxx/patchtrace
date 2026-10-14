"""KB integration plan A-10: `text_anchors()` is the public text-to-anchor rule set (SPEC-28 section H) and
`Anchor.source` gains the additive CVRF values `cvrf-title`, `cvrf-note`, `cvrf-tag`.
SYNTHETIC text and fixtures only."""
from __future__ import annotations

import hashlib
import typing
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.intelligence import anchors as an
from patchtrace.intelligence.contracts import Anchor, AnchorSet
from patchtrace.intelligence.csaf import normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
POINTER = '/Vulnerability/0/Notes/2/Value'
TEXT = ('Affects netstack.sys and NETSTACK.SYS in IPv6, see <b>evil.dll</b> <script>x()</script> '
        'and "Quoted UI text".')


def test_anchor_source_gains_the_cvrf_values_additively():
    sources = typing.get_args(Anchor.model_fields['source'].annotation)
    # The six earlier values keep their order; the three new ones are appended.
    assert sources == ('csaf-title', 'csaf-note', 'csaf-product', 'csaf-remediation', 'hypothesis-rule',
                       'artifact-identity', 'cvrf-title', 'cvrf-note', 'cvrf-tag')
    assert set(an.TEXT_SOURCES) == {'csaf-title', 'csaf-note', 'csaf-product', 'csaf-remediation',
                                    'cvrf-title', 'cvrf-note', 'cvrf-tag'}


def test_text_anchors_is_the_rule_set_anchors_for_applies_to_csaf_text():
    raw = (FIXTURES / 'synthetic-advisory-rev1.json').read_bytes()
    doc, report = validate.load_document(raw)
    facts = normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())
    note = facts.vulnerability('CVE-2099-10001').notes[0]
    derived = [a for a in an.anchors_for('CVE-2099-10001', [facts]).anchors
               if a.source == 'csaf-note' and a.pointer == note.pointer]
    assert derived and an.text_anchors(note.text, 'csaf-note', note.pointer) == tuple(derived)


@pytest.mark.parametrize('source', ['cvrf-title', 'cvrf-note', 'cvrf-tag'], ids=['title', 'note', 'tag'])
def test_cvrf_text_yields_labelled_search_hints(source):
    found = an.text_anchors(TEXT, source, POINTER)
    pairs = {(a.kind, a.value) for a in found}
    assert {('module', 'netstack.sys'), ('module', 'evil.dll'), ('feature', 'IPv6')} <= pairs
    # Quoted text becomes a string hint in notes only, exactly as for CSAF notes.
    assert (('string', 'Quoted UI text') in pairs) == (source == 'cvrf-note')
    assert all(a.source == source and a.pointer == POINTER and a.assessment == 'search-hint' for a in found)
    assert not any('<' in a.value or '>' in a.value or 'script' in a.value for a in found)  # no markup
    dumped = AnchorSet(cve='CVE-2099-10001', anchors=found).model_dump_json()
    assert AnchorSet.model_validate_json(dumped).anchors == found


def test_text_anchors_are_deduplicated_canonically_ordered_and_repeatable():
    found = an.text_anchors(TEXT, 'cvrf-note', POINTER)
    keys = [(a.kind, a.value, a.source, a.pointer or '') for a in found]
    assert keys == sorted(keys) and len(set(keys)) == len(keys)
    assert found == an.text_anchors(TEXT, 'cvrf-note', POINTER)
    modules = [a.value for a in found if a.kind == 'module']
    assert modules == ['evil.dll', 'netstack.sys']  # NETSTACK.SYS folds into the one netstack.sys anchor


@pytest.mark.parametrize('source', ['hypothesis-rule', 'artifact-identity', 'bogus'],
                         ids=['rule', 'ident', 'bogus'])
def test_text_anchors_refuses_sources_that_are_not_advisory_text(source):
    with pytest.raises(ValueError, match='text anchor source'):
        an.text_anchors(TEXT, source, POINTER)


def test_text_anchors_requires_a_valid_provenance_pointer():
    with pytest.raises(ValidationError):
        an.text_anchors(TEXT, 'cvrf-title', 'Vulnerability/0/Title')
