"""SPEC-31 D-30 / 07 s4: the bounded text of a unified row enters the EXISTING context preview as `unified` notes of
`build_context`; nothing else about the context contract moves (a context without notes is byte-identical to today's)."""
from __future__ import annotations

# ruff: noqa: F811  (fixtures imported from a sibling test module are redefined as parameters)
import json

import pytest
from test_interpretation import project, response  # noqa: F401  (fixture and helper of the interpretation tests)

from patchtrace.evidence import EvidenceError, build_context
from patchtrace.interpretation import InterpretationError, validate_context, validate_response

NOTE = ('Unified row 0123456789abcdef', 'older bounds -> newer bounds\nchange: comparison', ('facts: 1 delta not shown',))


def test_a_context_without_notes_is_unchanged_and_has_no_unified_key(project):
    context = build_context(project, ['match'])
    assert 'unified' not in json.loads(context.payload)
    assert build_context(project, ['match'], notes=()) == context


def test_notes_enter_the_payload_the_digest_and_the_omitted_list_and_the_context_validates(project):
    plain = build_context(project, ['match'])
    context = build_context(project, ['match'], notes=[NOTE])
    data = json.loads(context.payload)
    assert data['unified'] == [{'title': NOTE[0], 'text': NOTE[1]}]
    assert context.digest != plain.digest and 'unified: facts: 1 delta not shown' in context.omitted
    assert validate_context(context)['unified'] == data['unified']
    assert validate_response(response(context), context)


def test_notes_are_ordered_and_deterministic(project):
    other = ('Unified row aaaa', 'second', ())
    assert build_context(project, ['match'], notes=[NOTE, other]) == build_context(project, ['match'], notes=[NOTE, other])
    titles = [n['title'] for n in json.loads(build_context(project, ['match'], notes=[NOTE, other]).payload)['unified']]
    assert titles == [NOTE[0], 'Unified row aaaa']


def test_notes_are_bounded_and_a_note_that_does_not_fit_is_listed_as_omitted_not_cut(project):
    big = ('Unified row big', 'x' * 5000, ())
    context = build_context(project, ['match'], max_chars=3000, notes=[big, NOTE])
    data = json.loads(context.payload)
    assert len(context.payload) <= 3000
    assert [n['title'] for n in data.get('unified', [])] == [NOTE[0]]
    assert any('Unified row big' in o and 'context budget' in o for o in context.omitted)
    many = [(f'Unified row {i}', 'text', ()) for i in range(20)]
    assert len(json.loads(build_context(project, ['match'], notes=many).payload)['unified']) == 8
    assert any('additional unified' in o for o in build_context(project, ['match'], notes=many).omitted)


@pytest.mark.parametrize('bad', [('', 'text', ()), ('title', '', ()), ('t' * 201, 'x', ()), ('t', 'x' * 6001, ())],
                         ids=['no-title', 'no-text', 'long-title', 'long-text'])
def test_malformed_notes_are_refused(project, bad):
    with pytest.raises(EvidenceError):
        build_context(project, ['match'], notes=[bad])


def test_a_tampered_unified_section_fails_validation(project):
    context = build_context(project, ['match'], notes=[NOTE])
    data = json.loads(context.payload)
    data['unified'][0]['extra'] = 'x'
    forged = context.model_copy(update={'payload': json.dumps(data, sort_keys=True, separators=(',', ':'))})
    with pytest.raises(InterpretationError):
        validate_context(forged)
