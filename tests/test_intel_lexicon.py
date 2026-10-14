"""CWE lexicon (SPEC-28 section H): explicit CWE first, curated vocabulary second, negation and vagueness.
Inputs are SYNTHETIC fixtures or literal sentences written for these tests."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from patchtrace.intelligence import lexicon as lx
from patchtrace.intelligence.contracts import CVEFact, CweProfile, Note
from patchtrace.intelligence.csaf import normalize, validate

FIXTURES = Path(__file__).parent / 'fixtures' / 'csaf'
SOURCE = 'a' * 64


def facts(name='synthetic-advisory-rev1.json'):
    raw = (FIXTURES / name).read_bytes()
    doc, report = validate.load_document(raw)
    return normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())


def item(text: str, *, title: str | None = None, cwe=None, category: str = 'description') -> CVEFact:
    return CVEFact(source_id=SOURCE, cve='CVE-2099-20000', pointer='/vulnerabilities/0', title=title, cwe=cwe,
                   notes=(Note(category=category, text=text, pointer='/vulnerabilities/0/notes/0'),))


def profile(text: str, **kw) -> CweProfile:
    return lx.classify(item(text, **kw))


def cwes(p: CweProfile, confidence: str | None = None) -> set[str]:
    return {c.cwe_id for c in p.classifications if confidence is None or c.confidence == confidence}


def test_explicit_cwe_comes_first_and_vocabulary_second():
    p = lx.classify(facts().vulnerability('CVE-2099-10001'))
    assert p.status == 'explicit'
    explicit = next(c for c in p.classifications if c.basis == 'explicit-csaf-cwe')
    assert (explicit.cwe_id, explicit.confidence, explicit.assessment) == ('CWE-191', 'explicit', 'advisory-claim')
    assert explicit.pointers == ('/vulnerabilities/0/cwe', '/vulnerabilities/0/notes/0')  # claim + support
    assert any(h.term_id == 'integer-underflow' for h in explicit.hits)  # supporting text merged, not duplicated
    heap = next(c for c in p.classifications if c.cwe_id == 'CWE-122')
    assert (heap.basis, heap.confidence, heap.assessment) == ('curated-vocabulary', 'phrase-match', 'rule-hypothesis')
    assert p.disagreements and 'CWE-191' in p.disagreements[0] and 'CWE-122' in p.disagreements[0]


def test_missing_cwe_is_derived_from_vocabulary_and_negated_effect_is_excluded():
    p = lx.classify(facts().vulnerability('CVE-2099-10002'))
    assert p.status == 'derived' and cwes(p) == {'CWE-416'}
    assert {h.phrase for h in p.negated_hits} == {'remote code execution'}
    assert next(h for h in p.negated_hits).negation_cue == 'not'
    assert {h.phrase for h in p.effect_hits} == {'elevation of privilege'}  # from the title, not negated


@pytest.mark.parametrize('text', [
    'The update does not allow a heap overflow.',
    'This is a race condition, not a use-after-free.',
    'A buffer overflow is not possible in this code path.',
    'Heap corruption cannot occur here.',
    'The driver is free of buffer overflows.',
    'No use after free exists in the fixed build.',
])
def test_negated_weakness_phrases_never_classify(text):
    p = profile(text)
    assert not any(c.basis == 'curated-vocabulary' and c.cwe_id in {'CWE-122', 'CWE-416', 'CWE-787', 'CWE-119'}
                   for c in p.classifications), p
    assert p.negated_hits


@pytest.mark.parametrize('text, expected', [
    ('An attacker who does not have privileges could trigger a heap overflow.', 'CWE-122'),
    ('The parser does not properly validate the length, leading to an out-of-bounds write.', 'CWE-787'),
    ('A use-after-free that does not require user interaction exists in the service.', 'CWE-416'),
])
def test_negation_scope_ends_at_clause_and_distance(text, expected):
    assert expected in cwes(profile(text), 'phrase-match')


@pytest.mark.parametrize('text', [
    'The service may use after freeing the request object.',  # "freeing" is not "free"
    'The value overflowed its container label.',  # "overflowed" is not "overflow"; no CWE noun phrase
    'Shared reuse-after-freeze semantics.',
])
def test_word_boundaries(text):
    assert not cwes(profile(text), 'phrase-match')


def test_hyphen_space_markup_entities_and_fullwidth_text_match():
    assert cwes(profile('a <b>use</b>-after-free'), 'phrase-match') == {'CWE-416'}
    assert cwes(profile('a use&#8209;after&#8209;free condition'), 'phrase-match') == {'CWE-416'}
    assert cwes(profile('ｕｓｅ ａｆｔｅｒ ｆｒｅｅ'),
                'phrase-match') == {'CWE-416'}
    assert cwes(profile('An Out-Of-Bounds Read in **parse_header**'), 'phrase-match') == {'CWE-125'}


@pytest.mark.parametrize('text, status', [
    ('A vulnerability exists that could allow remote code execution.', 'vague'),
    ('Microsoft is aware of this issue. Customers should install the update.', 'vague'),
    ('A memory corruption vulnerability exists in the driver.', 'weak'),
    ('An improper input validation vulnerability exists.', 'weak'),
])
def test_vague_text_is_never_classified_confidently(text, status):
    p = profile(text)
    assert p.status == status
    assert not [c for c in p.classifications if c.confidence != 'weak']


def test_cwe_ids_written_in_text_are_advisory_claims_and_negatable():
    p = profile('This weakness is tracked as CWE-787 by the vendor.')
    claim = next(c for c in p.classifications if c.cwe_id == 'CWE-787')
    assert (claim.basis, claim.assessment, claim.confidence) == ('cwe-id-in-text', 'advisory-claim', 'phrase-match')
    assert 'CWE-787' not in cwes(profile('This is not CWE-787.'))


def test_legal_disclaimers_are_not_classified_and_empty_items_are_none():
    p = profile('Nothing here is a buffer overflow or a use after free claim.', category='legal_disclaimer')
    assert p.status == 'none' and p.classifications == ()
    empty = CVEFact(source_id=SOURCE, cve='CVE-2099-20000', pointer='/vulnerabilities/0')
    assert lx.classify(empty).status == 'none'


def test_long_text_is_capped_and_recorded():
    text = 'x ' * 40_000 + 'use after free'
    p = profile(text)
    assert 'CWE-416' not in cwes(p)
    assert p.limitations and '65536' in p.limitations[0]


def test_hits_carry_pointer_and_bounded_excerpt():
    p = profile('First sentence. ' + 'A heap-based buffer overflow occurs when ' + 'y' * 400 + '.')
    hit = next(h for c in p.classifications for h in c.hits)
    assert hit.pointer == '/vulnerabilities/0/notes/0' and len(hit.excerpt) <= 300
    assert 'heap' in hit.excerpt.lower()


def test_lexicon_is_versioned_and_deterministic():
    first = lx.classify(facts().vulnerability('CVE-2099-10001'))
    second = lx.classify(facts().vulnerability('CVE-2099-10001'))
    assert first == second and first.lexicon_version == lx.LEXICON_VERSION == 'cwe-lexicon/1'
    assert first.lexicon_digest == lx.lexicon_digest() and len(first.lexicon_digest) == 64


def test_every_term_maps_to_known_families():
    for term in lx.TERMS:
        assert term.phrases and term.scope in {'weakness', 'effect', 'component', 'primitive'}
        if term.scope == 'weakness':
            assert term.cwe_ids and all(lx.family(c) for c in term.cwe_ids), term
        else:
            assert not term.cwe_ids, term
    assert lx.family('CWE-787') == 'memory-write' and lx.family('CWE-416') == 'lifetime'
    assert lx.family('CWE-1021') is None


# ---- audit C-07: a cue that follows the phrase negates the weakness only as a predicate of its existence ---------

@pytest.mark.parametrize('text, expected', [
    ('Heap-based buffer overflow requires no user interaction.', 'CWE-122'),
    ('A heap-based buffer overflow without authentication allows code execution.', 'CWE-122'),
    ('The heap overflow does not require user interaction.', 'CWE-122'),
    ("The use after free doesn't require any privileges.", 'CWE-416'),
    ('This stack buffer overflow does not need valid credentials.', 'CWE-121'),
    ('The integer overflow does not allow remote code execution.', 'CWE-190'),
    ('The heap overflow never requires authentication.', 'CWE-122'),
    ('The double free has not been fixed in older builds.', 'CWE-415'),
], ids=['requires-no', 'without', 'does-not-require', 'doesnt-require', 'does-not-need', 'does-not-allow',
        'never-requires', 'not-been-fixed'])
def test_c07_negated_requirements_and_capabilities_leave_the_weakness_standing(text, expected):
    p = profile(text)
    assert expected in cwes(p, 'phrase-match'), p
    assert all(hit.scope != 'weakness' for hit in p.negated_hits), p


@pytest.mark.parametrize('text, cue', [
    ('The heap overflow does not occur in the fixed build.', 'not'),
    ('A buffer overflow is not present in this version.', 'not'),
    ('A buffer overflow is no longer possible after the update.', 'no longer'),
    ('The use after free cannot occur on this path.', 'cannot'),
    ('A double free never occurs on this path.', 'never'),
    ("The heap overflow isn't present.", "isn't"),
    ('Out of bounds write could not be reproduced.', 'not'),
    ('A heap overflow is impossible here.', 'impossible'),
], ids=['does-not-occur', 'is-not-present', 'no-longer', 'cannot-occur', 'never-occurs', 'isnt', 'could-not',
        'impossible'])
def test_c07_existence_negations_after_the_phrase_still_negate(text, cue):
    p = profile(text)
    assert not any(c.basis == 'curated-vocabulary' for c in p.classifications), p
    assert {hit.negation_cue for hit in p.negated_hits if hit.scope == 'weakness'} == {cue}, p


# ---- additive terms for the two weakness classes of the known-answer corpus that had none ------------------------

@pytest.mark.parametrize('text, cwe, family', [
    ('A format string vulnerability in the logging routine lets a peer read the stack.', 'CWE-134', 'format-string'),
    ('Use of Externally-Controlled Format String in the diagnostics service.', 'CWE-134', 'format-string'),
    ('The service passes an uncontrolled format string to the formatter.', 'CWE-134', 'format-string'),
    ('An off-by-one error in the name length check allows a one byte overwrite.', 'CWE-193', 'off-by-one'),
    ('The loop contains an off by one bug at the table bound.', 'CWE-193', 'off-by-one'),
], ids=['format-string-vulnerability', 'cwe-title', 'uncontrolled', 'off-by-one-error', 'off-by-one-bug'])
def test_format_string_and_off_by_one_are_confident_vocabulary_matches(text, cwe, family):
    p = profile(text)
    assert cwe in cwes(p, 'phrase-match'), p
    classification = next(c for c in p.classifications if c.cwe_id == cwe)
    assert (classification.family, classification.basis, classification.assessment) == (
        family, 'curated-vocabulary', 'rule-hypothesis')
    assert lx.family(cwe) == family and lx.CWE_NAMES[cwe]


@pytest.mark.parametrize('text, cwe', [
    ('The routine builds a format string from the request buffer.', 'CWE-134'),
    ('An off-by-one in the length check.', 'CWE-193'),
], ids=['bare-format-string', 'bare-off-by-one'])
def test_bare_phrases_are_weak_and_never_confident(text, cwe):
    p = profile(text)
    assert cwes(p, 'weak') == {cwe} and not cwes(p, 'phrase-match') and p.status == 'weak', p


def test_ordinary_english_and_negations_do_not_classify_the_new_classes():
    assert not cwes(profile('The setting can be switched off by one of the administrators.'), 'phrase-match')
    assert not cwes(profile('There is no format string vulnerability in this code path.'))
    assert not cwes(profile('An off-by-one error is not present in the fixed build.'))
