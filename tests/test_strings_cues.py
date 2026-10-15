from __future__ import annotations

import pytest

from patchtrace.strings.cues import CUE_VOCABULARY, MAX_CUES, CueContext, cues_for, secret_kind

GOLDEN = [
    ('index %u exceeds length %u', ('message', 'format')),
    ('bad header (%.64s)', ('message', 'format')),
    ('%s', ('format',)),
    ('100%% done now', ('message',)),
    ('Software\\Vendor\\Product\\Mode', ('registry',)),
    ('HKLM\\SOFTWARE\\Vendor', ('registry',)),
    ('C:\\Windows\\System32\\drivers\\etc\\hosts', ('path',)),
    ('\\\\server\\share\\file.txt', ('path',)),
    ('/usr/lib/libfoo.so', ('path',)),
    ('config\\settings.ini', ('path',)),
    ('https://example.test/a?b=1', ('url',)),
    ('{3F2504E0-4F89-11D3-9A0C-0305E82C3301}', ('guid',)),
    ('ntdll.dll', ('dll-name',)),
    ('C:\\build\\out\\app.pdb', ('path', 'pdb-path')),
    ('10.0.19041.1', ('version',)),
    ('v1.2.3', ('version',)),
    ('g_config_table', ('identifier',)),
    ('ParseHeader', ('identifier',)),
    ('Error', ()),
    ('AKIAIOSFODNN7EXAMPLE', ('secret-like',)),
    ('-----BEGIN RSA PRIVATE KEY-----', ('secret-like',)),
    ('!@#$%^&*()', ('noise-like',)),
    ('AAAAAAAA', ('noise-like',)),
    ('aBcDeFgH', ('noise-like',)),
    ('ab', ()),
]


@pytest.mark.parametrize('text,expected', GOLDEN, ids=[f'g{i}' for i in range(len(GOLDEN))])
def test_golden_cues(text, expected):
    assert cues_for(text) == expected


def test_every_cue_is_in_the_vocabulary():
    samples = [text for text, _ in GOLDEN] + ['plain words are here', 'RtlULongAdd']
    ctx = CueContext(imports={'RtlULongAdd'}, api_hints={'RtlULongAdd'}, region='resource',
                     advisory_phrases=('plain words',))
    for text in samples:
        for flag in (False, True):
            assert set(cues_for(text, ctx, lookalike=flag)) <= set(CUE_VOCABULARY)
            assert len(cues_for(text, ctx, lookalike=flag)) <= MAX_CUES


def test_vocabulary_is_fixed():
    assert len(CUE_VOCABULARY) == 18 and len(set(CUE_VOCABULARY)) == 18


def test_cues_follow_vocabulary_order():
    ctx = CueContext(advisory_phrases=('exceeds length',), region='resource')
    got = cues_for('index %u exceeds length %u', ctx, lookalike=True)
    assert got == ('message', 'format', 'advisory-text', 'lookalike', 'resource')
    assert list(got) == sorted(got, key=CUE_VOCABULARY.index)


def test_api_name_equals_import_or_export():
    assert 'api-name' in cues_for('CreateFileW', CueContext(imports={'CreateFileW'}))
    assert 'api-name' in cues_for('ServiceMain', CueContext(exports={'ServiceMain'}))
    assert 'api-name' not in cues_for('createfilew', CueContext(imports={'CreateFileW'}))


def test_dynamic_api_from_hint_or_other_side_import():
    hint = cues_for('RtlULongAdd', CueContext(api_hints={'RtlULongAdd'}))
    assert 'dynamic-api' in hint and 'advisory-api' in hint and 'api-name' not in hint
    moved = cues_for('LoadLibraryW', CueContext(other_side_imports={'LoadLibraryW'}))
    assert 'dynamic-api' in moved and 'advisory-api' not in moved


def test_dynamic_api_cue_requires_no_own_import():
    ctx = CueContext(imports={'LoadLibraryW'}, other_side_imports={'LoadLibraryW'}, api_hints={'LoadLibraryW'})
    got = cues_for('LoadLibraryW', ctx)
    assert 'dynamic-api' not in got and 'api-name' in got


def test_no_wordlist_means_no_api_cue():
    assert 'api-name' not in cues_for('CreateFileW')
    assert 'dynamic-api' not in cues_for('CreateFileW')


def test_advisory_text_matches_casefolded_phrase():
    ctx = CueContext(advisory_phrases=('index exceeds length',))
    assert 'advisory-text' in cues_for('INDEX EXCEEDS LENGTH', ctx)
    assert 'advisory-text' in cues_for('error: index exceeds length 5', ctx)
    assert 'advisory-text' not in cues_for('index fine', ctx)


def test_short_advisory_phrase_needs_whole_string_match():
    ctx = CueContext(advisory_phrases=('error',))
    assert 'advisory-text' in cues_for('Error', ctx)
    assert 'advisory-text' not in cues_for('an error happened here', ctx)


def test_resource_cue_from_region_only():
    assert 'resource' in cues_for('Open file', CueContext(region='resource'))
    assert 'resource' not in cues_for('Open file', CueContext(region='rdata'))


def test_lookalike_cue_is_caller_supplied():
    assert 'lookalike' not in cues_for('Error')
    assert 'lookalike' in cues_for('Error', lookalike=True)


def test_noise_not_added_to_structural_strings():
    assert 'noise-like' not in cues_for('C:\\a\\b')


@pytest.mark.parametrize('text,kind', [
    ('AKIAIOSFODNN7EXAMPLE', 'aws-access-key'),
    ('token ghp_' + 'a' * 36, 'github-token'),
    ('eyJhbGciOiJI.eyJzdWIiOiIx.c2ln', 'jwt'),
    ('hello world', None),
], ids=['aws', 'github', 'jwt', 'none'])
def test_secret_kind(text, kind):
    assert secret_kind(text) == kind
