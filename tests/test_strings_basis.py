"""WB3-S5 basis rules (spec WB3 s7.1): which types two tables may be compared on."""
from __future__ import annotations

import pytest

from patchtrace.strings import contracts as c
from patchtrace.strings.basis import compare_bases

EXE = 'a' * 64
CONSENT = 'b' * 64


def part(source='builtin-scan', types=('static',), *, exe=None, consent=None, semantics=c.STATIC_SEMANTICS_ID):
    extra = {'run_id': 'run-1', 'raw_sha256': 'e' * 64} if source == 'floss' else {}
    return c.BasisPart(source=source, semantics_id=semantics, types=types, config_digest='c' * 64,
                       executable_sha256=exe, consent_sha256=consent, **extra)


def basis(side, *, parts=None, min_length=4, stages=None, language=None):
    parts = parts or (part(),)
    names = [t for p in parts for t in p.types]
    states = stages if stages is not None else {t: c.StageState(state='heuristic' if t in ('stack', 'tight', 'decoded')
                                                                else 'complete') for t in names}
    return c.StringBasis(artifact_sha256='1' * 64, side=side, min_length=min_length, rows_seen=0, rows_kept=0,
                         stages=states, parts=parts, language=language or c.LanguageInfo())


def floss_parts(types, *, exe=EXE, consent=CONSENT):
    return (part('floss', types, exe=exe, consent=consent),)


def test_equal_bases_compare_on_their_types():
    verdict = compare_bases(basis('older'), basis('newer'))
    assert verdict.comparable and verdict.harmonized.types == ('static',) and verdict.notes == ()


def test_min_length_harmonizes_to_the_larger_value():
    verdict = compare_bases(basis('older', min_length=4), basis('newer', min_length=6))
    assert verdict.harmonized.min_length == 6 and any('4 and 6' in n for n in verdict.notes)


def test_different_semantics_block_with_a_reason():
    verdict = compare_bases(basis('older'), basis('newer', parts=(part(semantics='other/v2'),)))
    assert not verdict.comparable and verdict.harmonized is None and verdict.block_reasons


def test_builtin_against_floss_compares_static_and_shows_both_sources():
    verdict = compare_bases(basis('older'), basis('newer', parts=floss_parts(('static',))))
    assert verdict.comparable and verdict.compared == {'static'}
    assert any('different sources' in n for n in verdict.notes)


def test_emulation_on_one_side_only_is_not_compared():
    verdict = compare_bases(basis('older', parts=floss_parts(('static',))),
                            basis('newer', parts=floss_parts(('static', 'decoded'))))
    assert verdict.compared == {'static'} and verdict.not_compared == {'decoded'}


@pytest.mark.parametrize('newer_exe, newer_consent, compared', [
    (EXE, CONSENT, {'static', 'decoded'}),
    (EXE, 'd' * 64, {'static'}),
    ('f' * 64, CONSENT, {'static'}),
    (None, CONSENT, {'static'}),
], ids=['same', 'consent', 'executable', 'unknown-exe'])
def test_emulation_needs_the_same_executable_and_consent(newer_exe, newer_consent, compared):
    types = ('static', 'decoded')
    verdict = compare_bases(basis('older', parts=floss_parts(types)),
                            basis('newer', parts=floss_parts(types, exe=newer_exe, consent=newer_consent)))
    assert verdict.compared == compared


def test_language_needs_the_same_detected_language():
    types = ('static', 'language')
    a = basis('older', parts=floss_parts(types), language=c.LanguageInfo(detected='go'))
    b = basis('newer', parts=floss_parts(types), language=c.LanguageInfo(detected='rust'))
    assert compare_bases(a, b).compared == {'static'}


@pytest.mark.parametrize('state, bucket', [('truncated', 'indeterminate'), ('failed', 'indeterminate'),
                                           ('not-run', 'not_compared')], ids=['truncated', 'failed', 'not-run'])
def test_incomplete_stage_is_indeterminate_or_not_compared(state, bucket):
    older = basis('older', stages={'static': c.StageState(state='complete')})
    newer = basis('newer', stages={'static': c.StageState(state=state)})
    verdict = compare_bases(older, newer)
    if bucket == 'indeterminate':
        assert verdict.comparable and verdict.indeterminate == {'static'} and not verdict.compared
    else:
        assert not verdict.comparable  # nothing left to compare


def test_no_shared_type_blocks():
    verdict = compare_bases(basis('older', parts=floss_parts(('stack',))), basis('newer', parts=floss_parts(('decoded',))))
    assert not verdict.comparable and verdict.block_reasons


def test_swapped_orientation_is_stale():
    with pytest.raises(c.StringsError) as raised:
        compare_bases(basis('newer'), basis('older'))
    assert raised.value.code == 'PT-STR-STALE'
