"""strings-* contracts: strict, frozen, additive; basis digest and cache keys are stable and orientation-aware."""
from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from patchtrace.strings import contracts as c
from patchtrace.strings import keys

A, B, C = 'a' * 64, 'b' * 64, 'c' * 64


def floss_part(**kw):
    base = dict(source='floss', semantics_id=c.STATIC_SEMANTICS_ID, source_version='3.1.1', run_id='r1',
                raw_sha256=B, types=('static',), config_digest=C)
    return c.BasisPart(**{**base, **kw})


def basis(**kw):
    base = dict(artifact_sha256=A, side='older', min_length=4, rows_seen=3, rows_kept=3,
                stages={'static': c.StageState(state='complete')}, parts=(floss_part(),))
    return c.StringBasis(**{**base, **kw})


def test_basis_is_frozen_and_forbids_extra():
    b = basis()
    with pytest.raises(ValidationError):
        b.min_length = 5
    with pytest.raises(ValidationError):
        c.StringBasis.model_validate({**b.model_dump(mode='json'), 'x': 1})


@pytest.mark.parametrize('kw', [dict(run_id=None), dict(raw_sha256=None)], ids=['no-run', 'no-raw'])
def test_floss_part_must_be_traceable(kw):
    with pytest.raises(ValidationError):
        floss_part(**kw)


def test_builtin_scan_part_has_no_tool_run():
    c.BasisPart(source='builtin-scan', semantics_id=c.STATIC_SEMANTICS_ID, types=('static',), config_digest=C)
    with pytest.raises(ValidationError):
        c.BasisPart(source='builtin-scan', semantics_id=c.STATIC_SEMANTICS_ID, types=('static',), config_digest=C,
                    run_id='r')


def test_basis_rejects_two_parts_of_one_source_and_inconsistent_counts():
    with pytest.raises(ValidationError):
        basis(parts=(floss_part(), floss_part(types=('stack',))))
    with pytest.raises(ValidationError):
        basis(rows_kept=4)


def test_basis_digest_changes_with_orientation_and_settings():
    assert basis().digest() == basis().digest()
    assert basis().digest() != basis(side='newer').digest()
    assert basis().digest() != basis(min_length=6).digest()


def test_orientation_swap_changes_delta_key():
    older, newer = keys.table_key('1' * 64, A), keys.table_key('2' * 64, B)
    pd = keys.pairing_digest('run', B, [])
    assert keys.delta_key(older, newer, pd, None) != keys.delta_key(newer, older, pd, None)
    assert keys.delta_key(older, newer, pd, None) != keys.delta_key(older, newer, pd, C)


def test_table_key_depends_on_basis_and_source():
    k = keys.table_key(A, B)
    assert k == keys.table_key(A, B)
    assert k != keys.table_key(C, B) and k != keys.table_key(A, C)


def obs(**kw):
    return c.SideObservation(types=('static',), encodings=('ASCII',), **kw)


def change(**kw):
    base = dict(id=A, value_sha256=B, display='x', length=1, status='only-newer', newer=obs(), review_tier=5)
    return c.StringChange(**{**base, **kw})


@pytest.mark.parametrize('kw', [dict(older=obs()), dict(newer=None), dict(status='both'),
                                dict(cues=('scary',)), dict(review_tier=0), dict(display='x' * 257)],
                         ids=['wrong-side', 'no-side', 'both-one-side', 'bad-cue', 'tier-0', 'long-display'])
def test_change_rejects_inconsistent_rows(kw):
    with pytest.raises(ValidationError):
        change(**kw)


def test_cue_vocabulary_matches_the_literal():
    assert set(get_args(c.Cue)) == set(c.CUES) and len(c.CUES) == 18


def test_non_comparable_delta_has_no_changes_and_gate_stays_unvalidated():
    with pytest.raises(ValidationError):
        c.StringsDelta(older_basis_digest=A, newer_basis_digest=B, comparable=False, changes=(change(),))
    with pytest.raises(ValidationError):
        c.StringsDelta(older_basis_digest=A, newer_basis_digest=B, comparable=True, value_gate='validated')


def test_anchor_hit_strength_is_fixed_anchor():
    with pytest.raises(ValidationError):
        c.StringAnchorHit(anchor_id='a', kind='k', match='exact', string_id=A, presence_older=True,
                          presence_newer=False, lineage_group='g', strength='confirmed')


def test_strings_error_carries_code():
    err = c.StringsError('PT-STR-STALE', 'run changed')
    assert err.code == 'PT-STR-STALE' and str(err) == 'PT-STR-STALE: run changed'
