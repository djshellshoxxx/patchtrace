"""Resolver-window provenance for consented acquisition; synthetic index rows only."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from patchtrace.kbcorrelation.acquire import row_for, target_row_membership
from patchtrace.kbcorrelation.store import KbcStoreError

SHA = 'a' * 64
NAME = 'afd.sys'
KEY = '10-22H2'
KB = 'KB5030500'


def row(*, version=KEY, kb=None, other=(), label=''):
    return {'sha256': SHA, 'file_name': NAME, 'version_key': version,
            'kb': kb, 'other_versions': list(other), 'heading': label}


def test_original_sha_only_selection_could_bind_base_instead_of_target_kb():
    entries = [row(label='unrelated BASE'), row(kb=KB, label='selected KB update')]
    assert row_for(entries, SHA, NAME)['kb'] is None  # retained original compatibility seam
    target = target_row_membership(SimpleNamespace(window_id=f'index:{KEY}:{KB}'))
    assert row_for(entries, SHA, NAME, target=target)['kb'] == KB


def test_other_version_membership_is_eligible_when_exact_key_is_absent():
    copied = row(version='10-21H2', kb=KB, other=[KEY], label='copied body')
    assert row_for([copied], SHA, NAME, target=(KEY, KB)) is copied


def test_native_body_wins_over_shared_body_even_if_shared_was_first():
    copied = row(version='10-21H2', kb=KB, other=[KEY], label='copied body')
    own = row(kb=KB, label='own body')
    assert row_for([copied, own], SHA, NAME, target=(KEY, KB)) is own


def test_other_version_without_explicit_membership_is_not_used():
    entries = [row(version='10-21H2', kb=KB, other=['10-20H2'])]
    with pytest.raises(KbcStoreError) as exc:
        row_for(entries, SHA, NAME, target=(KEY, KB))
    assert exc.value.code == 'PT-KBC-INPUT'


def test_missing_target_kb_refuses_arbitrary_same_sha_body():
    entries = [row(), row(kb='KB5030200')]
    with pytest.raises(KbcStoreError) as exc:
        row_for(entries, SHA, NAME, target=(KEY, KB))
    assert exc.value.code == 'PT-KBC-INPUT'


@pytest.mark.parametrize('anchor', ['manual', 'index:', 'index::KB5030500',
                                     'index:10-22H2:', 'index:10-22H2:KB5030500:tail'])
def test_non_index_or_malformed_window_refused(anchor):
    with pytest.raises(KbcStoreError) as exc:
        target_row_membership(SimpleNamespace(window_id=anchor))
    assert exc.value.code == 'PT-KBC-INPUT'


def test_base_anchor_matches_only_base_body():
    entries = [row(kb=KB), row(label='BASE body')]
    target = target_row_membership(SimpleNamespace(window_id=f'index:{KEY}:BASE'))
    assert target == (KEY, None)
    assert row_for(entries, SHA, NAME, target=target)['kb'] is None


def test_wrong_sha_or_basename_cannot_supply_selected_body():
    unrelated = {**row(kb=KB), 'sha256': 'b' * 64}
    with pytest.raises(KbcStoreError) as exc:
        row_for([unrelated], SHA, NAME, target=(KEY, KB))
    assert exc.value.code == 'PT-KBC-INPUT'
