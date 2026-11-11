"""A display order is not consent to select a binary pair; dates cannot crash revision selection."""
from types import SimpleNamespace

import pytest
from kbc_k3_support import FixedClock, write_pair

from patchtrace.kbcorrelation import index
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.sources.cvrf import normal_timestamp
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import build_service
from patchtrace.sample import synthetic_pe


def pair(key, grade='A'):
    return SimpleNamespace(pair_id=key * 64, grade=grade)


def candidates(*pairs):
    return [SimpleNamespace(pairs=pairs)]


@pytest.mark.parametrize('reverse', [False, True])
def test_ambiguous_viable_pairs_require_explicit_selection(reverse):
    rows = [pair('a'), pair('b')]
    if reverse:
        rows.reverse()
    with pytest.raises(KbcStoreError, match='select one with --pair') as caught:
        KbService._pick_pair(candidates(*rows), None)
    assert caught.value.code == 'PT-KBC-INPUT'
    assert KbService._pick_pair(candidates(*rows), 'a' * 8).pair_id == 'a' * 64


def test_duplicate_observations_and_blocked_pairs_do_not_create_false_ambiguity():
    selected = pair('a')
    assert KbService._pick_pair(candidates(selected, selected, pair('b', 'X')), None) is selected
    assert KbService._pick_pair(candidates(pair('b', 'X')), None) is None


@pytest.mark.parametrize('value', ['0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00'])
def test_release_dates_with_unrepresentable_utc_instants_are_rejected_and_legacy_rows_are_safe(value):
    assert normal_timestamp(value) is None
    assert index._instant(value) == index._instant(None)


def test_valid_offset_timestamp_keeps_original_text_and_compares_by_instant():
    value = '2099-02-01T00:30:00+01:00'
    assert normal_timestamp(value) == value
    assert index._instant(value) == index._instant('2099-01-31T23:30:00Z')


def test_local_pair_approval_is_bound_to_previewed_content(tmp_path):
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    old, new = write_pair(tmp_path / 'inputs')
    destination = tmp_path / 'project'
    preview = service.import_pair('new', str(old), str(new), str(destination), dry_run=True)
    expected = preview.result['pair']['pair_id']
    new.write_bytes(synthetic_pe(2))
    with pytest.raises(KbcStoreError, match='changed after preview') as caught:
        service.import_pair('new', str(old), str(new), str(destination), expected_pair_id=expected)
    assert caught.value.code == 'PT-KBC-STALE'
    assert not destination.exists()
    new.write_bytes(synthetic_pe(1))
    result = service.import_pair('new', str(old), str(new), str(destination), expected_pair_id=expected)
    assert result.exit == 0
    assert result.result['pair']['pair_id'] == expected
