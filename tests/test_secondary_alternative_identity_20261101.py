"""Issue #120: an alternative is evidence from exactly one engine and one real candidate endpoint."""
from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError
from unified_s0_fixtures import BASE, alternative, bd, bindiff_set, rz

from patchtrace.secondary.contracts import AlternativeMatch, SecondaryMatchSet
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.sources.secondary import read_loaded


@pytest.mark.parametrize('change', ['source', 'candidate-engine', 'anchor', 'missing-anchor', 'set-engine',
                                  'candidate-version'])
def test_import_rejects_inconsistent_alternative_identity(change):
    correct = alternative('older', 0x1000, bd(0x1000, 0x1100))
    payload = bindiff_set([bd(0x1000, 0x1080)], alternatives=[correct]).model_dump(mode='json')
    alt = payload['alternatives'][0]
    if change == 'source':
        alt['source'] = 'rz-diff'
    elif change == 'candidate-engine':
        alt['candidate'] = rz(0x1000, 0x1100).model_dump(mode='json')
    elif change == 'anchor':
        alt['anchor_address'] = BASE + 0x1777
    elif change == 'missing-anchor':
        alt.update(anchor_side='newer')
        alt['candidate'] = rz(0x1000, None).model_dump(mode='json')
        alt['source'] = 'rz-diff'
    elif change == 'set-engine':
        alt['source'] = 'rz-diff'
        alt['candidate'] = rz(0x1000, 0x1100).model_dump(mode='json')
    else:
        alt['candidate']['engine_version'] = '9.0'
    with pytest.raises(ValidationError):
        SecondaryMatchSet.model_validate_json(json.dumps(payload))


def test_an_alternative_rejects_a_source_and_anchor_that_do_not_describe_its_candidate():
    with pytest.raises(ValidationError):
        AlternativeMatch(anchor_side='older', anchor_address=BASE + 0x1777,
                         candidate=rz(0x1000, 0x1100), source='bindiff', rank=2)


@pytest.mark.parametrize('side,anchor', [('older', 0x1000), ('newer', 0x1100)])
def test_valid_alternatives_keep_the_existing_wire_shape_and_round_trip(side, anchor):
    value = bindiff_set([bd(0x1000, 0x1080)],
                       alternatives=[alternative(side, anchor, bd(0x1000, 0x1100), rank=2)])
    assert SecondaryMatchSet.model_validate_json(value.model_dump_json()) == value
    assert set(value.alternatives[0].model_dump()) == {
        'anchor_side', 'anchor_address', 'candidate', 'source', 'rank'}


def test_worker_snapshot_import_refuses_bad_alternative_without_modifying_source_bytes(tmp_path):
    correct = alternative('older', 0x1000, bd(0x1000, 0x1100))
    value = bindiff_set([bd(0x1000, 0x1080)], alternatives=[correct]).model_dump(mode='json')
    value['alternatives'][0]['anchor_address'] = BASE + 0x1777
    raw = json.dumps({'entry_id': 'original-entry', 'match_set': value}).encode()
    path = tmp_path / 'original.json'
    path.write_bytes(raw)
    with pytest.raises(UnifiedError) as rejected:
        read_loaded(path, expected_sha256=hashlib.sha256(raw).hexdigest(), expected_size=len(raw))
    assert rejected.value.reason == 'secondary-invalid'
    assert path.read_bytes() == raw
