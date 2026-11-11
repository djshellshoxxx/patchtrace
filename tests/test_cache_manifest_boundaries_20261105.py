"""Real cache publication/read regressions; all payloads are authored bytes."""
import json

import pytest

from patchtrace.enrichment.cache import CacheConfig, DerivedCache

KEY = 'a' * 64


@pytest.mark.parametrize('field', ['size', 'inputs', 'nested-input'])
def test_duplicate_manifest_fields_are_quarantined(tmp_path, field):
    cache = DerivedCache(CacheConfig(tmp_path))
    assert cache.put('signals', KEY, b'original', {'pair': 'owned'})
    entry = tmp_path / 'v1' / 'signals' / 'aa' / KEY
    path = entry / 'manifest.json'
    original = path.read_bytes()
    # Both a scalar and nested input ownership must have one interpretation.
    extra = b'"size":999,' if field == 'size' else b'"inputs":{"pair":"forged"},'
    damaged = b'{' + extra + original[1:]
    if field == 'nested-input':
        damaged = original.replace(b'"pair":"owned"', b'"pair":"forged","pair":"owned"')
    path.write_bytes(damaged)
    assert cache.get('signals', KEY) is None
    assert not entry.exists()
    quarantined = list((tmp_path / 'v1' / 'quarantine').iterdir())
    assert len(quarantined) == 1
    assert (quarantined[0] / 'payload').read_bytes() == b'original'
    assert (quarantined[0] / 'manifest.json').read_bytes() == damaged
    assert cache.put('signals', KEY, b'replacement', {'pair': 'owned'})
    assert cache.get('signals', KEY) == b'replacement'


def test_unreadable_manifest_not_admitted_or_existing_entry_disturbed(tmp_path):
    cache = DerivedCache(CacheConfig(tmp_path))
    assert cache.put('signals', KEY, b'original', {})
    original = tmp_path / 'v1' / 'signals' / 'aa' / KEY
    saved = (original / 'manifest.json').read_bytes()
    huge_inputs = {'pair': 'x' * (1024 * 1024)}
    assert not cache.put('signals', 'b' * 64, b'new', huge_inputs)
    assert not (tmp_path / 'v1' / 'signals' / 'bb').exists()
    assert cache.get('signals', KEY) == b'original'
    assert (original / 'manifest.json').read_bytes() == saved
    assert json.loads(saved)['inputs'] == {}


@pytest.mark.parametrize('damaged', [b'{"size":NaN}', b'{"size":Infinity}', b'{"created":"\xff"}'])
def test_non_strict_json_is_a_recoverable_miss(tmp_path, damaged):
    cache = DerivedCache(CacheConfig(tmp_path))
    assert cache.put('signals', KEY, b'original', {})
    path = tmp_path / 'v1' / 'signals' / 'aa' / KEY / 'manifest.json'
    path.write_bytes(damaged)
    assert cache.get('signals', KEY) is None
    assert cache.verify()['quarantined'] == 1
    assert cache.put('signals', KEY, b'recovered', {})
    assert cache.get('signals', KEY) == b'recovered'
