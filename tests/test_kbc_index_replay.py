"""Complete synthetic Winbindex replay; no files, network or target execution."""
from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import replace

import pytest
from kbc_k5_support import SHA, record, scope

from patchtrace.acquisition import winbindex
from patchtrace.kbcorrelation import index_replay as replay
from patchtrace.kbcorrelation import resolver

NAME = 'exampledrv.sys'
DATE = '2099-02-12'


def capture(document=None, *, compressed=False, raw=None):
    plain = json.dumps(record() if document is None else document, indent=2).encode()
    raw = raw if raw is not None else gzip.compress(plain, mtime=17) if compressed else plain
    parsed = winbindex.parse_rows(raw, NAME, DATE, compressed=compressed)
    return replay.CapturedIndex.from_rows(
        raw, file_name=NAME, data_date=DATE, compressed=compressed,
        mappings=[r.as_mapping() for r in parsed.rows],
        skipped=parsed.skipped, skipped_bodies=parsed.skipped_bodies)


def prepared(snapshot=None, *, kb='KB5099001', **kwargs):
    snapshot = snapshot or capture()
    inputs = replay.ResolverInputs(scope=scope(), kb=kb, fixed_build=None, **kwargs)
    result = inputs.resolve(snapshot)
    pair = result.pairs[0]
    manifest = replay.capture_replay(snapshot, inputs, result, pair)
    return snapshot, inputs, result, pair, manifest


@pytest.mark.parametrize('compressed', [False, True])
def test_complete_source_and_exact_resolver_result_replay(compressed):
    snapshot, _inputs, result, pair, manifest = prepared(capture(compressed=compressed))
    assert snapshot.raw == snapshot.raw[:]
    assert manifest.source.sha256 == hashlib.sha256(snapshot.raw).hexdigest()
    assert manifest.source.byte_count == len(snapshot.raw)
    assert manifest.source.compressed is compressed
    assert manifest.source.relative_path == f'kb/winbindex/{manifest.source.sha256}.bin'
    assert manifest.source.workspace_path == f'winbindex-objects/{manifest.source.sha256}.bin'
    assert replay.verify_replay(snapshot, manifest, pair) == result
    assert manifest.parser_skipped == 2 and manifest.parser_skipped_bodies == 1
    assert manifest.conversion_rejected == 0
    assert 'INDEX_GAP' in pair.reason_codes


def test_resolver_retains_original_predecessor_not_any_equal_sha_body():
    snapshot, _inputs, result, pair, manifest = prepared()
    selected = next(m for m in result.memberships if m.pair_id == pair.pair_id)
    assert selected.older.sha256 == SHA['Y']
    assert selected.older.kb == 'KB5098000'
    assert manifest.older.kb == selected.older.kb
    assert manifest.older.source_version_key == selected.older.build.version_key
    assert manifest.older.pointer == f'/{SHA["Y"]}/windowsVersions/11-24H2/KB5098000'
    entry = snapshot.entry_for(manifest.older)
    assert entry.kb == 'KB5098000'
    assert any(row.sha256 == entry.sha256 and row.kb != entry.kb for row in snapshot.mappings)


def test_copied_membership_retains_original_body_key():
    doc = record()
    for entry in doc.values():
        if not isinstance(entry, dict):
            continue
        versions = entry.get('windowsVersions', {})
        if not isinstance(versions, dict) or '11-24H2' not in versions:
            continue
        for body in versions['11-24H2'].values():
            if isinstance(body, dict) and isinstance(body.get('updateInfo'), dict):
                body['updateInfo']['otherWindowsVersions'] = ['11-23H2']
    snapshot = capture(doc)
    inputs = replay.ResolverInputs(scope=scope('11-23H2'), kb='KB5099001', fixed_build=None)
    result = inputs.resolve(snapshot)
    pair = result.pairs[0]
    manifest = replay.capture_replay(snapshot, inputs, result, pair)
    assert manifest.older.version_key == manifest.newer.version_key == '11-23H2'
    assert manifest.older.source_version_key == manifest.newer.source_version_key == '11-24H2'
    assert snapshot.entry_for(manifest.older).version_key == '11-24H2'
    assert replay.verify_replay(snapshot, manifest, pair) == result


@pytest.mark.parametrize('change', ['whitespace', 'irrelevant-entry', 'gzip-header'])
def test_raw_only_source_change_is_not_the_same_replay(change):
    snapshot, _inputs, _result, pair, manifest = prepared(capture(compressed=change == 'gzip-header'))
    if change == 'whitespace':
        changed = capture(raw=snapshot.raw + b'\n')
    elif change == 'irrelevant-entry':
        doc = record()
        doc['not-a-build'] = {'ignored': 'retained original claim'}
        changed = capture(doc)
    else:
        changed = capture(compressed=True, raw=gzip.compress(gzip.decompress(snapshot.raw), mtime=18))
    assert changed.source.sha256 != snapshot.source.sha256
    with pytest.raises(ValueError, match='replay'):
        replay.verify_replay(changed, manifest, pair)


@pytest.mark.parametrize('field,value', [
    ('mapping_sha256', 'f' * 64), ('lineage_sha256', 'f' * 64),
    ('resolution_sha256', 'f' * 64), ('mapping_count', 1), ('lineage_count', 1),
    ('parser_skipped', 0), ('parser_skipped_bodies', 0), ('conversion_rejected', 1),
])
def test_every_retained_input_binding_is_checked(field, value):
    snapshot, _inputs, _result, pair, manifest = prepared()
    altered = manifest.model_copy(update={field: value})
    with pytest.raises(ValueError, match='replay'):
        replay.verify_replay(snapshot, altered, pair)


def test_changed_selected_endpoint_membership_refuses():
    snapshot, _inputs, _result, pair, manifest = prepared()
    altered = manifest.model_copy(update={'older': manifest.older.model_copy(update={'kb': 'KB5097000'})})
    with pytest.raises(ValueError, match='replay'):
        replay.verify_replay(snapshot, altered, pair)


def test_snapshot_owns_copies_of_the_parser_mappings():
    parsed = winbindex.parse_rows(json.dumps(record()).encode(), NAME, DATE, compressed=False)
    mappings = [row.as_mapping() for row in parsed.rows]
    raw = json.dumps(record()).encode()
    snapshot = replay.CapturedIndex.from_rows(raw, file_name=NAME, data_date=DATE, compressed=False,
                                             mappings=mappings, skipped=parsed.skipped,
                                             skipped_bodies=parsed.skipped_bodies)
    before = snapshot.mappings[0]
    mappings[0]['heading'] = 'mutated caller mapping'
    mappings[0]['other_versions'].append('11-99H9')
    assert snapshot.mappings[0] == before
    assert snapshot.mappings[0].heading != 'mutated caller mapping'


def test_replay_does_not_accept_different_retained_bytes_with_same_metadata():
    snapshot, _inputs, _result, pair, manifest = prepared()
    with pytest.raises(ValueError, match='bytes'):
        replay.verify_replay(replace(snapshot, raw=snapshot.raw + b' '), manifest, pair)


def test_snapshot_and_mapping_limits_are_explicit(monkeypatch):
    snapshot = capture()
    monkeypatch.setattr(replay, 'MAX_REPLAY_ROWS', 1)
    with pytest.raises(replay.ReplayLimitError, match='rows'):
        capture()
    monkeypatch.setattr(replay, 'MAX_RAW_BYTES', len(snapshot.raw) - 1)
    with pytest.raises(replay.ReplayLimitError, match='bytes'):
        capture()


def test_potential_copy_expansion_is_bounded_before_lineage_conversion(monkeypatch):
    snapshot = capture()
    rows = [row.model_dump(mode='json') for row in snapshot.mappings]
    rows[0]['other_versions'] = [f'11-copy-{n}' for n in range(30)]
    monkeypatch.setattr(replay, 'MAX_REPLAY_ROWS', len(rows) + 5)
    monkeypatch.setattr(replay, 'index_rows', lambda *args, **kwargs: pytest.fail('unbounded expansion reached lineage'))
    with pytest.raises(replay.ReplayLimitError, match='potential lineage rows'):
        replay.CapturedIndex.from_rows(snapshot.raw, file_name=NAME, data_date=DATE, compressed=False,
                                       mappings=rows, skipped=0, skipped_bodies=0)


def test_unknown_replay_contract_is_not_silently_accepted():
    _snapshot, _inputs, _result, _pair, manifest = prepared()
    body = manifest.model_dump(mode='json')
    body['source']['parser_version'] = 'unknown-parser/2'
    with pytest.raises(ValueError):
        replay.IndexReplay.model_validate_json(json.dumps(body))


@pytest.mark.parametrize('version', [True, False, '1', None])
def test_replay_version_has_no_bool_or_string_coercion(version):
    _snapshot, _inputs, _result, _pair, manifest = prepared()
    body = manifest.model_dump(mode='json')
    body['replay_version'] = version
    with pytest.raises(ValueError):
        replay.IndexReplay.model_validate_json(json.dumps(body))


def test_existing_resolver_pair_values_are_unchanged():
    snapshot, inputs, result, pair, _manifest = prepared()
    directly = resolver.resolve(snapshot.rows, kb=inputs.kb, scope=inputs.scope,
                                file_name=NAME, skipped_rows=snapshot.gap)
    assert directly.pairs == result.pairs
    assert next(m for m in directly.memberships if m.pair_id == pair.pair_id).newer.sha256 == pair.newer.sha256
