"""Provider display labels cannot carry terminal controls or merge source provenance."""
import hashlib
import json

from patchtrace.acquisition import winbindex


def entry(sha, windows):
    return {'fileInfo': {'sha256': sha, 'size': 1024, 'machineType': 34404,
                         'timestamp': 1, 'virtualSize': 4096}, 'windowsVersions': windows}


def test_version_labels_cleaned_but_raw_record_authority_preserved():
    sha = 'a' * 64
    body = entry(sha, {'11\n\u202eSpoof': {}, 'z' * 1000: {}})
    raw = json.dumps({sha: body}).encode()
    result = winbindex.parse(raw, 'demo.dll', '2026-11-05', compressed=False)
    candidate, = result.candidates
    assert candidate.windows_versions == ('11  Spoof', 'z' * 64)
    canonical = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    assert candidate.record_sha256 == hashlib.sha256(canonical).hexdigest()
    assert json.loads(raw)[sha]['windowsVersions'] == body['windowsVersions']


def test_display_collision_reported_without_collapsing_candidates_or_kb_refs():
    names = ['a' * 64 + '1', 'a' * 64 + '2']
    windows = {names[0]: {'KB1111111': {}}, names[1]: {'KB2222222': {}}}
    bodies = {sha: entry(sha, windows) for sha in ('a' * 64, 'b' * 64)}
    raw = json.dumps(bodies).encode()
    result = winbindex.parse(raw, 'demo.dll', '2026-11-05', compressed=False)
    assert len(result.candidates) == 2 and result.skipped == 0
    assert any('2 Windows version display label collisions' in w for w in result.warnings)
    for candidate in result.candidates:
        assert candidate.windows_versions == ('a' * 64,)
        assert {ref.kb for ref in candidate.kbs} == {'KB1111111', 'KB2222222'}
        canonical = json.dumps(bodies[candidate.sha256], sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False).encode()
        assert candidate.record_sha256 == hashlib.sha256(canonical).hexdigest()
    assert len({c.record_sha256 for c in result.candidates}) == 2
