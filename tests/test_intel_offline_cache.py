"""Offline CSAF cache index (random audit 1, RA-4): an index file that cannot be read is never rewritten, and the URL
index is sharded so that no file grows with the whole cache. No network: the transport gets a fake opener."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as tr

BASE = 'https://msrc.microsoft.com/csaf/advisories/2099'


def url_of(i: int) -> str:
    return f'{BASE}/pt-synth_cve-2099-{i:05d}.json'


def fetched(url: str, body: bytes = b'{"doc": 1}') -> tr.Fetched:
    return tr.Fetched(url, url, body, hashlib.sha256(body).hexdigest(), '2099-03-01T00:00:00Z')


def shard_path(root, url: str):
    """The documented layout: urls/<first byte of the SHA-256 of the URL, as hex>.json."""
    return root / 'urls' / (hashlib.sha256(url.encode('utf-8')).hexdigest()[:2] + '.json')


def colliding_urls(root, count: int) -> list[str]:
    first, found, i = shard_path(root, url_of(0)), [url_of(0)], 1
    while len(found) < count:
        if shard_path(root, url_of(i)) == first:
            found.append(url_of(i))
        i += 1
    return found


def write_legacy_index(root, entries: dict[str, bytes]) -> bytes:
    """An index as the first version wrote it: one urls.json next to bodies/ (indent 1, sorted keys)."""
    (root / 'bodies').mkdir(parents=True, exist_ok=True)
    index = {}
    for url, body in entries.items():
        sha = hashlib.sha256(body).hexdigest()
        (root / 'bodies' / sha).write_bytes(body)
        index[url] = {'sha256': sha, 'retrieved_at': '2099-01-01T00:00:00Z', 'final_url': url}
    raw = json.dumps(index, sort_keys=True, indent=1).encode('utf-8')
    (root / 'urls.json').write_bytes(raw)
    return raw


UNREADABLE = {
    'garbage': b'{not json', 'array': b'[]', 'binary': b'\xff\xfe\x00', 'nested': b'[' * 100_000,
    'over-cap': b'{"k": "' + b'v' * tr.OfflineCache.MAX_MAP_BYTES + b'"}',
}


@pytest.mark.parametrize('raw', UNREADABLE.values(), ids=list(UNREADABLE))
def test_an_unreadable_index_file_is_never_rewritten(tmp_path, raw):
    shard = shard_path(tmp_path, url_of(1))
    shard.parent.mkdir()
    shard.write_bytes(raw)
    with pytest.raises(IntelError) as info:
        tr.OfflineCache(tmp_path).put(fetched(url_of(1)))
    assert info.value.code == 'PT-INTEL-CONFIG'
    assert shard.read_bytes() == raw and not (tmp_path / 'bodies').exists()  # refused before anything was stored


def test_the_index_outgrows_one_files_cap_without_losing_entries(tmp_path, monkeypatch):
    """RA-4: one urls.json over the read cap read back as {} and the next put() rewrote it with a single entry."""
    monkeypatch.setattr(tr.OfflineCache, 'MAX_MAP_BYTES', 4096)
    cache = tr.OfflineCache(tmp_path)
    for i in range(60):
        cache.put(fetched(url_of(i), b'body %d' % i))
    assert [cache.get(url_of(i)).body for i in range(60)] == [b'body %d' % i for i in range(60)]
    assert max(p.stat().st_size for p in (tmp_path / 'urls').glob('*.json')) <= 4096


def test_a_full_shard_is_refused_and_keeps_what_it_holds(tmp_path, monkeypatch):
    cache = tr.OfflineCache(tmp_path)
    first, second, third = colliding_urls(tmp_path, 3)
    cache.put(fetched(first, b'one'))
    cache.put(fetched(second, b'two'))
    monkeypatch.setattr(tr.OfflineCache, 'MAX_MAP_BYTES', shard_path(tmp_path, first).stat().st_size + 10)
    with pytest.raises(IntelError) as info:
        cache.put(fetched(third, b'three'))
    assert info.value.code == 'PT-INTEL-LIMIT'
    assert cache.get(first).body == b'one' and cache.get(second).body == b'two' and cache.get(third) is None
    assert not (tmp_path / 'bodies' / hashlib.sha256(b'three').hexdigest()).exists()


def test_an_index_from_the_first_version_is_still_read_and_never_rewritten(tmp_path):
    raw = write_legacy_index(tmp_path, {url_of(1): b'old body'})
    cache = tr.OfflineCache(tmp_path)
    assert cache.get(url_of(1)).body == b'old body'
    cache.put(fetched(url_of(2), b'new body'))
    assert cache.get(url_of(1)).body == b'old body' and cache.get(url_of(2)).body == b'new body'
    assert (tmp_path / 'urls.json').read_bytes() == raw


def test_a_newer_shard_entry_wins_over_the_legacy_one(tmp_path):
    write_legacy_index(tmp_path, {url_of(1): b'old body'})
    cache = tr.OfflineCache(tmp_path)
    cache.put(fetched(url_of(1), b'new body'))
    assert cache.get(url_of(1)).body == b'new body'


def test_an_over_cap_legacy_index_survives_a_put_untouched(tmp_path, monkeypatch):
    """Recipe R4, scaled down: the index the old code could no longer read was replaced by a single entry."""
    monkeypatch.setattr(tr.OfflineCache, 'MAX_MAP_BYTES', 2048)
    raw = write_legacy_index(tmp_path, {url_of(i): b'%d' % i for i in range(20)})
    assert len(raw) > 2048
    cache = tr.OfflineCache(tmp_path)
    cache.put(fetched(url_of(100), b'later'))
    assert cache.get(url_of(100)).body == b'later'
    assert (tmp_path / 'urls.json').read_bytes() == raw


class OneResponse:
    status = 200
    headers: dict = {}

    def __init__(self, body: bytes):
        self._body = body

    def read(self, size: int) -> bytes:
        piece, self._body = self._body[:size], self._body[size:]
        return piece

    def close(self) -> None:
        pass


def test_an_unusable_index_does_not_fail_a_fetch_that_succeeded(tmp_path):
    """SPEC-28 section D: the cache is best-effort, a refused cache write is announced and the fetch still returns."""
    url = url_of(1)
    shard = shard_path(tmp_path, url)
    shard.parent.mkdir()
    shard.write_bytes(b'{not json')
    seen: list[str] = []
    client = tr.CsafTransport(tr.CsafConsent.for_hosts(['msrc.microsoft.com']), cache=tr.OfflineCache(tmp_path),
                              opener=lambda u, headers, timeout: OneResponse(b'{"x": 1}'), announce=seen.append,
                              now=lambda: datetime(2099, 3, 1, tzinfo=UTC))
    assert client.get(url, 'document').body == b'{"x": 1}'
    assert any('cache not updated' in line for line in seen), seen
    assert shard.read_bytes() == b'{not json'
