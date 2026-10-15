"""Raw-first cache for capa output (CAP-4): the exact stdout is cached, never the parsed set, so a parser improvement
re-parses old output instead of invalidating it. Built on the existing content-addressed `DerivedCache`, which already
refuses unreadable, mismatched or oversized entries; this layer adds the capa key, zlib framing and the soft-miss rule.

Every failure here is a miss: a corrupt entry, a bad zlib stream, an over-large stream or a refused write never fails
an analysis. The cache directory is the profile's own `cache_dir` and is never the scratch HOME/XDG/LOCALAPPDATA that
capa sees (its rule cache is a pickle and must not share a directory with this one)."""
from __future__ import annotations

import json
import zlib
from collections.abc import Callable
from dataclasses import dataclass

from ...enrichment.cache import DerivedCache
from .common import CONTRACT, ToolManifest, cache_key

STAGE = 'capa-raw'


@dataclass(frozen=True)
class RawResult:
    raw: bytes | None
    hit: bool


def _inflate(payload: bytes, max_bytes: int) -> bytes | None:
    """Bounded decompression: a stream that expands past the stdout limit is treated as corrupt."""
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(payload, max_bytes + 1)
    except zlib.error:
        return None
    if len(raw) > max_bytes or not inflater.eof or inflater.unused_data or not raw.strip():
        return None
    return raw


def lookup(cache: DerivedCache, artifact_sha256: str, manifest: ToolManifest, options: dict[str, str],
           max_bytes: int) -> bytes | None:
    payload = cache.get(STAGE, cache_key(artifact_sha256, manifest, options))
    return None if payload is None else _inflate(payload, max_bytes)


def store(cache: DerivedCache, artifact_sha256: str, manifest: ToolManifest, options: dict[str, str],
          raw: bytes) -> bool:
    inputs = {'artifact_sha256': artifact_sha256, 'contract': CONTRACT, 'options': json.dumps(options, sort_keys=True),
              'tool': json.dumps(manifest.identity(), sort_keys=True)}
    return cache.put(STAGE, cache_key(artifact_sha256, manifest, options), zlib.compress(raw, 6), inputs)


def fetch_or_run(cache: DerivedCache | None, artifact_sha256: str, manifest: ToolManifest, options: dict[str, str],
                 spawn: Callable[[], bytes | None], *, max_bytes: int) -> RawResult:
    """Raw output for one build: from the cache when present (nothing is spawned), else from `spawn()`, which returns
    the raw stdout of a successful run or None. Only successful output is cached; with no cache `spawn` just runs."""
    if cache is not None:
        raw = lookup(cache, artifact_sha256, manifest, options, max_bytes)
        if raw is not None:
            return RawResult(raw, True)
    raw = spawn()
    if raw is not None and cache is not None:
        store(cache, artifact_sha256, manifest, options, raw)
    return RawResult(raw, False)
