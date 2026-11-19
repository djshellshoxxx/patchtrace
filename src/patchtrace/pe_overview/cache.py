"""Cache key and sidecar round trip for PE metadata results (SPEC-51 7.6).

The generic port remains available for callers. Production owner-thread storage and
strict metadata decoding live in cache_store and cache_codec. Older versions are misses.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Protocol

from .models import Limits
from .resources import DEFAULT_RESOURCE_LIMITS

KIND = 'pe-metadata'
OVERVIEW_VERSION = 2
TRUST_MODES = ('offline', 'cache', 'online')


class SidecarPort(Protocol):
    def get(self, kind: str, key: str) -> dict[str, Any] | None: ...

    def put(self, kind: str, key: str, payload: dict[str, Any]) -> None: ...


def limits_digest(limits: Limits) -> str:
    payload = {'pe': asdict(limits), 'resources': asdict(DEFAULT_RESOURCE_LIMITS)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def cache_key(artifact_sha256: str, limits: Limits, trust_mode: str, trust_fingerprint: str) -> str:
    """`trust_fingerprint` is `win32:<build>` or `portable`, so a portable result never serves as a Windows one."""
    if not isinstance(artifact_sha256, str) or re.fullmatch(r'[0-9a-f]{64}', artifact_sha256) is None:
        raise ValueError('PE metadata cache requires an artifact SHA-256')
    if trust_mode not in TRUST_MODES or not isinstance(trust_fingerprint, str) or not trust_fingerprint:
        raise ValueError('PE metadata cache requires an explicit supported trust identity')
    parts = '|'.join((artifact_sha256, str(OVERVIEW_VERSION), limits_digest(limits), trust_mode, trust_fingerprint))
    return hashlib.sha256(parts.encode()).hexdigest()


def load_or_compute(port: SidecarPort, key: str, compute: Callable[[], dict[str, Any]],
                    consent: dict[str, Any]) -> dict[str, Any]:
    row = port.get(KIND, key)
    if isinstance(row, dict) and row.get('overview_version') == OVERVIEW_VERSION \
            and isinstance(row.get('result'), dict):
        return row['result']
    result = compute()
    port.put(KIND, key, {'overview_version': OVERVIEW_VERSION, 'consent': consent, 'result': result})
    return result
