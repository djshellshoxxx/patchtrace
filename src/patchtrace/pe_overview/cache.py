"""Cache key and sidecar round trip for PE metadata results (SPEC-51 7.6).

The storage is a port so this module needs no database: the enrichment sidecar kind `pe-metadata` implements it
once the integration owner adds the kind. A row from another `overview_version` is ignored and recomputed.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict
from typing import Any, Protocol

from .models import Limits

KIND = 'pe-metadata'
OVERVIEW_VERSION = 2
TRUST_MODES = ('offline', 'cache', 'online')


class SidecarPort(Protocol):
    def get(self, kind: str, key: str) -> dict[str, Any] | None: ...

    def put(self, kind: str, key: str, payload: dict[str, Any]) -> None: ...


def limits_digest(limits: Limits) -> str:
    return hashlib.sha256(json.dumps(asdict(limits), sort_keys=True).encode()).hexdigest()


def cache_key(artifact_sha256: str, limits: Limits, trust_mode: str, trust_fingerprint: str) -> str:
    """`trust_fingerprint` is `win32:<build>` or `portable`, so a portable result never serves as a Windows one."""
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
