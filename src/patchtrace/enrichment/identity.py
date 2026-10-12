"""Canonical JSON and domain-separated SHA-256 identities (SPEC-07 §3). Pure stdlib.

Content identities must be reproducible on every platform: strings are NFC, keys
sorted, separators compact, and floats/NaN are rejected outright so a score input can
never drift through binary floating point. Timestamps and absolute paths must not be
passed in; the caller decides what is semantic.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Iterable, Mapping

_PREFIX = b'patchtrace\x00'


def _normalize(value):
    if isinstance(value, str):
        return unicodedata.normalize('NFC', value)
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise TypeError('floats are not permitted in identity payloads')
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError('identity payload keys must be strings')
            normalized = unicodedata.normalize('NFC', key)
            if normalized in out:
                raise ValueError('keys collide after NFC normalization')
            out[normalized] = _normalize(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    raise TypeError(f'unsupported identity payload type {type(value).__name__}')


def canonical_json(value) -> bytes:
    return json.dumps(_normalize(value), sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def domain_id(domain: str, version: int, payload) -> str:
    if not domain or '\x00' in domain or type(version) is not int or version < 1:
        raise ValueError('invalid identity domain or version')
    data = _PREFIX + domain.encode('ascii') + b'\x00' + str(version).encode('ascii') + b'\x00'
    return hashlib.sha256(data + canonical_json(payload)).hexdigest()


def sorted_unique(items: Iterable) -> list:
    """Order-independent set representation by canonical bytes."""
    seen = {canonical_json(item): item for item in items}
    return [seen[key] for key in sorted(seen)]


def excerpt_sha256(lines: Iterable[str]) -> str:
    return hashlib.sha256('\n'.join(lines).encode('utf-8')).hexdigest()


def diff_id(older_sha256: str, newer_sha256: str, raw_sha256: str, tool: str = 'ghidriff') -> str:
    return domain_id('diff', 1, {'older_sha256': older_sha256, 'newer_sha256': newer_sha256,
                                 'raw_sha256': raw_sha256, 'tool': tool})


def occurrence(diff: str, side: str, address: int | None, name: str, ordinal: int) -> dict:
    return {'diff_id': diff, 'side': side, 'address': address, 'name': name, 'ordinal': ordinal}


def pairing_id(diff: str, category: str, manual: bool, older: Iterable[dict], newer: Iterable[dict]) -> str:
    return domain_id('pairing', 1, {'diff_id': diff, 'category': category, 'manual': bool(manual),
                                    'older': sorted_unique(older), 'newer': sorted_unique(newer)})


def signal_id(pairing: str, detector: str, version: int, group_key: str, locations: Iterable[dict]) -> str:
    return domain_id('signal', 1, {'pairing_id': pairing, 'detector': detector, 'detector_version': version,
                                   'group_key': group_key, 'locations': sorted_unique(locations)})


def stage_id(stage: str, version: int, inputs: Mapping[str, str]) -> str:
    return domain_id('stage', 1, {'stage': stage, 'stage_version': version, 'inputs': dict(inputs)})


def parse_address(text: str | None) -> int | None:
    """Ghidriff hex/decimal address text to int; 0 is valid, unparsable is None."""
    if text is None:
        return None
    value = text.strip().lower()
    if value.startswith('0x'):
        value = value[2:]
    elif not all(c in '0123456789abcdef' for c in value):
        return None
    try:
        number = int(value, 16)
    except ValueError:
        return None
    return number if 0 <= number < 2**64 else None
