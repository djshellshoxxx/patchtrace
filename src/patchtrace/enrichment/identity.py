"""Canonical JSON and domain-separated SHA-256 identities (SPEC-07 §3). Pure stdlib.

Content identities must be reproducible on every platform: strings are NFC, keys
sorted, separators compact, and floats/NaN are rejected outright so a score input can
never drift through binary floating point. Timestamps and absolute paths must not be
passed in; the caller decides what is semantic.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping

_PREFIX = b'patchtrace\x00'
_SKIP = object()


def _normalize(value):
    """Exact-type fast path for the hot identity payloads (dicts, lists, ASCII strings, ints); anything
    else takes the general path below. Output and errors are identical (tests/test_identity_equivalence.py)."""
    kind = type(value)
    if kind is str:
        return value if value.isascii() else unicodedata.normalize('NFC', value)  # NFC never changes ASCII
    if kind is int or kind is bool or value is None:
        return value
    if kind is dict:
        out = {}
        for key, item in value.items():
            if type(key) is not str and not isinstance(key, str):
                raise TypeError('identity payload keys must be strings')
            normalized = key if key.isascii() else unicodedata.normalize('NFC', key)
            if normalized in out:
                raise ValueError('keys collide after NFC normalization')
            # Scalars are the bulk of every payload: handle them without a recursive call.
            leaf = type(item)
            if leaf is str and item.isascii() or leaf is int:
                out[normalized] = item
            else:
                out[normalized] = _normalize(item)
        return out
    if kind is list or kind is tuple:
        return [item if type(item) is int or type(item) is str and item.isascii() else _normalize(item)
                for item in value]
    return _normalize_general(value)


def _normalize_general(value):
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


# One shared encoder: `json.dumps` with these options builds a new JSONEncoder per call. Stateless while
# encoding (`markers` is per call), so it is safe to share between threads.
_ENCODER = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def canonical_json(value) -> bytes:
    return _ENCODER.encode(_normalize(value)).encode('utf-8')


def domain_id(domain: str, version: int, payload) -> str:
    if not domain or '\x00' in domain or type(version) is not int or version < 1:
        raise ValueError('invalid identity domain or version')
    data = _PREFIX + domain.encode('ascii') + b'\x00' + str(version).encode('ascii') + b'\x00'
    return hashlib.sha256(data + canonical_json(payload)).hexdigest()


def sorted_unique(items: Iterable) -> list:
    """Order-independent set representation by canonical bytes."""
    items = list(items)
    if len(items) <= 1:  # nothing to order or merge (1:1 pairings); the caller's payload is still validated
        return items
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


def _plain(value, depth: int = 0):
    """Canonical-JSON-able form of a plain-data constant, or _SKIP for code, types and other objects."""
    if depth > 32:
        return _SKIP
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return {'float': repr(value)}
    if isinstance(value, re.Pattern):
        pattern = value.pattern if isinstance(value.pattern, str) else value.pattern.hex()
        return {'re': pattern, 'flags': int(value.flags)}
    if isinstance(value, (tuple, list, set, frozenset)):
        items = [_plain(item, depth + 1) for item in value]
        if any(item is _SKIP for item in items):
            return _SKIP
        return sorted_unique(items) if isinstance(value, (set, frozenset)) else items
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            plain_key, plain_item = _plain(key, depth + 1), _plain(item, depth + 1)
            if plain_key is _SKIP or plain_item is _SKIP:
                return _SKIP
            out[plain_key if isinstance(plain_key, str) else canonical_json(plain_key).decode('utf-8')] = plain_item
        return out
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        out = {'__dataclass__': type(value).__qualname__}
        for item in dataclasses.fields(value):
            plain_item = _plain(getattr(value, item.name), depth + 1)
            if plain_item is not _SKIP:  # callables (detector rules) are code, not data
                out[item.name] = plain_item
        return out
    return _SKIP


def constants_digest(domain: str, version: int, namespaces: Iterable[Mapping[str, object]],
                     exclude: Iterable[str] = ()) -> str:
    """Digest of the plain-data module constants that define an algorithm (SPEC-07h Phase D).

    Every non-dunder global whose value is plain data (see `_plain`) is included under
    `<module>:<name>`, so editing a regex, table, limit or detector declaration changes the digest
    without anyone bumping a version. Functions, classes, modules and other objects are skipped:
    logic changes still need an explicit version bump."""
    skip = set(exclude)
    payload: dict[str, object] = {}
    for namespace in namespaces:
        module = str(namespace.get('__name__', ''))
        for name in sorted(namespace):
            if name.startswith('__') or name in skip:
                continue
            value = _plain(namespace[name])
            if value is not _SKIP:
                payload[f'{module}:{name}'] = value
    return domain_id(domain, version, payload)


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
