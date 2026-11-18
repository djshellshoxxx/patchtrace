"""Rizin/radare2 output -> ranked changed-function names.

Native nested rz-diff JSON must have unambiguous report-visible names, addresses and mappings before ranking.
This does not verify source-to-binary truth or replace production parse/ownership checks. Legacy text/flat JSON
remains UNVERIFIED. The text row layout follows radiff2's `diffrow` printf as recalled
from the source: `name size 0xaddr | STATUS (similarity) | 0xaddr2 size2 name2`, STATUS in MATCH / UNMATCH / NEW.
The legacy JSON reader is deliberately tolerant (a list of objects, or an object holding one; keys `name`, `name2`,
`similarity`/`dist`, `type`/`match`) because the key names are not confirmed. `radiff2 -g` graph output is not
supported. Similarity 1.0 = identical (excluded); magnitude = 1 - similarity; NEW rows, and rows with no
similarity and no counterpart, are one-sided and rank below changed ones. Name = left side, else right.
"""
from __future__ import annotations

import json
import re

from . import _common
from ._common import Source, load_text, normalise_name, rank, unit_float

_NATIVE_KEYS = frozenset({'similarity', 'type', 'original', 'modified'})
_SIDE_KEYS = frozenset({'addr', 'name', 'size'})
_TYPES = frozenset({'COMPLETE', 'PARTIAL', 'UNLIKE'})
_Side = tuple[int, str, str, int]  # address, raw name, normalized name, size
_Record = tuple[_Side | None, _Side | None, str, float]

_ROW = re.compile(
    r'^\s*(?P<name>\S+)\s+(?P<size>\d+)\s+0x[0-9a-fA-F]+\s*\|\s*(?P<status>MATCH|UNMATCH|NEW)\s*'
    r'(?:\((?P<sim>[0-9.]+)\))?\s*\|\s*(?:0x[0-9a-fA-F]+\s+(?:\d+\s+)?(?P<name2>\S+))?\s*$')


def parse(source: Source) -> list[str]:
    text = load_text(source, 'radiff2 output')
    return _parse_json(text) if text.lstrip()[:1] in '[{' else _parse_text(text)


def _parse_text(text: str) -> list[str]:
    changed: list[tuple[str, float]] = []
    one_sided: list[str] = []
    rows = 0
    for line in text.splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        rows += 1
        left, right = (m.group('name'), m.group('name2'))
        name = normalise_name(left if left not in ('-', '') else right)
        if name is None:
            continue
        status, sim = m.group('status'), m.group('sim')
        if status == 'NEW' or (sim is None and not right):
            one_sided.append(name)
            continue
        similarity = unit_float(float(sim), 'similarity') if sim is not None else 0.0
        if similarity < 1.0:
            changed.append((name, 1.0 - similarity))
    if not rows:
        raise ValueError('no radiff2 -C rows found (expected `name size 0xaddr | MATCH (1.0) | 0xaddr2 size name2`)')
    return rank(changed, one_sided)


def _parse_json(text: str) -> list[str]:
    native = False

    def unique_object(pairs):
        nonlocal native
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError(f'duplicate JSON object key {key[:80]!r}')
            # Detect native records before selecting a legacy wrapper's first list. Otherwise a later list
            # could hide conflicting identities (or a legacy first list could bypass native validation).
            if key in ('original', 'modified'):
                native = True
            obj[key] = value
        # Missing both side keys must not downgrade a recognizable native record to unnamed legacy output.
        if (isinstance(obj.get('type'), str) and obj['type'] in _TYPES
                and 'name' not in obj and 'name2' not in obj):
            native = True
        return obj

    try:
        doc = json.loads(text, object_pairs_hook=unique_object,
                         parse_constant=lambda t: (_ for _ in ()).throw(ValueError(t)))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f'radiff2 JSON is malformed: {exc}') from exc
    if native:
        if not isinstance(doc, list):
            raise ValueError('native rz-diff JSON must be a bare array, not a legacy wrapper')
        return _parse_native(doc)
    if isinstance(doc, dict):
        doc = next((v for v in doc.values() if isinstance(v, list)), None)
    if not isinstance(doc, list) or not doc:
        raise ValueError('radiff2 JSON holds no list of function rows')
    changed: list[tuple[str, float]] = []
    one_sided: list[str] = []
    for i, row in enumerate(doc):
        if not isinstance(row, dict):
            raise ValueError(f'radiff2 JSON row {i} is not an object')
        name = normalise_name(row.get('name') or row.get('name2'))
        if name is None:
            continue
        kind = str(row.get('type', row.get('match', ''))).lower()
        sim = row.get('similarity', row.get('dist'))
        if kind == 'new' or sim is None:
            one_sided.append(name)
            continue
        similarity = unit_float(sim, f'row {i} similarity')
        if similarity < 1.0:
            changed.append((name, 1.0 - similarity))
    return rank(changed, one_sided)


def _native_side(value: object, label: str) -> _Side | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != _SIDE_KEYS:
        raise ValueError(f'{label} must be null or an object with addr, name, size')
    address, raw_name, size = value['addr'], value['name'], value['size']
    if isinstance(address, bool) or not isinstance(address, int) or not 0 <= address < 2**64:
        raise ValueError(f'{label}.addr must be an unsigned 64-bit integer')
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError(f'{label}.size must be a nonnegative integer')
    name = normalise_name(raw_name)
    if name is None:
        raise ValueError(f'{label}.name must be nonblank text')
    try:
        name.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError(f'{label}.name must be valid UTF-8 text') from exc
    return address, raw_name, name, size


def _parse_native(rows: list) -> list[str]:
    if len(rows) > _common.MAX_FUNCTIONS:
        raise ValueError(f'more than {_common.MAX_FUNCTIONS} native function rows')
    endpoints: tuple[dict[int, _Record], dict[int, _Record]] = ({}, {})
    labels: dict[str, tuple[int | None, int | None]] = {}
    changed: list[tuple[str, float]] = []
    one_sided: list[str] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != _NATIVE_KEYS:
            raise ValueError(f'native rz-diff row {i} must contain only similarity, type, original, modified')
        kind = row['type']
        if not isinstance(kind, str) or kind not in _TYPES:
            raise ValueError(f'native rz-diff row {i} has an invalid match type')
        similarity = unit_float(row['similarity'], f'row {i} similarity')
        left = _native_side(row['original'], f'row {i} original')
        right = _native_side(row['modified'], f'row {i} modified')
        if left is None and right is None:
            raise ValueError(f'native rz-diff row {i} has no function identity on either side')
        record = (left, right, kind, similarity)
        pair = (left[0] if left is not None else None, right[0] if right is not None else None)
        repeated = False
        for side, indexed in zip((left, right), endpoints, strict=True):
            if side is None:
                continue
            address, _raw, name, _size = side
            prior = indexed.get(address)
            if prior is not None and prior != record:
                raise ValueError(f'native rz-diff row {i} has conflicting identity or match data at address {address}')
            if name in labels and labels[name] != pair:
                raise ValueError(f'native rz-diff row {i} has an ambiguous normalized function name {name[:80]!r}')
            repeated = repeated or prior is not None
            indexed[address] = record
            labels[name] = pair
        # Exact repeated records contribute once. Unchanged records still own their endpoints and both labels.
        if repeated:
            continue
        name = left[2] if left is not None else right[2]
        if left is None or right is None:
            one_sided.append(name)
        elif similarity < 1.0:
            changed.append((name, 1.0 - similarity))
    return rank(changed, one_sided)
