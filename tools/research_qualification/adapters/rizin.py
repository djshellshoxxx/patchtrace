"""Rizin/radare2 `radiff2 -C` output (text or `-j` JSON) -> ranked changed-function names.

UNVERIFIED: no real radiff2 run was available. The text row layout follows radiff2's `diffrow` printf as recalled
from the source: `name size 0xaddr | STATUS (similarity) | 0xaddr2 size2 name2`, STATUS in MATCH / UNMATCH / NEW.
The JSON reader is deliberately tolerant (a list of objects, or an object holding one; keys `name`, `name2`,
`similarity`/`dist`, `type`/`match`) because the key names are not confirmed. `radiff2 -g` graph output is not
supported. Similarity 1.0 = identical (excluded); magnitude = 1 - similarity; NEW rows, and rows with no
similarity and no counterpart, are one-sided and rank below changed ones. Name = left side, else right.
"""
from __future__ import annotations

import json
import re

from ._common import Source, load_text, normalise_name, rank, unit_float

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
    try:
        doc = json.loads(text, parse_constant=lambda t: (_ for _ in ()).throw(ValueError(t)))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f'radiff2 JSON is malformed: {exc}') from exc
    if isinstance(doc, dict):
        doc = next((v for v in doc.values() if isinstance(v, list)), None)
    if not isinstance(doc, list) or not doc:
        raise ValueError('radiff2 JSON holds no list of function rows')
    changed: list[tuple[str, float]] = []
    one_sided: list[str] = []
    for i, row in enumerate(doc):
        if not isinstance(row, dict):
            raise ValueError(f'radiff2 JSON row {i} is not an object')
        orig, mod = row.get('original'), row.get('modified')
        if isinstance(orig, dict) or isinstance(mod, dict) or 'original' in row or 'modified' in row:
            # rizin `rz-diff -j` layout: names nested under original/modified, a null side = unmatched
            left = normalise_name(orig.get('name')) if isinstance(orig, dict) else None
            right = normalise_name(mod.get('name')) if isinstance(mod, dict) else None
            name = left or right
            if name is None:
                continue
            if left is None or right is None:
                one_sided.append(name)
                continue
        else:
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
