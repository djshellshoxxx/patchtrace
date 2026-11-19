"""Ghidriff report -> ranked changed-function names. JSON (`*.ghidriff.json`) or markdown (`*.md`), auto-detected.

JSON layout (read from ghidriff 1.0.0 source, ghidra_diff_engine.py): `functions.modified[]` entries carry
`old`/`new` (each with `name`, `fullname`), `diff_type` and similarity ratios (`ratio` code, `b_ratio` blocks,
`m_ratio` mnemonics, 1.0 = identical); `functions.added[]` / `functions.deleted[]` entries carry `fullname`.
Changed = a modified entry whose `diff_type` has `code`; magnitude = 1 - ratio, ties
by the block then mnemonic ratio. Name = the old side's `fullname` (what the markdown report headings use).
Markdown: `# Modified` / `# Deleted` / `# Added` sections with one `##` heading per function; magnitude = number of
`+`/`-` lines in that function's `### <name> Diff` block. `# Modified (No Code Changes)` is treated as unchanged.
"""
from __future__ import annotations

import hashlib
import json
import re

from . import _common
from ._common import Source, load_text, normalise_name, rank, unit_float


def parse(source: Source) -> list[str]:
    text = load_text(source, 'ghidriff report')
    return _parse_json(text) if text.lstrip().startswith('{') else _parse_markdown(text)


def _reject_constant(token: str) -> None:
    raise ValueError(f'ghidriff JSON contains the non-standard constant {token}')


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON object key {key[:80]!r}')
        result[key] = value
    return result


def _name(raw: object) -> str | None:
    name = normalise_name(raw)
    if name is not None:
        try:
            name.encode('utf-8')
        except UnicodeEncodeError as exc:
            raise ValueError('ghidriff function name must be valid UTF-8 text') from exc
    return name


_ADDRESS = re.compile(r'(?:0[xX])?[0-9a-fA-F]{1,16}\Z')


def _side(record: object, label: str) -> tuple[str, int | None]:
    if not isinstance(record, dict):
        raise ValueError(f'{label} must be an object')
    short, full = _name(record.get('name')), _name(record.get('fullname'))
    name = full or short
    if name is None:
        raise ValueError(f'{label} needs a nonblank name or fullname')
    address = record.get('address')
    if address is None or isinstance(address, str) and not address.strip():
        return name, None  # old name-only fixtures remain explicitly unverified
    if not isinstance(address, str) or not _ADDRESS.fullmatch(address.strip()):
        raise ValueError(f'{label}.address must be unsigned 64-bit hexadecimal text or unknown')
    return name, int(address.strip(), 16)


def _parse_json(text: str) -> list[str]:
    try:
        doc = json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError(f'ghidriff JSON is malformed: {exc}') from exc
    funcs = doc.get('functions') if isinstance(doc, dict) else None
    if (not isinstance(funcs, dict) or set(funcs) != {'modified', 'added', 'deleted'}
            or not all(isinstance(value, list) for value in funcs.values())):
        raise ValueError('ghidriff JSON has no functions.modified/added/deleted lists')
    if sum(map(len, funcs.values())) > _common.MAX_FUNCTIONS:
        raise ValueError(f'more than {_common.MAX_FUNCTIONS} ghidriff function records')
    labels: dict[str, str] = {}
    addresses: tuple[dict[int, str], dict[int, str]] = ({}, {})
    records: set[str] = set()

    def register(collection, entry, old, new):
        # Hash complete canonical records, not only scored fields: exact repeats
        # can count once, but a changed identity/body/score cannot silently win.
        try:
            encoded = json.dumps([collection, entry], sort_keys=True, separators=(',', ':'), allow_nan=False)
        except (ValueError, RecursionError) as exc:
            raise ValueError('ghidriff record cannot be represented as strict JSON') from exc
        digest = hashlib.sha256(encoded.encode('utf-8')).hexdigest()
        for endpoint, indexed in zip((old, new), addresses, strict=True):
            if endpoint is None:
                continue
            name, address = endpoint
            if name in labels and labels[name] != digest:
                raise ValueError(f'ghidriff report has ambiguous function label {name!r}')
            if address is not None and address in indexed and indexed[address] != digest:
                raise ValueError(f'ghidriff report has conflicting function identity at address {address:x}')
            labels[name] = digest
            if address is not None:
                indexed[address] = digest
        if digest in records:
            return False
        records.add(digest)
        return True

    changed: list[tuple[str, float]] = []
    for i, entry in enumerate(funcs['modified']):
        if not isinstance(entry, dict) or not isinstance(entry.get('old'), dict):
            raise ValueError(f'functions.modified[{i}] is not an object with an `old` side')
        label = f'functions.modified[{i}]'
        old = _side(entry['old'], label + '.old')
        new = _side(entry['new'], label + '.new') if 'new' in entry else None
        ratio = unit_float(entry.get('ratio', 1.0), f'functions.modified[{i}].ratio')
        b_ratio = unit_float(entry.get('b_ratio', 1.0), f'functions.modified[{i}].b_ratio')
        m_ratio = unit_float(entry.get('m_ratio', 1.0), f'functions.modified[{i}].m_ratio')
        diff_type = entry.get('diff_type', [])
        if not isinstance(diff_type, list) or any(not isinstance(kind, str) for kind in diff_type):
            raise ValueError(f'functions.modified[{i}].diff_type must be a list of strings')
        fresh = register('modified', entry, old, new)
        if not fresh or 'code' not in diff_type:
            continue  # name/address/call-graph-only change: not a code change (ratio is decompiler text, may drift)
        # magnitude dominated by the code ratio; block/mnemonic ratios only separate ties
        changed.append((old[0], (1.0 - ratio) + 1e-3 * (1.0 - b_ratio) + 1e-6 * (1.0 - m_ratio)))
    one_sided: list[str] = []
    for key in ('added', 'deleted'):
        for i, entry in enumerate(funcs[key]):
            endpoint = _side(entry, f'functions.{key}[{i}]')
            old, new = (endpoint, None) if key == 'deleted' else (None, endpoint)
            if register(key, entry, old, new):
                one_sided.append(endpoint[0])
    return rank(changed, one_sided)


_HEADING = re.compile(r'^(#{1,6})\s+(.+?)\s*#*\s*$')
_SECTIONS = {'Modified': 'modified', 'Deleted': 'deleted', 'Added': 'added',
             'Modified (No Code Changes)': 'unchanged'}


def _parse_markdown(text: str) -> list[str]:
    section: str | None = None
    func: str | None = None
    func_title: str | None = None
    sub: str | None = None
    in_fence = False
    fence_is_diff = False
    sizes: dict[str, int] = {}
    one_sided: list[str] = []
    names: set[str] = set()
    saw_section = False
    for line in text.splitlines():
        if line.startswith('```'):
            in_fence = not in_fence
            fence_is_diff = in_fence and line[3:].strip().lower() == 'diff'
            continue
        if in_fence:
            if (fence_is_diff and section == 'modified' and func and sub == f'{func_title} Diff'
                    and line[:1] in '+-' and not line.startswith(('+++', '---'))):
                sizes[func] = sizes.get(func, 0) + 1
            continue
        m = _HEADING.match(line)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2)
        if level == 1:
            section = _SECTIONS.get(title)
            saw_section = saw_section or title in _SECTIONS
            func = func_title = sub = None
        elif level == 2 and section and not title.startswith('Max '):
            name = _name(title)
            func, func_title, sub = name, title, None
            if name is None:
                continue
            if len(names) >= _common.MAX_FUNCTIONS:
                raise ValueError(f'more than {_common.MAX_FUNCTIONS} ghidriff function headings')
            if name in names:
                raise ValueError(f'ghidriff markdown has ambiguous function label {name!r}')
            names.add(name)
            if section == 'modified':
                sizes.setdefault(name, 0)
            elif section != 'unchanged':
                one_sided.append(name)
        elif level == 3:
            sub = title
    if not saw_section:
        raise ValueError('not a ghidriff report: no Modified/Added/Deleted sections found')
    return rank(((n, float(c)) for n, c in sizes.items() if c > 0), one_sided)
