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

import json
import re

from ._common import Source, load_text, normalise_name, rank, unit_float


def parse(source: Source) -> list[str]:
    text = load_text(source, 'ghidriff report')
    return _parse_json(text) if text.lstrip().startswith('{') else _parse_markdown(text)


def _reject_constant(token: str) -> None:
    raise ValueError(f'ghidriff JSON contains the non-standard constant {token}')


def _parse_json(text: str) -> list[str]:
    try:
        doc = json.loads(text, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f'ghidriff JSON is malformed: {exc}') from exc
    funcs = doc.get('functions') if isinstance(doc, dict) else None
    if not isinstance(funcs, dict) or not all(isinstance(funcs.get(k), list) for k in ('modified', 'added', 'deleted')):
        raise ValueError('ghidriff JSON has no functions.modified/added/deleted lists')
    changed: list[tuple[str, float]] = []
    for i, entry in enumerate(funcs['modified']):
        if not isinstance(entry, dict) or not isinstance(entry.get('old'), dict):
            raise ValueError(f'functions.modified[{i}] is not an object with an `old` side')
        ratio = unit_float(entry.get('ratio', 1.0), f'functions.modified[{i}].ratio')
        diff_type = entry.get('diff_type', [])
        if not isinstance(diff_type, list):
            raise ValueError(f'functions.modified[{i}].diff_type must be a list')
        if 'code' not in diff_type:
            continue  # name/address/call-graph-only change: not a code change (ratio is decompiler text, may drift)
        old = entry['old']
        name = normalise_name(old.get('fullname') or old.get('name'))
        if name is None:
            continue
        b_ratio = unit_float(entry.get('b_ratio', 1.0), f'functions.modified[{i}].b_ratio')
        m_ratio = unit_float(entry.get('m_ratio', 1.0), f'functions.modified[{i}].m_ratio')
        # magnitude dominated by the code ratio; block/mnemonic ratios only separate ties
        changed.append((name, (1.0 - ratio) + 1e-3 * (1.0 - b_ratio) + 1e-6 * (1.0 - m_ratio)))
    one_sided: list[str] = []
    for key in ('added', 'deleted'):
        for i, entry in enumerate(funcs[key]):
            if not isinstance(entry, dict):
                raise ValueError(f'functions.{key}[{i}] is not an object')
            name = normalise_name(entry.get('fullname') or entry.get('name'))
            if name is not None:
                one_sided.append(name)
    return rank(changed, one_sided)


_HEADING = re.compile(r'^(#{1,6})\s+(.+?)\s*#*\s*$')
_SECTIONS = {'Modified': 'modified', 'Deleted': 'deleted', 'Added': 'added'}


def _parse_markdown(text: str) -> list[str]:
    section: str | None = None
    func: str | None = None
    sub: str | None = None
    in_fence = False
    fence_is_diff = False
    sizes: dict[str, int] = {}
    one_sided: list[str] = []
    saw_section = False
    for line in text.splitlines():
        if line.startswith('```'):
            in_fence = not in_fence
            fence_is_diff = in_fence and line[3:].strip().lower() == 'diff'
            continue
        if in_fence:
            if (fence_is_diff and section == 'modified' and func and sub == f'{func} Diff'
                    and line[:1] in '+-' and not line.startswith(('+++', '---'))):
                sizes[func] = sizes.get(func, 0) + 1
            continue
        m = _HEADING.match(line)
        if not m:
            continue
        level, title = len(m.group(1)), m.group(2)
        if level == 1:
            section = _SECTIONS.get(title)
            saw_section = saw_section or title in _SECTIONS or title.startswith('Modified (')
            func = sub = None
        elif level == 2 and section and not title.startswith('Max '):
            name = normalise_name(title)
            func, sub = name, None
            if name is None:
                continue
            if section == 'modified':
                sizes.setdefault(name, 0)
            else:
                one_sided.append(name)
        elif level == 3:
            sub = title
    if not saw_section:
        raise ValueError('not a ghidriff report: no Modified/Added/Deleted sections found')
    return rank(((n, float(c)) for n, c in sizes.items() if c > 0), one_sided)
