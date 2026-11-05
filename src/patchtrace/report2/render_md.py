"""Markdown renderer (SPEC-50 7.4): data reaches the page only through the escaping matrix or a computed fence."""
from __future__ import annotations

from . import text
from .blocks import Block, build_blocks
from .render_json import render_json


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    if not rows:
        return []
    return ['| ' + ' | '.join(headers) + ' |', '|' + '---|' * len(headers),
            *('| ' + ' | '.join(text.md_cell(c) for c in row) + ' |' for row in rows)]


def _block(block: Block) -> list[str]:
    kind, *args = block
    if kind in ('h1', 'h2'):
        return ['#' * int(kind[1]) + ' ' + args[0]]
    if kind == 'h3':
        return ['### ' + text.md_heading(args[0])]
    if kind == 'note':
        return [args[0]]
    if kind == 'para':
        return [text.md_paragraph(args[0])]
    if kind == 'facts':
        return ['\n'.join(f'- {label}: {text.md_paragraph(value)}' for label, value in args[0])]
    if kind == 'bullets':
        return ['\n'.join('- ' + text.md_paragraph(v) for v in args[0])] if args[0] else []
    if kind == 'table':
        table = _table(*args)
        return ['\n'.join(table)] if table else []
    return [text.md_fence(args[0])]


def render_md(data: dict) -> str:
    parts = [chunk for block in build_blocks(data, render_json(data).rstrip('\n')) for chunk in _block(block)]
    return '\n\n'.join(parts) + '\n'
