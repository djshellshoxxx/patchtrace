"""HTML renderer (SPEC-50 7.4): one `<style>` covered by a CSP hash, no scripts, links, or attributes built from data."""
from __future__ import annotations

import base64
import hashlib
import html

from . import text
from .blocks import Block, build_blocks
from .render_json import render_json

STYLE = ('body{max-width:1000px;margin:2rem auto;padding:0 1rem;font:16px sans-serif}'
         'table{border-collapse:collapse}th,td{border:1px solid #888;padding:.2rem .5rem;text-align:left;'
         'vertical-align:top;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;'
         'border:1px solid #888;padding:.5rem}')
STYLE_HASH = base64.b64encode(hashlib.sha256(STYLE.encode('ascii')).digest()).decode('ascii')
CSP = f"default-src 'none'; style-src 'sha256-{STYLE_HASH}'; base-uri 'none'; form-action 'none'"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ''
    head = ''.join(f'<th>{html.escape(h)}</th>' for h in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{text.html_text(c)}</td>' for c in row) + '</tr>' for row in rows)
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def _block(block: Block) -> str:
    kind, *args = block
    if kind in ('h1', 'h2'):
        return f'<{kind}>{html.escape(args[0])}</{kind}>'
    if kind == 'h3':
        return f'<h3>{text.html_text(args[0])}</h3>'
    if kind == 'note':
        return f'<p>{html.escape(args[0])}</p>'
    if kind == 'para':
        return f'<p>{text.html_text(args[0])}</p>'
    if kind == 'facts':
        items = ''.join(f'<li><strong>{html.escape(label)}</strong>: {text.html_text(value)}</li>'
                        for label, value in args[0])
        return f'<ul>{items}</ul>'
    if kind == 'bullets':
        return '<ul>' + ''.join(f'<li>{text.html_text(v)}</li>' for v in args[0]) + '</ul>' if args[0] else ''
    if kind == 'table':
        return _table(*args)
    return f'<pre>{text.html_pre(args[0])}</pre>'


def render_html(data: dict) -> str:
    title = text.html_text('PatchTrace report: ' + data['name'])
    body = '\n'.join(filter(None, (_block(b) for b in build_blocks(data, render_json(data).rstrip('\n')))))
    return ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<meta name="referrer" content="no-referrer">\n'
            f'<meta http-equiv="Content-Security-Policy" content="{html.escape(CSP)}">\n'
            f'<title>{title}</title>\n<style>{STYLE}</style></head>\n<body><main>\n{body}\n</main></body></html>\n')
