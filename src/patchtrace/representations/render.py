"""Render a PageBytes into display text, caption and exact copy text."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .formatters import base64_exact, format_base64, format_binary, format_hex
from .paging import MAX_PAGE_SIZE, PageBytes


class Representation(Enum):
    HEX = 'hex'
    BINARY = 'binary'
    BASE64 = 'base64'


@dataclass(frozen=True)
class RenderedPage:
    text: str
    caption: str
    copy_text: str
    byte_count: int


def _ranges(page: PageBytes) -> str:
    if not page.chunks:
        return 'none (empty)'
    return ', '.join(f'0x{off:x}..0x{off + len(c):x}' for off, c in page.chunks)


def render_page(page: PageBytes, representation: Representation) -> RenderedPage:
    if page.byte_count > MAX_PAGE_SIZE:
        raise ValueError(f'page exceeds the {MAX_PAGE_SIZE} byte render cap')
    representation = Representation(representation)
    data = page.data
    if representation is Representation.BASE64:
        text = format_base64(data)
        encoding = 'Base64 (RFC 4648) of exactly these bytes in logical order'
    else:
        fmt = format_hex if representation is Representation.HEX else format_binary
        multi = len(page.chunks) > 1
        parts = []
        for n, (off, chunk) in enumerate(page.chunks, 1):
            body = fmt(chunk, off)
            if multi:
                body = (f'-- segment {n}/{len(page.chunks)}: file offset 0x{off:x}..0x{off + len(chunk):x} '
                        f'({len(chunk)} bytes) --\n' + body)
            parts.append(body)
        text = '\n'.join(parts)
        encoding = 'Hex' if representation is Representation.HEX else 'Binary (8-bit groups)'
    caption = (f'{page.scope.label} | {encoding} | file offset {_ranges(page)} | {page.byte_count} bytes | '
               f'page {page.page_index + 1}/{max(page.page_count, 1)} | SHA-256 of displayed bytes '
               f'{page.sha256} | original on-disk bytes (not transformed)')
    if representation is Representation.BASE64:
        caption += f' | Base64 length {len(base64_exact(data))} chars'
    header = (f'# PatchTrace raw bytes: {page.scope.label}; {encoding}; file offset {_ranges(page)}; '
              f'{page.byte_count} bytes; SHA-256 {page.sha256}; original on-disk bytes')
    return RenderedPage(text, caption, header + '\n' + text, page.byte_count)
