"""Pure text formatters for raw bytes (no I/O)."""
from __future__ import annotations

import base64


def _gutter_width(base_offset: int, length: int) -> int:
    return max(8, len(f'{base_offset + max(length - 1, 0):x}'))


def _check_args(data: bytes, base_offset: int, per_line: int) -> None:
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('data must be bytes')
    if isinstance(base_offset, bool) or not isinstance(base_offset, int) or base_offset < 0:
        raise ValueError('base_offset must be a non-negative integer')
    if isinstance(per_line, bool) or not isinstance(per_line, int) or per_line < 1:
        raise ValueError('line width must be a positive integer')


def format_hex(data: bytes, base_offset: int, width: int = 16, ascii: bool = True) -> str:  # noqa: A002
    _check_args(data, base_offset, width)
    gw = _gutter_width(base_offset, len(data))
    lines = []
    for i in range(0, len(data), width):
        row = data[i:i + width]
        cells = []
        for j in range(width):
            if j == 8:
                cells.append('')
            cells.append(f'{row[j]:02x}' if j < len(row) else '  ')
        line = f'{base_offset + i:0{gw}x}  ' + ' '.join(cells)
        if ascii:
            line += '  |' + ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in row) + '|'
        lines.append(line)
    return '\n'.join(lines)


def format_binary(data: bytes, base_offset: int, per_line: int = 8) -> str:
    _check_args(data, base_offset, per_line)
    gw = _gutter_width(base_offset, len(data))
    return '\n'.join(
        f'{base_offset + i:0{gw}x}  ' + ' '.join(f'{b:08b}' for b in data[i:i + per_line])
        for i in range(0, len(data), per_line))


def base64_exact(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode('ascii')


def format_base64(data: bytes, wrap: int = 76) -> str:
    if isinstance(wrap, bool) or not isinstance(wrap, int) or wrap < 1:
        raise ValueError('wrap must be a positive integer')
    text = base64_exact(data)
    return '\n'.join(text[i:i + wrap] for i in range(0, len(text), wrap))
