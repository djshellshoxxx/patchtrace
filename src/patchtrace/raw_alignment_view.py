"""Pure presentation of bounded, independently addressed verified byte windows."""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from .artifact_bytes import ArtifactBytesError, VerifiedArtifactReader
from .representations import (
    ByteAlignment,
    PageBytes,
    RenderedPage,
    Representation,
    align_pages,
    file_range,
    format_binary,
    format_hex,
    read_page,
    render_page,
)

MAX_WINDOW = 4096
GAP = '[display-only gap: no bytes]'


@dataclass(frozen=True)
class WindowRequest:
    older: VerifiedArtifactReader
    newer: VerifiedArtifactReader
    older_offset: int
    newer_offset: int
    window: int
    representation: Representation


@dataclass(frozen=True)
class SpanRow:
    label: str
    line: int
    end_line: int
    kind: str


@dataclass(frozen=True)
class AlignmentView:
    older: RenderedPage
    newer: RenderedPage
    older_text: str
    newer_text: str
    spans: tuple[SpanRow, ...]
    summary: str
    alignment: ByteAlignment | None


def _check_cancel(cancel: Callable[[], bool]) -> None:
    if cancel():
        raise ArtifactBytesError('cancelled', 'Paired window read cancelled')


def _window(reader: VerifiedArtifactReader, offset: int, size: int) -> PageBytes:
    scope = file_range(reader.size, offset, size)
    if scope.total_length:
        return read_page(reader, scope, 0, size)
    # Even an empty window rechecks the verified handle. align_pages intentionally rejects empty pages.
    data = reader.read(offset, 0, clip=False)
    return PageBytes(0, 0, scope, (), 0, 0, hashlib.sha256(data).hexdigest())


def build_alignment_view(request: WindowRequest, cancel: Callable[[], bool] = lambda: False) -> AlignmentView:
    """Read at most 4096 bytes per side. No Qt, project/service references, network or inferred continuation."""
    size = request.window
    if type(size) is not int or not 16 <= size <= MAX_WINDOW or size % 16:
        raise ValueError('Paired window must be a multiple of 16 within 16..4096 bytes')
    if request.representation not in (Representation.HEX, Representation.BINARY):
        raise ValueError('Paired alignment supports Hex and Binary only')
    _check_cancel(cancel)
    older = _window(request.older, request.older_offset, size)
    _check_cancel(cancel)
    newer = _window(request.newer, request.newer_offset, size)
    _check_cancel(cancel)
    rendered = [render_page(page, request.representation) for page in (older, newer)]
    notes = [f'{side.upper()}: 0x{offset:x}, {page.byte_count}/{size} bytes'
             + (' · EOF (window clipped)' if page.scope.clipped else '')
             for side, offset, page in (('older', request.older_offset, older),
                                        ('newer', request.newer_offset, newer))]
    if not older.byte_count or not newer.byte_count:
        return AlignmentView(*rendered, rendered[0].text or '[EOF: no bytes]',
                             rendered[1].text or '[EOF: no bytes]', (),
                             'Alignment unavailable: a physical window starts at EOF\n' + '; '.join(notes), None)
    alignment = align_pages(older, newer, cancel=cancel)
    _check_cancel(cancel)
    fmt = format_hex if request.representation is Representation.HEX else format_binary
    lines: list[list[str]] = [[], []]
    rows = []
    for span in alignment.spans:
        label = (f'{span.kind} · older 0x{span.older_offset:x}+{len(span.older)} · '
                 f'newer 0x{span.newer_offset:x}+{len(span.newer)}')
        first = len(lines[0])
        bodies = [fmt(span.older, span.older_offset).splitlines(),
                  fmt(span.newer, span.newer_offset).splitlines()]
        count = max(len(body) for body in bodies)
        for target, body in zip(lines, bodies, strict=True):
            target.append(f'[{label}]')
            target.extend(body + [GAP] * (count - len(body)))
        rows.append(SpanRow(label, first, len(lines[0]) - 1, span.kind))
    status = alignment.status + (f' · {alignment.reason}' if alignment.reason else '')
    summary = f'Bounded byte alignment: {status} · {len(rows)} spans; byte equality only\n' + '; '.join(notes)
    return AlignmentView(*rendered, '\n'.join(lines[0]), '\n'.join(lines[1]), tuple(rows), summary, alignment)
