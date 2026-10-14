"""Bounded paging of a scope through the verified artifact reader."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from ..artifact_bytes import ArtifactBytesError
from .scope import ByteScope

MIN_PAGE_SIZE = 16
MAX_PAGE_SIZE = 65536
DEFAULT_PAGE_SIZE = 4096


class ByteReader(Protocol):
    @property
    def size(self) -> int: ...
    @property
    def sha256(self) -> str: ...
    def read(self, offset: int, length: int, *, clip: bool = True) -> bytes: ...


@dataclass(frozen=True)
class PageBytes:
    page_index: int
    page_count: int
    scope: ByteScope
    chunks: tuple[tuple[int, bytes], ...]
    logical_start: int
    byte_count: int
    sha256: str

    @property
    def data(self) -> bytes:
        return b''.join(chunk for _, chunk in self.chunks)


def check_page_size(page_size: int) -> int:
    if isinstance(page_size, bool) or not isinstance(page_size, int):
        raise ValueError('page_size must be an integer')
    if not MIN_PAGE_SIZE <= page_size <= MAX_PAGE_SIZE or page_size % 16:
        raise ValueError(f'page_size must be a multiple of 16 in {MIN_PAGE_SIZE}..{MAX_PAGE_SIZE}')
    return page_size


def page_count(scope: ByteScope, page_size: int) -> int:
    check_page_size(page_size)
    if not scope.available:
        return 0
    return -(-scope.total_length // page_size)


def read_page(reader: ByteReader, scope: ByteScope, page_index: int,
              page_size: int = DEFAULT_PAGE_SIZE) -> PageBytes:
    check_page_size(page_size)
    if not scope.available:
        raise ValueError(scope.unavailable_reason or 'scope unavailable')
    if isinstance(page_index, bool) or not isinstance(page_index, int):
        raise TypeError('page_index must be an integer')
    count = page_count(scope, page_size)
    if not 0 <= page_index < count:
        raise IndexError(f'page {page_index} outside 0..{count - 1}')
    if scope.file_size is not None and reader.size != scope.file_size:
        raise ArtifactBytesError('size_mismatch',
                                 f'scope built for {scope.file_size} bytes, reader has {reader.size}')
    start = page_index * page_size
    end = min(start + page_size, scope.total_length)
    chunks: list[tuple[int, bytes]] = []
    pos = 0
    for seg in scope.segments:
        seg_start, seg_end = pos, pos + seg.length
        pos = seg_end
        lo, hi = max(start, seg_start), min(end, seg_end)
        if lo >= hi:
            continue
        offset = seg.file_offset + (lo - seg_start)
        chunks.append((offset, reader.read(offset, hi - lo, clip=False)))
    digest = hashlib.sha256()
    for _, chunk in chunks:
        digest.update(chunk)
    return PageBytes(page_index, count, scope, tuple(chunks), start, end - start, digest.hexdigest())
