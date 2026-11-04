"""U7-10: `read_snapshot` never buffers more than one line cap (+1 byte) at a time."""
from __future__ import annotations

import hashlib

import pytest

from patchtrace.unified import sources
from patchtrace.unified.limits import UnifiedError


class _SpyFile:
    """A binary file whose reads record the largest chunk handed out."""

    def __init__(self, data: bytes) -> None:
        self.data, self.pos, self.largest = data, 0, 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def readline(self, limit: int = -1) -> bytes:
        end = self.data.find(b'\n', self.pos)
        end = len(self.data) if end < 0 else end + 1
        if limit >= 0:
            end = min(end, self.pos + limit)
        chunk, self.pos = self.data[self.pos:end], end
        self.largest = max(self.largest, len(chunk))
        return chunk

    def __iter__(self):  # an unbounded line iterator: what the old code used
        while True:
            chunk = self.readline()
            if not chunk:
                return
            yield chunk

    def read(self, size: int = -1) -> bytes:
        end = len(self.data) if size < 0 else self.pos + size
        chunk, self.pos = self.data[self.pos:end], end
        self.largest = max(self.largest, len(chunk))
        return chunk


def test_oversized_line_is_refused_without_reading_it_whole(monkeypatch, tmp_path):
    monkeypatch.setattr(sources, 'LINE_MAX_BYTES', 1024)
    data = b'x' * 100_000  # one hostile line, no newline
    spy = _SpyFile(data)
    monkeypatch.setattr(sources, 'open', lambda *a, **k: spy, raising=False)
    with pytest.raises(UnifiedError) as caught:
        sources.read_snapshot(tmp_path / 'matches.jsonl', expected_sha256=hashlib.sha256(data).hexdigest(),
                              expected_lines=1)
    assert caught.value.code == 'PT-UNIFIED-LIMIT'
    assert spy.largest <= 1025
