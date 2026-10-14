"""Shared inspection context: bounded reads, warnings and cancellation."""
from __future__ import annotations

from collections.abc import Callable

from patchtrace.artifact_bytes import VerifiedArtifactReader

from .models import Limits, PeWarning

MAX_STRUCT_READ = 1024 * 1024


class Cancelled(Exception):
    """Internal control flow only; never escapes ``inspect_pe``."""


def clean_text(raw: bytes) -> str:
    """Latin-1 decode with control characters replaced, safe to show in a UI."""
    return ''.join(chr(b) if 0x20 <= b != 0x7F else '?' for b in raw)


class Ctx:
    def __init__(self, reader: VerifiedArtifactReader, cancel: Callable[[], bool] | None, limits: Limits):
        self.reader = reader
        self.cancel = cancel
        self.limits = limits
        self.warnings: list[PeWarning] = []
        self._seen: set[str] = set()

    def check(self) -> None:
        if self.cancel is not None and self.cancel():
            raise Cancelled

    def warn(self, code: str, message: str) -> None:
        if code not in self._seen:
            self._seen.add(code)
            self.warnings.append(PeWarning(code, message))

    def read(self, offset: int, length: int) -> bytes:
        """Clipped read; returns b'' when the offset is outside the file."""
        if offset < 0 or length <= 0 or offset >= self.reader.size:
            return b''
        return self.reader.read(offset, min(length, MAX_STRUCT_READ))

    def cstring(self, offset: int) -> tuple[str, bool] | None:
        """Bounded NUL-terminated string at a file offset: (text, truncated) or None if unreadable."""
        cap = self.limits.max_name_length
        data = self.read(offset, cap + 1)
        if not data:
            return None
        end = data.find(b'\0')
        if end < 0:
            if len(data) <= cap and offset + len(data) >= self.reader.size:
                return clean_text(data), False
            self.warn('name_truncated', f'a name longer than {cap} bytes was truncated')
            return clean_text(data[:cap]), True
        return clean_text(data[:end]), False
