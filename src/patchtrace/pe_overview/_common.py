"""Shared inspection context: bounded reads, warnings and cancellation."""
from __future__ import annotations

from collections.abc import Callable

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.hostile_text import is_hostile

from .models import Limits, PeWarning

MAX_STRUCT_READ = 1024 * 1024
_LATIN1_HOSTILE = {b: '?' for b in range(256) if is_hostile(chr(b))}


class Cancelled(Exception):
    """Internal control flow only; never escapes ``inspect_pe``."""


def clean_text(raw: bytes) -> str:
    """Latin-1 decode with control and format characters (the shared hostile rule) replaced by '?', safe to show in
    a UI."""
    return raw.decode('latin-1').translate(_LATIN1_HOSTILE)


class Ctx:
    def __init__(self, reader: VerifiedArtifactReader, cancel: Callable[[], bool] | None, limits: Limits):
        self.reader = reader
        self.cancel = cancel
        self.limits = limits
        self.warnings: list[PeWarning] = []
        self.entropy_spent = 0  # bytes measured so far, against the per-file budget of `entropy.py`
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

    def cstring(self, offset: int, limit: int | None = None) -> tuple[str, bool] | None:
        """Bounded NUL-terminated string at a file offset: (text, truncated) or None if unreadable.

        `limit` bounds the read to the bytes that are contiguously mapped at the string's RVA,
        so a string cannot run into unrelated file data after its section ends. A string without a
        terminator is cut by whichever limit comes first, and the warning names that one (PE-8); one
        that runs to the end of the file is returned whole.
        """
        cap = self.limits.max_name_length
        data = self.read(offset, cap + 1 if limit is None else min(cap + 1, limit))
        if not data:
            return None
        end = data.find(b'\0')
        if end >= 0:
            return clean_text(data[:end]), False
        if len(data) > cap:
            self.warn('name_truncated', f'a name longer than {cap} bytes was truncated')
            return clean_text(data[:cap]), True
        if offset + len(data) >= self.reader.size:
            return clean_text(data), False
        if limit is not None and len(data) == limit:
            where = f'before its section data ends; cut there after {len(data)} bytes'
        else:
            where = f'within the {len(data)} bytes of one read; cut there'
        self.warn('name_truncated', f'a name has no terminator {where} (the name limit is {cap})')
        return clean_text(data), True
