"""Adapters: diff-engine output -> the accuracy scoring input (`{case_id: [function, ...] | None}`).

Each adapter exposes `parse(source) -> list[str]`, changed function names ranked most-changed first (ties by name),
unchanged functions excluded, added/removed-only functions after the changed ones. `source` is text or bytes
content, or an `os.PathLike` (read through pathguard.confine). See docs/research/adapters.md for the formats and
which of them are verified.
"""
from __future__ import annotations

from . import bindiff, ghidriff, rizin
from ._common import normalise_name

PARSERS = {'ghidriff': ghidriff.parse, 'bindiff': bindiff.parse, 'rizin': rizin.parse}

__all__ = ['PARSERS', 'bindiff', 'ghidriff', 'normalise_name', 'rizin']
