"""Shared trackers stay readable UTF-8 text.

Regression for d99cd77, which replaced ``tasks/todo.md`` with a truncated
base64 dump of a tool output (``file`` reported "data"). Every coordinator
and worker appends to these files, so a binary blob silently blocks all
tracker updates and loses history.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRACKERS = ("tasks/todo.md", "docs/qa.md", "docs/modules.md", "docs/specs/REGISTRY.md")
# A tool banner that leaked into d99cd77 ahead of the base64 payload.
_BANNERS = ("Warning: truncated output", "Warningtruncatedoutput", "original token count")
_CUT = re.compile(r"\u2026\d+ tokens truncated\u2026|\.\.\.\d+ tokens truncated\.\.\.")


@pytest.mark.parametrize("rel", TRACKERS, ids=["todo", "qa", "modules", "registry"])
def test_tracker_is_utf8_markdown(rel: str) -> None:
    data = (ROOT / rel).read_bytes()
    assert data, f"{rel} is empty"
    text = data.decode("utf-8")  # raises on a binary blob
    assert "\x00" not in text
    assert text.lstrip().startswith("#"), f"{rel} must start with a Markdown heading"
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\n\r\t")
    assert control == 0, f"{rel} has {control} control characters"
    for banner in _BANNERS:
        assert banner not in text[:500], f"{rel} starts with a tool banner"
    # docs/qa.md lost 744 lines to a head+tail cut joined by this marker (08f6a5f, b8e0a67).
    assert not _CUT.search(text), f"{rel} contains a truncation marker: content between head and tail is missing"
