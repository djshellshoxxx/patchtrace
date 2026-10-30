"""Encoding boundary fixtures are read as bytes to preserve BOM and CRLF."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"


def test_bom_fixture_starts_with_utf8_bom() -> None:
    raw = (ROOT / "cvrf_bom.json").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")


def test_crlf_fixture_contains_crlf_without_lone_lf() -> None:
    raw = (ROOT / "cvrf_crlf.json").read_bytes()
    assert b"\r\n" in raw
    assert raw.replace(b"\r\n", b"").find(b"\n") == -1
