"""Encoding boundary fixtures are read as bytes to preserve BOM and CRLF."""
from __future__ import annotations

from pathlib import Path

import pytest
from kbc_k1_support import NOW, no_sockets  # noqa: F401 - pytest fixture registration

from patchtrace.kbcorrelation.sources.cvrf import SourceError
from patchtrace.kbcorrelation.sources.importer import import_bytes

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"
pytestmark = pytest.mark.usefixtures("no_sockets")


def test_bom_fixture_is_rejected_before_import() -> None:
    raw = (ROOT / "cvrf_bom.json").read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    with pytest.raises(SourceError, match="byte order mark"):
        import_bytes(raw, now=NOW)


def test_crlf_fixture_imports_without_lone_lf() -> None:
    raw = (ROOT / "cvrf_crlf.json").read_bytes()
    assert b"\r\n" in raw
    assert raw.replace(b"\r\n", b"").find(b"\n") == -1
    imported = import_bytes(raw, now=NOW)
    assert imported.source.release_id == "2099-Feb"
    assert imported.source.dialect == "cvrf-json/0"
