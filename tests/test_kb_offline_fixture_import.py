"""Offline fixture imports fail immediately if any socket operation is attempted."""
from __future__ import annotations

from pathlib import Path

import pytest

from kbc_k1_support import import_doc
from patchtrace.kbcorrelation.sources.cvrf import parse_cvrf

ROOT = Path(__file__).resolve().parent / "fixtures" / "kb"
pytestmark = pytest.mark.usefixtures("no_sockets")


def test_local_import_and_parse_need_no_network() -> None:
    """The baseline fixture is parsed from bytes already on disk with socket operations denied."""
    payload = (ROOT / "cvrf_v3_synthetic.json").read_text(encoding="utf-8")
    import json

    wrapper = json.loads(payload)
    raw = json.dumps(wrapper["documents"][0]["document"]).encode("utf-8")
    parsed = parse_cvrf(raw)
    imported = import_doc(wrapper["documents"][0]["document"])
    assert parsed.release_id == imported.source.release_id
