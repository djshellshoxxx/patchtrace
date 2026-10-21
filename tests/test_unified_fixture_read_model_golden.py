"""UNVERIFIED read-model golden test. Publishes synthetic rows through the real sidecar writer.

Only stable, user-visible fields are projected; paths, digests and timestamps are checked elsewhere.
The golden is read-only during tests and cannot be silently regenerated to hide a changed result.
"""
from __future__ import annotations

import json
from pathlib import Path

from unified_read_support import contested_row, make_facts, make_row, publish, request

from patchtrace.unified import read_model as rm


def test_authored_read_model_golden(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "unified" / "synthetic_read_model.json"
    expected = json.loads(fixture.read_text(encoding="utf-8"))
    before = fixture.read_bytes()
    empty = rm.load_unified(rm.UnifiedLoadRequest(None))
    progress = rm.progress_model(rm.UnifiedLoadRequest("synthetic-project"), "match", 3, 10)
    review = make_row([(0x1000, "constant")], [(0x1080, "constant")],
                      materiality="review", classes=("constant",))
    conflict = contested_row(0x1100, 0x1180, "conflict")
    equal = make_row([(0x1200, "equal")], [(0x1280, "equal")], materiality="unchanged")
    facts = (make_facts(review, "review"), make_facts(equal, "unchanged", proof="UNCH/1"))
    loaded = publish(tmp_path / "golden", (review, conflict, equal), facts)
    vm = rm.load_unified(request(loaded, extraction_configured=True))
    actual = {
        "state": vm.state, "display_level": vm.display_level, "summary": rm.summary_text(vm),
        "rows": [{"label": r.function_label, "address": r.address_label, "decision": r.decision,
                  "glyph": r.glyph, "change": r.materiality, "collapsed": r.collapsed} for r in vm.rows],
    }
    assert {"state": empty.state, "text": empty.state_text} == expected["empty"]
    assert {"state": progress.state, "text": progress.state_text} == expected["progress"]
    assert actual == expected["published"]
    assert fixture.read_bytes() == before
    assert vm.rows[0].decision == "contested" and vm.rows[0].collapsed is False
