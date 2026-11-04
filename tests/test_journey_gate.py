"""Unit checks of tools/journey_gate.py (summary shape and failure exit); no Qt, no journey run."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import journey_gate  # noqa: E402


def test_summary_counts_and_shape():
    summary = journey_gate.summarize([(0, 1.0), (1, 2.5), (0, 0.5)])
    assert (summary['runs'], summary['passed'], summary['failed']) == (3, 2, 1)
    assert summary['durations'] == [1.0, 2.5, 0.5] and 'not live evidence' in summary['evidence_class']


def test_gate_writes_summary_and_fails_when_a_run_fails(tmp_path, monkeypatch):
    codes = iter([0, 1])
    monkeypatch.setattr(journey_gate, 'run_once', lambda *_: (next(codes), 0.1))
    out = tmp_path / 'sub' / 'summary.json'
    assert journey_gate.main(['--repeat', '2', '--out', str(out)]) == 1
    data = json.loads(out.read_text(encoding='utf-8'))
    assert data['runs'] == 2 and data['failed'] == 1
