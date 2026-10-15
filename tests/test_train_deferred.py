"""LBL-26 pre-lock audit, deferred items D-04, D-05, D-07..D-11 and the T-03 leftovers (preregistration file check,
single-use locked run). SYNTHETIC data only: no network, no target binary is executed."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.mutations import labels as ML  # noqa: E402
from tools.calibration.tier_r import labeler as LB  # noqa: E402
from tools.calibration.tier_r.debuginfo import ImageFunction, Inventory  # noqa: E402

SRC_OLD = 'int f(int x)\n{\n    return x + 1;\n}\n'
SRC_NEW = 'int f(int x)\n{\n    return x + 2;\n}\n'


def side(tmp_path: Path, name: str, text: str, raw: str, masked: str) -> LB.SideData:
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    (root / 'a.c').write_text(text, encoding='utf-8')
    fn = ImageFunction('f', 'a.c', 'a.c', 1, 0x1000, 16, None, 'a.o', 'project')
    return LB.SideData(None, Inventory(functions=[fn]), {0x1000: (raw, masked)}, root)


def pair(tmp_path, new_text, new_raw, new_masked):
    return (side(tmp_path, 'old', SRC_OLD, 'r1', 'm1'), side(tmp_path, 'new', new_text, new_raw, new_masked))


# ---- D-04 a declared change that the evidence calls ambiguous is not an agreement -------------------------------------

def test_declared_change_with_ambiguous_evidence_is_not_checked_ok(tmp_path):
    old, new = pair(tmp_path, SRC_NEW, 'r2', 'm1')          # source changed, masked body equal -> ambiguous
    (rec,) = LB.label_diff(old, new, label_source='source-diff', declared_changed={'f': 'source-diff'})
    assert rec['label'] == 'ambiguous'
    assert rec['check'] == 'unchecked' and 'not verified' in rec['notes']


def test_declared_change_with_agreeing_evidence_stays_ok_and_disagree_stays_disagree(tmp_path):
    old, new = pair(tmp_path, SRC_NEW, 'r2', 'm2')
    (rec,) = LB.label_diff(old, new, label_source='source-diff', declared_changed={'f': 'source-diff'})
    assert (rec['label'], rec['check']) == ('changed', 'ok')
    old, new = pair(tmp_path, SRC_OLD, 'r1', 'm1')
    (rec,) = LB.label_diff(old, new, label_source='source-diff', declared_changed={'f': 'source-diff'})
    assert (rec['label'], rec['check']) == ('unchanged', 'disagree')
