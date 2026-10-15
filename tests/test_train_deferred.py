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


# ---- D-05 cosmetic operators: the masked-body equality rule is the same in both labellers ------------------------------

SOURCE_COSMETIC = ('ws-comment', 'dead-code', 'reorder-defs', 'local-rename', 'macro-rewrite', 'inline-toggle')
OPT_COSMETIC = ('loop-extract', 'hotcoldsplit', 'mergefunc', 'always-inline', 'partial-inliner')


@pytest.mark.parametrize('op', SOURCE_COSMETIC)
def test_cosmetic_target_with_changed_masked_body_disagrees_in_mutation_labels(op):
    def facts(eq):
        return [ML.FunctionFact('t', True, True, eq)]
    (d,) = ML.label_mutation(op, 't', facts(False))
    assert (d.label, d.change_kind, d.check) == ('cosmetic', op, 'disagree') and 'masked body' in d.note
    (d,) = ML.label_mutation(op, 't', facts(True))
    assert (d.label, d.check) == ('cosmetic', 'ok')
    (d,) = ML.label_mutation(op, 't', facts(None))           # not comparable is not accepted, as for semantic
    assert d.check == 'disagree'


@pytest.mark.parametrize('op', OPT_COSMETIC)
def test_opt_pass_operators_restructure_code_by_design(op):
    (d,) = ML.label_mutation(op, 't', [ML.FunctionFact('t', True, True, False)])
    assert (d.label, d.check) == ('cosmetic', 'ok')


@pytest.mark.parametrize('op', SOURCE_COSMETIC)
@pytest.mark.parametrize('body, check', [('identical', 'ok'), ('address-only', 'ok'), ('different', 'disagree')])
def test_cosmetic_target_rule_matches_in_the_pair_labeller(tmp_path, op, body, check):
    raw, masked = {'identical': ('r1', 'm1'), 'address-only': ('r2', 'm1'), 'different': ('r2', 'm2')}[body]
    old, new = pair(tmp_path, SRC_OLD, raw, masked)
    (rec,) = LB.label_construction(old, new, label_source='x', semantic=False, declared={'f': ('cosmetic', op)})
    assert (rec['label'], rec['check']) == ('cosmetic', check)
