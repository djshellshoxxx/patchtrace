"""LBL-12 unified adapter. The rows are SYNTHETIC hand-built `unified-match/1` lines: they check the mapping rules
(own engine, abstention, unknown is not negative), never live engine evidence."""
from __future__ import annotations

import sys
from pathlib import Path

from test_tier_r_eval_metrics import FUNCS, make_labels

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.evalcore.engines import unified as U  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402

FIXTURES = ROOT / 'tests' / 'fixtures' / 'known_answer' / 'unified'
LABELS = make_labels(FUNCS, pair_id='syn-uni')


def _out():
    return U.UnifiedProvider(FIXTURES)(LABELS, 'none')


def test_mapping_flags_and_abstentions():
    out = _out()
    assert (out.engine, out.status, out.implicit_unchanged) == ('unified', 'ok', False)
    flags = {p.old_name: p.changed for p in out.predictions}
    assert flags == {'A': False, 'B': False, 'C': True, 'D': True, 'E': False}   # F (unknown) abstains
    assert out.old_only == {0x1060} and out.new_only == {0x1070}
    assert out.ignored_unaddressed == 2                                           # F unknown flag, I/J candidate


def test_scores_and_abstention_is_not_wrong():
    counts, wrong = E.score_pair(LABELS, _out())
    assert wrong == []
    assert (counts['changed_tp'], counts['changed_fn'], counts['changed_fp']) == (2, 0, 0)
    assert counts['identity_fp'] == 0


def test_lead_order_material_before_review():
    keys = sorted((p.order_key, p.old_name) for p in _out().predictions if p.changed)
    assert [name for _, name in keys] == ['C', 'D']


def test_missing_result_is_blocked_not_absent(tmp_path):
    out = U.UnifiedProvider(tmp_path)(LABELS, 'none')
    assert out.status == 'blocked' and 'syn-uni' in out.reason
    assert U.UnifiedProvider(None)(LABELS, 'none').status == 'blocked'


def test_corrupt_rows_fail(tmp_path):
    (tmp_path / 'syn-uni.unified.jsonl').write_text('{"nope": 1}\n', encoding='utf-8', newline='\n')
    assert U.UnifiedProvider(tmp_path)(LABELS, 'none').status == 'failed'
