"""A-28: a Ghidriff one-to-many abstention is never scored by tier-R or the attention lead list. SYNTHETIC Ghidriff JSON
(hand-built); it checks the failure rule, not live engine evidence.

`tier-r-engine-output/1` has no field for an abstention next to `implicit_unchanged`: scoring the pair would leave the
abstained functions unmentioned, so `implicit_unchanged` would credit them as paired-correct and unchanged (an invented
score), and the attention view would turn a one-sided row into an `old_only` vote. Both providers therefore report the
pair `failed` with a one-to-many reason, and the report carries no metrics for it.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from test_tier_r_eval_metrics import FUNCS, make_labels

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.evalcore.engines import attention  # noqa: E402
from tools.calibration.evalcore.engines import ghidriff as G  # noqa: E402
from tools.calibration.tier_r import evaluate as E  # noqa: E402

BASE = 0x180000000
LABELS = make_labels(FUNCS, pair_id='syn-1ton')
OLD_CODE = 'int f(char *b, int n, int i) {\n  return b[i];\n}'
NEW_CODE = 'int f(char *b, int n, int i) {\n  if (i >= n) {\n    return -1;\n  }\n  return b[i];\n}'


def _fn(name, rva, code=OLD_CODE):
    return {'name': name, 'fullname': name, 'address': f'{BASE + rva:x}', 'code': code}


def _ghidriff(one_to_many: bool):
    """C changes (a bounds guard); with `one_to_many` Ghidriff also pairs the same C record with D's newer function."""
    mod = [{'old': _fn('C', 0x1020), 'new': _fn('C', 0x1020, NEW_CODE), 'ratio': 0.75,
            'match_types': ['ExactBytes'], 'diff_type': ['code']}]
    if one_to_many:
        mod.append({'old': copy.deepcopy(mod[0]['old']), 'new': _fn('D', 0x1030, NEW_CODE), 'ratio': 0.4,
                    'match_types': ['StructuralGraphHash'], 'diff_type': ['code', 'name']})
    return {'old_meta': {'Executable SHA256': LABELS.older.sha256},
            'new_meta': {'Executable SHA256': LABELS.newer.sha256},
            'functions': {'added': [_fn('H', 0x1070, None)], 'deleted': [_fn('G', 0x1060, None)], 'modified': mod}}


def _place(tmp_path, raw):
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / 'syn-1ton.ghidriff.json').write_text(json.dumps(raw), encoding='utf-8', newline='\n')
    return tmp_path


@pytest.mark.parametrize('provider', [G.GhidriffImportProvider, attention.AttentionProvider],
                         ids=['ghidriff', 'attention'])
def test_one_to_many_pair_is_failed_with_an_honest_reason(tmp_path, provider):
    out = provider(_place(tmp_path, _ghidriff(True)))(LABELS, 'hidden')
    assert out.status == 'failed' and 'one-to-many' in out.reason and '3 functions abstained' in out.reason
    assert 'repeated' not in out.reason
    assert out.predictions == () and out.old_only == frozenset() and out.new_only == frozenset()


def test_abstained_rows_never_reach_implicit_unchanged_credit(tmp_path):
    clean = E.evaluate([LABELS], [G.GhidriffImportProvider(_place(tmp_path / 'a', _ghidriff(False))),
                                  attention.AttentionProvider(tmp_path / 'a')], b_count=20)
    assert {e['engine']: e['status'] for e in clean['engines']} == {'ghidriff': 'ok', 'attention': 'ok'}
    assert 'ghidriff' in clean['strata']['authored']  # the control: the clean pair is scored
    doc = E.evaluate([LABELS], [G.GhidriffImportProvider(_place(tmp_path / 'b', _ghidriff(True))),
                                attention.AttentionProvider(tmp_path / 'b')], b_count=20)
    assert {e['engine']: e['status'] for e in doc['engines']} == {'ghidriff': 'failed', 'attention': 'failed'}
    assert all(p['metrics'] is None and 'one-to-many' in p['reason'] for p in doc['pairs'])
    assert doc['strata'] == {}  # no paired-correct, unchanged or old_only credit for C, the newer C or D
