"""SPEC-31 S3b: the decompile path on REAL output. The IR is the recorded Ghidra 12.0.4 output of the clang probe pair
(tests/fixtures/unified/PROVENANCE.json); the decompiler text is the C that Ghidra 12.0.4 printed for the same two
functions of the MinGW build of the same sources (recorded 2026-10-14 with the repository's own `decompile` mode over
the retained GZF, docs/qa.md [S3b:decompile]): the literals of the edits are the same in both builds."""
from __future__ import annotations

import pytest
from test_unified_gu_mutants import recorded
from unified_facts_builder import decided

from patchtrace.unified import keys
from patchtrace.unified.addressing import AddressMap, PeLayout
from patchtrace.unified.facts import verdict
from patchtrace.unified.facts.channels import FactsContext
from patchtrace.unified.facts.irchannels import IrSides
from patchtrace.unified.facts.refacts import select_for_decompile

ADD_CLAMPED_OLD = '''
int add_clamped(int param_1,int param_2)

{
  int iVar1;

                    /* 0x1390  1  add_clamped */
  iVar1 = param_1 + param_2;
  if (iVar1 < -1000) {
    iVar1 = -1000;
  }
  if (1000 < iVar1) {
    iVar1 = 1000;
  }
  return iVar1;
}

'''
ADD_CLAMPED_NEW = ADD_CLAMPED_OLD.replace('(1000 < iVar1)', '(0x400 < iVar1)').replace('iVar1 = 1000;', 'iVar1 = 0x400;')
DISPATCH_OLD = '''
uint dispatch(undefined4 param_1,uint param_2)

{
  uint uVar1;

                    /* 0x13b0  2  dispatch */
  switch(param_1) {
  case 0:
    return param_2 + 1;
  case 1:
    return param_2 * 3;
  case 2:
    return param_2 - 7;
  case 3:
    return param_2 ^ 0x55;
  case 4:
    return param_2 * 4;
  case 5:
    uVar1 = -param_2;
    break;
  case 6:
    return param_2 + 100;
  default:
    uVar1 = 0;
  }
  return uVar1;
}

'''
DISPATCH_NEW = DISPATCH_OLD.replace('0x55', '0x56')
EDITED = ('add_clamped', 'dispatch')


@pytest.fixture
def judged(tmp_path):
    """`judged(decompiled)` -> {name: (pair, Judged)} over the recorded clang probe pair, matched by name; the
    argument maps a function name to (older text, newer text)."""
    old, tables_old, data_old = recorded(tmp_path, 'probe_old')
    new, tables_new, data_new = recorded(tmp_path, 'probe_new')

    def names(reader):
        return {reader.functions.name[i]: reader.functions.get('rva', i) for i in range(reader.functions.n)}
    no, nn = names(old), names(new)
    rows = [decided(no[name], nn[name]) for name in sorted(no) if name in nn]
    layout = lambda reader: PeLayout(image_base=reader.manifest.image_base,  # noqa: E731
                                     size_of_image=reader.manifest.size_of_image)
    sides = IrSides(old, new, tuple((s.start, s.end) for s in tables_old.sections),
                    tuple((s.start, s.end) for s in tables_new.sections))
    by_rva = {rva: name for name, rva in no.items()}

    def judge(decompiled=None):
        texts = None if decompiled is None else {'older': {no[name]: pair[0] for name, pair in decompiled.items()},
                                                 'newer': {nn[name]: pair[1] for name, pair in decompiled.items()}}
        context = FactsContext.build(older_sha256=data_old['sha256'], newer_sha256=data_new['sha256'],
                                     addr=AddressMap(layout(old), layout(new)), matches=[], rows=rows, bindiff_flags={},
                                     ir_sides=sides, decompiled=texts)
        return {by_rva[row.pair[0]]: (row.pair, verdict.judge(
            keys.row_id(data_old['sha256'], data_new['sha256'], row.older, row.newer), row.decision,
            context.collect(row))) for row in rows}
    return judge


def test_the_two_constant_edits_are_selected_and_become_material_with_the_real_decompiler_text(judged):
    before = judged()
    assert before['add_clamped'][1].facts.verdict == before['dispatch'][1].facts.verdict == 'review'
    chosen = select_for_decompile(before.values())
    assert sorted(before[name][0] for name in EDITED) == sorted(chosen)             # not `say`, not `use_data`
    after = judged({'add_clamped': (ADD_CLAMPED_OLD, ADD_CLAMPED_NEW), 'dispatch': (DISPATCH_OLD, DISPATCH_NEW)})
    for name in EDITED:
        facts = after[name][1].facts
        assert (facts.verdict, facts.second_channel) == ('material', 'C6'), name
        assert dict(facts.channels)['C6'] == 'differs' and {d.cls for d in facts.deltas} == {'constant'}
    untouched = {name: (j.facts.verdict, j.facts.proof) for name, (_p, j) in after.items() if name not in EDITED}
    assert untouched == {name: (j.facts.verdict, j.facts.proof) for name, (_p, j) in before.items() if name not in EDITED}


def test_the_unchanged_text_leaves_the_rows_in_review(judged):
    """The decompiler printed the same C for both builds: it does not show the change, so nothing is promoted."""
    after = judged({'add_clamped': (ADD_CLAMPED_OLD, ADD_CLAMPED_OLD), 'dispatch': (DISPATCH_OLD, DISPATCH_OLD)})
    for name in EDITED:
        facts = after[name][1].facts
        assert (facts.verdict, facts.second_channel) == ('review', None) and dict(facts.channels)['C6'] == 'equal'


def test_text_of_another_function_edit_does_not_anchor_this_one(judged):
    after = judged({'add_clamped': (DISPATCH_OLD, DISPATCH_NEW), 'dispatch': (ADD_CLAMPED_OLD, ADD_CLAMPED_NEW)})
    for name in EDITED:
        assert after[name][1].facts.verdict == 'review'                     # the literals shown are not the ones edited
