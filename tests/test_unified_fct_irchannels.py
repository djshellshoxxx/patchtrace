"""SPEC-31 S3 audit (card fct): the IR channels on large functions (bounded work, cooperative cancel, 04 I7).

A function may hold up to L-06 instructions (100,000). The callee multiset C4 compared every call target of one side
with every call target of the other (O(calls^2) target-map lookups, 16 s for 4,000 calls per side, never ticking the
budget); per call the call row was searched linearly. Repetition is the normal case (thousands of calls to the same
helper), so the work must grow with the DISTINCT targets, and what remains must observe cancel. Hand-assembled x86-64
through the real ingest; synthetic, never live Ghidra evidence."""
from __future__ import annotations

import threading

import pytest
from unified_facts_builder import NEW_SHA, OLD_SHA, build_reader, function

from patchtrace.unified.facts import irchannels
from patchtrace.unified.facts.datamap import TargetMap
from patchtrace.unified.facts.fnview import load_view
from patchtrace.unified.facts.operands import CallTarget, call_target
from patchtrace.unified.limits import Budget, BudgetExhausted

SIZE = 0x40000                       # the big test image: .text, .rdata, then an executable section from 0x4000
HELPERS = {'helper': 0x1200, 'other': 0x1300}


def views(tmp_path, old_callee, new_callee, *, count):
    helpers = [function(0x1200, [('mov_ri', 'EAX', 1), ('ret',)], name='helper'),
               function(0x1300, [('mov_ri', 'EAX', 2), ('ret',)], name='other')]

    def big(callee):
        items = [item for _ in range(count) for item in (('mov_ri', 'ECX', 5), ('call', callee))]
        return [*helpers, function(0x4000, [*items, ('ret',)], name='f', sym=HELPERS)]
    older = build_reader(tmp_path, 'old', big(old_callee), sha=OLD_SHA, size=SIZE)
    newer = build_reader(tmp_path, 'new', big(new_callee), sha=NEW_SHA, size=SIZE)
    targets = TargetMap(older, newer, [(0x1200, 0x1200), (0x1300, 0x1300), (0x4000, 0x4000)])
    return (load_view(older, 'older', older.functions.rva_to_fid[0x4000]),
            load_view(newer, 'newer', newer.functions.rva_to_fid[0x4000]), targets)


class Counting:
    """Counts the target-map lookups C4 makes."""

    def __init__(self, targets):
        self.targets, self.calls = targets, 0

    def __getattr__(self, name):
        return getattr(self.targets, name)

    def function_state(self, *args, **kwargs):
        self.calls += 1
        return self.targets.function_state(*args, **kwargs)


@pytest.mark.parametrize('new_callee', ['helper', 'other'], ids=['same', 'retargeted'])
def test_c4_work_grows_with_distinct_callees_not_with_calls(tmp_path, new_callee):
    old, new, targets = views(tmp_path, 'helper', new_callee, count=300)
    counting = Counting(targets)
    only_old, only_new = irchannels.callee_leftovers(old, new, counting, (0x4000, 0x4000))
    assert counting.calls <= 4
    if new_callee == 'helper':
        assert (only_old, only_new) == ([], [])
    else:
        assert only_old == [CallTarget('fn', 0x1200)] * 300 and only_new == [CallTarget('fn', 0x1300)] * 300


def test_c4_matching_observes_cancel(tmp_path):
    old, new, targets = views(tmp_path, 'helper', 'other', count=20)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BudgetExhausted):
        irchannels.callee_leftovers(old, new, targets, (0x4000, 0x4000), Budget(cancel=cancel, check_every=1))


def test_the_following_call_of_an_instruction_stays_inside_its_block(tmp_path):
    """F17 asks for the next call of the SAME block after an argument load, NOP padding included or not."""
    items = [('mov_ri', 'ECX', 1), ('nop',), ('mov_ri', 'EDX', 2), ('call', 'helper'), ('cmp_ri', 'ECX', 3),
             ('jcc', 'Z', 'out'), ('mov_ri', 'EAX', 4), ('label', 'out'), ('mov_ri', 'EAX', 5), ('call', 'other'),
             ('ret',)]
    reader = build_reader(tmp_path, 'one', [function(0x1000, items, name='f', sym=HELPERS)], sha=OLD_SHA)
    view = load_view(reader, 'older', 0)
    by_mnemonic = [insn.mnem for insn in view.insns]
    first_call, second_call = (index for index, mnem in enumerate(by_mnemonic) if mnem == 'CALL')
    assert [view.following_call(index) for index in range(first_call)] == [first_call] * first_call   # NOP too
    assert view.following_call(first_call) is None                 # the block ends at the JZ: no call after it there
    assert view.following_call(second_call - 2) is None            # `mov eax, 4` falls into the next block
    assert view.following_call(second_call - 1) == second_call and view.following_call(second_call) is None


def test_call_rows_are_found_by_site(tmp_path):
    old, _new, _targets = views(tmp_path, 'helper', 'helper', count=50)
    calls = [index for index, insn in enumerate(old.insns) if insn.mnem == 'CALL']
    assert len(calls) == 50 and all(call_target(old, index) == CallTarget('fn', 0x1200) for index in calls)
    assert call_target(old, calls[0] - 1) is None
