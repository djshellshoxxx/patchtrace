"""Manual groups cannot be shortened before identity hashing. Real validated records; synthetic project wrapper."""
from types import SimpleNamespace

import pytest

from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.sources import MAX_FUNCTIONS_PER_SIDE, snapshot_from_project


@pytest.mark.parametrize('side', ['older', 'newer'])
@pytest.mark.parametrize('manual_only', [False, True])
def test_oversized_manual_group_is_refused_instead_of_silently_truncated(side, manual_only):
    def functions(artifact, count):
        return [FunctionRecord(artifact_id=artifact, run_id='run-1', name=f'f{i}', address=f'{0x140001000+i:x}')
                for i in range(count)]
    sides = {s: functions(s, MAX_FUNCTIONS_PER_SIDE + 1 if s == side else 1) for s in ('older', 'newer')}
    correction = FunctionMatch(run_id='run-1', category='merged', manual=True, **sides)
    project = SimpleNamespace(matches=[correction])
    with pytest.raises(UnifiedError) as caught:
        snapshot_from_project(project, 'run-1', manual_only=manual_only)
    assert caught.value.code == 'PT-UNIFIED-LIMIT' and caught.value.reason == 'manual-members-cap'


@pytest.mark.parametrize('side', ['older', 'newer'])
def test_manual_group_at_the_snapshot_cap_keeps_every_member(side):
    count = MAX_FUNCTIONS_PER_SIDE
    members = [FunctionRecord(artifact_id=side, run_id='run-1', name=f'f{i}', address=f'{0x140001000+i:x}')
               for i in range(count)]
    correction = FunctionMatch(run_id='run-1', category='unmatched', manual=True, **{side: members})
    snapshot, = snapshot_from_project(SimpleNamespace(matches=[correction]), 'run-1')
    assert len(getattr(snapshot, side)) == count
    assert getattr(snapshot, side)[-1].name == f'f{count-1}'


def test_a_manual_group_in_another_run_does_not_block_the_selected_run():
    members = [FunctionRecord(artifact_id='old', run_id='old-run', name=f'f{i}')
               for i in range(MAX_FUNCTIONS_PER_SIDE + 1)]
    correction = FunctionMatch(run_id='old-run', category='removed', manual=True, older=members)
    assert snapshot_from_project(SimpleNamespace(matches=[correction]), 'selected-run') == ()
