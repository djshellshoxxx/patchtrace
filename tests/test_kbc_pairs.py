"""K3: manual pairs and the local plan (KB-integration-plan 7.2 pair rules, 8.2 KB9 copy, 10.1 step 3). Pure."""
from __future__ import annotations

import pytest

from patchtrace.kbcorrelation import pairs as pr
from patchtrace.kbcorrelation.plan import local_plan

SCOPE = 'a' * 64


def file(sha: str, name: str = 'exampledrv.sys', machine: str = 'amd64') -> pr.LocalFile:
    return pr.LocalFile(sha256=sha * 64, size=1024, basename=name, machine=machine)


def test_two_amd64_files_with_one_name_are_grade_b_tier_e_user_asserted():
    pair = pr.propose_manual(file('1'), file('2'), scope_id=SCOPE)
    assert (pair.grade, pair.tier, pair.bytes_state, pair.lineage_state, pair.fix_boundary) == (
        'B', 'E', 'verified', 'user-asserted', 'unverified')
    assert pair.reason_codes == ('ORDER_UNVERIFIED',) and pair.window == () and pair.window_complete is None
    assert pair.older.origin == 'local-file' and pair.older.authenticity == 'unverified-local-file'


def test_identical_bytes_are_grade_x_identical_content():
    pair = pr.propose_manual(file('1'), file('1'), scope_id=SCOPE)
    assert pair.grade == 'X' and pr.blocking_reasons(pair) == ('IDENTICAL_CONTENT',)
    assert pr.blocking_text(pair) == 'These two files are byte-identical; this file did not change between them.'


def test_a_non_amd64_side_blocks_and_names_the_architecture():
    pair = pr.propose_manual(file('1'), file('2', machine='arm64'), scope_id=SCOPE)
    assert pair.grade == 'X' and pair.bytes_state == 'incompatible'
    assert pr.blocking_text(pair) == 'PatchTrace compares AMD64 PE files; this file is arm64.'


def test_different_names_block_until_confirmed():
    blocked = pr.propose_manual(file('1'), file('2', 'renamed.sys'), scope_id=SCOPE)
    assert blocked.grade == 'X' and pr.blocking_reasons(blocked) == ('NAME_MISMATCH',)
    assert pr.blocking_text(blocked).startswith('The two files have different names.')
    ok = pr.propose_manual(file('1'), file('2', 'renamed.sys'), scope_id=SCOPE, confirm_same_component=True)
    assert ok.grade == 'B' and 'NAME_MISMATCH' not in ok.reason_codes


def test_pair_id_follows_the_files_and_the_scope():
    base = pr.propose_manual(file('1'), file('2'), scope_id=SCOPE)
    assert base.pair_id == pr.propose_manual(file('1'), file('2'), scope_id=SCOPE).pair_id
    assert base.pair_id != pr.propose_manual(file('2'), file('1'), scope_id=SCOPE).pair_id
    assert base.pair_id != pr.propose_manual(file('1'), file('2'), scope_id='b' * 64).pair_id


@pytest.mark.parametrize('code', sorted(pr.REASON_TEXT), ids=lambda c: c.lower())
def test_every_reason_has_plain_copy_without_markup(code):
    text = pr.reason_text(code, arch='arm64', k=3)
    assert text and '<' not in text and '>' not in text and '{' not in text


def test_the_local_plan_makes_no_request_and_is_bound_to_the_pair():
    pair = pr.propose_manual(file('1'), file('2'), scope_id=SCOPE)
    plan = local_plan(pair)
    assert plan.network_requests == 0 and plan == local_plan(pair)
    assert plan.plan_sha != local_plan(pr.propose_manual(file('1'), file('3'), scope_id=SCOPE)).plan_sha
    assert 'no network request' in plan.text and plan.as_dict()['older_sha'] == '1' * 64
