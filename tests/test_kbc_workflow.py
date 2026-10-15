"""K2: the pure investigation reducer (KB-integration-plan 7.5). Synthetic ids only; no I/O."""
from __future__ import annotations

import ast
import inspect

import pytest

from patchtrace.kbcorrelation import workflow
from patchtrace.kbcorrelation.contracts import InvestigationRevision, Lead
from patchtrace.kbcorrelation.errors import KbcIssue
from patchtrace.kbcorrelation.workflow import Event, reduce

INV = '00000000-0000-4000-8000-0000000000a1'
SCOPE = 'a' * 64
PAIR = 'b' * 64
PLAN = 'c' * 64


def first(kind: str = 'kb', state: str = 'NEW') -> InvestigationRevision:
    return InvestigationRevision(investigation_id=INV, revision=1, lead=Lead(kind=kind, value='KB5099001',
                                                                              raw='kb5099001'), state=state)


def step(snapshot: InvestigationRevision, kind: str, **fields) -> InvestigationRevision:
    result = reduce(snapshot, Event(kind, snapshot.revision, **fields))
    assert isinstance(result, InvestigationRevision), result
    return result


def walk(snapshot, *steps):
    for kind, fields in steps:
        snapshot = step(snapshot, kind, **fields)
    return snapshot


KB_PATH = (
    ('lead_parsed', {}),
    ('search_done', {'outcome': 'METADATA_READY', 'scope_ids': (SCOPE,), 'coverage_ids': ('d' * 64,)}),
    ('product_selected', {'scope_id': SCOPE}),
    ('components_ready', {}),
    ('pair_proposed', {'outcome': 'PAIR_PROPOSED', 'pair_id': PAIR}),
    ('pair_approved', {}),
    ('plan_ready', {'plan_sha': PLAN}),
    ('acquire_started', {'plan_sha': PLAN}),
    ('bytes_verified', {'parsed': True, 'both_sides': True}),
    ('project_created', {'both_sides': True}),
    ('context_attached', {}),
    ('comparison_pending', {}),
    ('analyzed', {}),
    ('leads_ready', {}),
)


def test_kb_lead_walks_to_leads_ready_with_a_linear_history():
    snapshot = first()
    seen = [snapshot]
    for kind, fields in KB_PATH:
        snapshot = step(snapshot, kind, **fields)
        seen.append(snapshot)
    assert snapshot.state == 'LEADS_READY'
    assert [s.revision for s in seen] == list(range(1, len(KB_PATH) + 2))
    assert all(s.parent == s.revision - 1 for s in seen[1:])
    assert snapshot.selected_scope_id == SCOPE and snapshot.selected_pair_id == PAIR and snapshot.plan_sha == PLAN


def test_manual_file_lead_skips_search_and_product_and_local_files_skip_the_plan():
    snapshot = walk(first('file'), ('lead_parsed', {}), ('pair_proposed', {'outcome': 'PAIR_PROPOSED', 'pair_id': PAIR}),
                    ('pair_approved', {}), ('bytes_verified', {'parsed': True, 'both_sides': True}))
    assert snapshot.state == 'BYTES_VERIFIED' and snapshot.plan_sha is None


def test_reduce_never_mutates_and_is_deterministic():
    snapshot = first()
    before = snapshot.model_dump_json()
    a = reduce(snapshot, Event('lead_parsed', 1))
    b = reduce(snapshot, Event('lead_parsed', 1))
    assert snapshot.model_dump_json() == before and a == b and a.revision == 2


@pytest.mark.parametrize('outcome', ['METADATA_READY', 'METADATA_PARTIAL', 'NOT_OBSERVED', 'SCOPE_REQUIRED'])
def test_search_outcomes_are_the_four_searched_substates(outcome):
    snapshot = walk(first(), ('lead_parsed', {}), ('search_done', {'outcome': outcome, 'warnings': ('PARTIAL',)}))
    assert snapshot.state == outcome and snapshot.warnings == ('PARTIAL',)


@pytest.mark.parametrize('outcome', ['NEEDS_OLDER', 'NEEDS_NEWER', 'LINEAGE_BLOCKED', 'NEEDS_PAIR_SELECTION'])
def test_blocked_pair_outcomes_carry_no_selected_pair(outcome):
    snapshot = walk(first('file'), ('lead_parsed', {}), ('pair_proposed', {'outcome': outcome}))
    assert snapshot.state == outcome and snapshot.selected_pair_id is None


def test_a_wider_search_is_a_new_search_and_clears_downstream_choices():
    snapshot = walk(first(), *KB_PATH[:5])
    assert snapshot.selected_pair_id == PAIR
    again = step(snapshot, 'product_selected', scope_id=SCOPE)
    assert again.state == 'PRODUCT_SELECTED' and again.selected_pair_id is None


@pytest.mark.parametrize(('state', 'kind', 'fields'), [
    ('NEW', 'search_done', {'outcome': 'METADATA_READY'}),
    ('LEAD_PARSED', 'pair_approved', {}),
    ('PAIR_PROPOSED', 'plan_ready', {'plan_sha': PLAN}),
    ('PLAN_READY', 'project_created', {'both_sides': True}),
    ('BYTES_VERIFIED', 'analyzed', {}),
    ('LEADS_READY', 'lead_parsed', {}),
    ('ACQUIRING', 'product_selected', {'scope_id': SCOPE}),
], ids=['search-first', 'approve-unproposed', 'plan-unapproved', 'create-unverified', 'analyze-uncompared',
        'leads-restart', 'product-while-acquiring'])
def test_an_event_outside_its_state_is_a_state_issue(state, kind, fields):
    snapshot = first().model_copy(update={'state': state})
    result = reduce(snapshot, Event(kind, 1, **fields))
    assert isinstance(result, KbcIssue) and result.code == 'PT-KBC-STATE'


def test_stale_generation_and_unknown_events_are_dropped_not_applied():
    snapshot = step(first(), 'lead_parsed')
    stale = reduce(snapshot, Event('search_done', 1, outcome='NOT_OBSERVED'))
    assert isinstance(stale, KbcIssue) and stale.code == 'PT-KBC-STALE'
    unknown = reduce(snapshot, Event('format_disk', snapshot.revision))
    assert isinstance(unknown, KbcIssue) and unknown.code == 'PT-KBC-INPUT'


@pytest.mark.parametrize('fields', [{'parsed': True, 'both_sides': False}, {'parsed': False, 'both_sides': True}, {}],
                         ids=['one-side', 'unparsed', 'nothing'])
def test_bytes_verified_needs_both_files_hashed_and_parsed(fields):
    snapshot = walk(first(), *KB_PATH[:8])
    result = reduce(snapshot, Event('bytes_verified', snapshot.revision, **fields))
    assert isinstance(result, KbcIssue) and result.code == 'PT-KBC-STATE'


def test_project_created_needs_both_sides_verified():
    snapshot = walk(first(), *KB_PATH[:9])
    assert snapshot.state == 'BYTES_VERIFIED'
    refused = reduce(snapshot, Event('project_created', snapshot.revision))
    assert isinstance(refused, KbcIssue)


def test_a_product_outside_the_investigation_scopes_is_refused():
    snapshot = walk(first(), ('lead_parsed', {}), ('search_done', {'outcome': 'METADATA_READY',
                                                                  'scope_ids': (SCOPE,)}))
    refused = reduce(snapshot, Event('product_selected', snapshot.revision, scope_id='e' * 64))
    assert isinstance(refused, KbcIssue) and refused.code == 'PT-KBC-STATE'


def test_the_plan_that_was_consented_to_is_the_plan_that_acquires():
    snapshot = walk(first(), *KB_PATH[:7])
    assert snapshot.state == 'PLAN_READY'
    refused = reduce(snapshot, Event('acquire_started', snapshot.revision, plan_sha='f' * 64))
    assert isinstance(refused, KbcIssue)


def test_cancel_restores_the_previous_committed_snapshot_as_a_new_revision():
    snapshot = walk(first(), *KB_PATH[:8])
    assert snapshot.state == 'ACQUIRING'
    previous = walk(first(), *KB_PATH[:6])  # PAIR_APPROVED, revision 7
    restored = step(snapshot, 'cancel', restore=previous)
    assert restored.state == 'PAIR_APPROVED' and restored.plan_sha is None
    assert restored.revision == snapshot.revision + 1 and restored.parent == snapshot.revision
    assert 'cancelled' in restored.warnings[-1]


def test_cancel_refuses_a_foreign_or_future_snapshot():
    snapshot = walk(first(), *KB_PATH[:8])
    foreign = first().model_copy(update={'investigation_id': '00000000-0000-4000-8000-0000000000a2'})
    assert isinstance(reduce(snapshot, Event('cancel', snapshot.revision, restore=foreign)), KbcIssue)
    assert isinstance(reduce(snapshot, Event('cancel', snapshot.revision, restore=snapshot)), KbcIssue)
    assert isinstance(reduce(snapshot, Event('cancel', snapshot.revision)), KbcIssue)


def test_a_failure_after_project_created_is_context_pending_and_can_still_attach():
    snapshot = walk(first(), *KB_PATH[:10])
    assert snapshot.state == 'PROJECT_CREATED'
    pending = step(snapshot, 'context_pending')
    assert pending.state == 'CONTEXT_PENDING'
    assert step(pending, 'context_attached').state == 'CONTEXT_ATTACHED'


def test_the_reducer_module_is_pure():
    imported = set()
    for node in ast.walk(ast.parse(inspect.getsource(workflow))):
        if isinstance(node, ast.Import):
            imported |= {a.name.split('.')[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module.split('.')[0])
    assert not imported & {'sqlite3', 'os', 'socket', 'urllib', 'PySide6', 'time', 'datetime', 'pathlib'}
