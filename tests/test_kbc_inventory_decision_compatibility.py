"""Independent actual-route controls for inventory decision classification.

All documents, source claims and SQLite mutations belong to disposable fixtures.
No target executes and no remote request occurs.
"""
from __future__ import annotations

import json
import socket

import pytest
import test_kbc_inventory_selection as setup

from patchtrace.kbcorrelation.contracts import AnalystDecision, SourceRef
from patchtrace.kbcorrelation.store import WorkspaceStore


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('independent inventory compatibility control must stay offline')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, refuse)


def _decision_bytes(ws, investigation):
    return tuple(ws.db.execute(
        'SELECT seq,CAST(body AS BLOB) FROM decisions WHERE investigation_id=? ORDER BY seq',
        (investigation,)))


def _assert_successful_replay(svc, state, identity, selected):
    investigation, scope, _ = state
    with WorkspaceStore(svc.root) as ws:
        before = ws.current_revision(investigation)
        decisions = _decision_bytes(ws, investigation)

    result = svc.components(investigation, product=scope, files=[])
    assert result.exit == 0
    assert result.result['state'] == 'COMPONENTS_READY'
    assert len(result.result['hints']) == 1
    hint = result.result['hints'][0]
    assert hint['basename'] == 'review.sys'
    assert hint['inventory_refs'] == selected.result['hint']['inventory_refs']
    with WorkspaceStore(svc.root) as ws:
        after = ws.current_revision(investigation)
        assert after.revision == before.revision + 1
        assert after.parent == before.revision
        assert after.selected_scope_id == before.selected_scope_id == scope
        assert after.coverage_ids == before.coverage_ids
        assert _decision_bytes(ws, investigation) == decisions

    repeated = svc.select_inventory(investigation, *identity, product=scope,
                                    expected_revision=after.revision, assert_scope=True)
    assert repeated.exit == 0
    assert repeated.result['revision'] == after.revision
    with WorkspaceStore(svc.root) as ws:
        assert ws.current_revision(investigation) == after
        assert _decision_bytes(ws, investigation) == decisions


@pytest.mark.parametrize('body_kind', ['many-source-refs', 'multibyte-fields'])
def test_large_valid_unrelated_decision_preserves_inventory_components(tmp_path, body_kind):
    count = 80 if body_kind == 'many-source-refs' else 1
    svc = setup.service(tmp_path, doc=setup.document(builds=('10.0.26100.9001',) * count))
    state = setup.start(svc)
    identity = setup.inventory(svc, tmp_path)
    selected = setup.select(svc, state, identity)

    with WorkspaceStore(svc.root) as ws:
        if body_kind == 'many-source-refs':
            source = next(item for item in ws.sources() if item.kind == 'cvrf-month')
            refs = tuple(SourceRef(doc_id=source.doc_id, pointer=f'/vulnerabilities/{i}/title',
                                   assertion='advisory_fact') for i in range(count))
            decision = AnalystDecision(op='review-sources', prior='unreviewed', next='reviewed',
                                       reason='Individual references to the authored advisory document.',
                                       created_at=setup.NOW, refs=refs)
        else:
            decision = AnalystDecision(op='review-translation', prior='\U0001f9ed' * 1000,
                                       next='\U0001f9ed' * 1000, reason='\U0001f9ed' * 500,
                                       created_at=setup.NOW)
        body = decision.model_dump_json()
        assert len(body.encode('utf-8')) > 8192
        assert AnalystDecision.model_validate_json(body) == decision
        ws.append_decision(state[0], decision)
        assert ws.decisions(state[0])[-1] == decision

    _assert_successful_replay(svc, state, identity, selected)


@pytest.mark.parametrize('body_kind', ['pretty-json', 'escaped-operation'])
def test_equivalent_inventory_json_preserves_components(tmp_path, body_kind):
    svc = setup.service(tmp_path)
    state = setup.start(svc)
    identity = setup.inventory(svc, tmp_path)
    selected = setup.select(svc, state, identity)
    with WorkspaceStore(svc.root) as ws:
        sequence, original = ws.db.execute(
            'SELECT seq,body FROM decisions WHERE investigation_id=?', (state[0],)).fetchone()
        if body_kind == 'pretty-json':
            changed = json.dumps(json.loads(original), indent=2)
        else:
            changed = original.replace('"inventory-select"', '"inventory\\u002dselect"')
        assert changed != original
        assert json.loads(changed) == json.loads(original)
        assert AnalystDecision.model_validate_json(changed) == AnalystDecision.model_validate_json(original)
        # Only this authored fixture bypasses append-only protection to model a
        # stored record whose valid serialization is not the writer's spelling.
        ws.db.execute('DROP TRIGGER decisions_update')
        ws.db.execute('UPDATE decisions SET body=? WHERE seq=?', (changed, sequence))

    _assert_successful_replay(svc, state, identity, selected)
