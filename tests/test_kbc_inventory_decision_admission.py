"""Stored decision admission preserves inventory evidence before service mutations."""
from __future__ import annotations

import json
import sqlite3
import threading

import pytest
import test_kbc_inventory_selection as controls

from patchtrace.kbcorrelation import inventory_selection as selected
from patchtrace.kbcorrelation.contracts import AnalystDecision, SourceRef
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore


def prepared(tmp_path):
    service = controls.service(tmp_path)
    state = controls.start(service)
    identity = controls.inventory(service, tmp_path)
    outcome = controls.select(service, state, identity)
    return service, (state[0], state[1], outcome.result['revision']), identity


def replace_decision(service, state, transform):
    """Only a disposable authored database loses its trigger to represent stored corruption."""
    with WorkspaceStore(service.root) as store:
        sequence, body = store.db.execute('SELECT seq,body FROM decisions WHERE investigation_id=?',
                                         (state[0],)).fetchone()
        store.db.execute('DROP TRIGGER decisions_update')
        replacement = transform(body)
        store.db.execute('UPDATE decisions SET body=? WHERE seq=?', (replacement, sequence))
        return replacement


@pytest.mark.parametrize('style', ['indented', 'spaces', 'escaped-key', 'escaped-value'])
@pytest.mark.parametrize('operation', ['select', 'components'])
def test_equivalent_decision_json_preserves_the_same_selected_claim(tmp_path, style, operation):
    service, state, identity = prepared(tmp_path)

    def reformat(body):
        if style == 'indented':
            return json.dumps(json.loads(body), indent=2)
        if style == 'spaces':
            return json.dumps(json.loads(body), separators=(', ', ': '))
        if style == 'escaped-key':
            return body.replace('"op":', '"o\\u0070":')
        return body.replace('"inventory-select"', '"inventory\\u002dselect"')

    body = replace_decision(service, state, reformat)
    if operation == 'select':
        outcome = controls.select(service, state, identity)
        assert outcome.result['revision'] == state[2]
    else:
        outcome = service.components(state[0], product=state[1], files=[])
        hint, = outcome.result['hints']
        assert hint['basename'] == 'review.sys'
        assert hint['inventory_refs'][0]['entry_id'] == identity[1]
    assert outcome.exit == 0 and outcome.result['state'] == 'COMPONENTS_READY'
    with WorkspaceStore(service.root) as store:
        decision, = selected._decisions(store, state[0])
        assert (decision.import_id, decision.entry_id) == identity
        assert store.db.execute('SELECT body FROM decisions WHERE investigation_id=?',
                                (state[0],)).fetchall() == [(body,)]


@pytest.mark.parametrize('kind', ['empty', 'null', 'array', 'object', 'truncated',
                                  'duplicate-op', 'duplicate-op-last', 'escaped-op-first', 'escaped-op-last'])
def test_unknown_decision_text_refuses_before_component_names_or_revision_are_written(tmp_path, kind):
    service, state, identity = prepared(tmp_path)
    replacement = {'empty': '', 'null': 'null', 'array': '[]', 'object': '{}',
                   'truncated': '{"op": "inventory-select"'}

    def corrupt(body):
        if kind in ('duplicate-op', 'escaped-op-first'):
            key = 'op' if kind == 'duplicate-op' else 'o\\u0070'
            return '{"' + key + '":"component-name",' + body[1:]
        if kind in ('duplicate-op-last', 'escaped-op-last'):
            key = 'op' if kind == 'duplicate-op-last' else '\\u006fp'
            return body[:-1] + ',"' + key + '":"component-name"}'
        return replacement[kind]

    replace_decision(service, state, corrupt)
    with WorkspaceStore(service.root) as store:
        before = tuple(store.db.iterdump())
    with pytest.raises(KbcStoreError) as error:
        service.components(state[0], product=state[1], files=['other.sys'])
    assert error.value.code == 'PT-KBC-VERIFY'
    with WorkspaceStore(service.root) as store:
        assert tuple(store.db.iterdump()) == before
        assert store.current_revision(state[0]).revision == state[2]
    assert service.inventory_details(identity[0]).result['inventory']['import_id'] == identity[0]


@pytest.mark.parametrize(('field', 'value'), [
    ('op', None), ('op', 1), ('op', True), ('op', []), ('op', {}), ('prior', []),
    ('next', {}), ('reason', 0), ('created_at', None), ('contract', []), ('refs', {}),
    ('refs', ['not a reference']), ('refs', [{'doc_id': '0' * 64, 'pointer': 1,
                                         'assertion': 'advisory_fact'}]),
])
def test_unsupported_header_and_reference_types_refuse_before_service_mutation(tmp_path, field, value):
    service, state, _identity = prepared(tmp_path)

    def corrupt(body):
        record = json.loads(body)
        record['op'] = 'review-note'
        record[field] = value
        return json.dumps(record)

    replace_decision(service, state, corrupt)
    with WorkspaceStore(service.root) as store:
        before = tuple(store.db.iterdump())
    with pytest.raises(KbcStoreError) as error:
        service.components(state[0], product=state[1], files=['other.sys'])
    assert error.value.code == 'PT-KBC-VERIFY'
    with WorkspaceStore(service.root) as store:
        assert tuple(store.db.iterdump()) == before


def test_semantically_valid_inventory_body_still_has_the_original_full_body_bound(tmp_path):
    service, state, _identity = prepared(tmp_path)
    body = replace_decision(service, state, lambda raw: ' ' * 8192 + raw)
    assert AnalystDecision.model_validate_json(body).op == selected.SELECTION_OP
    with WorkspaceStore(service.root) as store:
        before = tuple(store.db.iterdump())
    with pytest.raises(KbcStoreError) as error:
        service.components(state[0], product=state[1], files=['other.sys'])
    assert error.value.code == 'PT-KBC-VERIFY'
    with WorkspaceStore(service.root) as store:
        assert tuple(store.db.iterdump()) == before


@pytest.mark.parametrize('suffix', ['x' * 8193, '\u3042' * 3000, '\x00' + 'x' * 8193],
                         ids=['ascii', 'multibyte', 'nul'])
def test_oversized_text_without_an_operation_token_is_refused_before_python_decoding(tmp_path, suffix):
    service, state, _identity = prepared(tmp_path)
    with WorkspaceStore(service.root) as store:
        store.db.execute('INSERT INTO decisions(investigation_id,body) VALUES (?,?)',
                         (state[0], '{"unknown":"' + suffix + '"}'))

        def bounded_decode(raw):
            assert len(raw) <= 8192, 'an oversized unknown decision crossed the SQL projection'
            return raw.decode('utf-8')

        store.db.text_factory = bounded_decode
        with pytest.raises(KbcStoreError) as error:
            selected._decisions(store, state[0])
        assert error.value.code == 'PT-KBC-VERIFY'


def test_unrelated_valid_decisions_do_not_consume_the_inventory_claim_limit(tmp_path, monkeypatch):
    service, state, identity = prepared(tmp_path)
    monkeypatch.setattr(selected, 'MAX_SELECTIONS', 1)
    with WorkspaceStore(service.root) as store:
        for index in range(3):
            record = AnalystDecision(op='component-name', prior='COMPONENTS_READY', next=f'other{index}.sys',
                                     reason='Authored unrelated decision', created_at=controls.NOW)
            store.db.execute('INSERT INTO decisions(investigation_id,body) VALUES (?,?)',
                             (state[0], record.model_dump_json()))
        decisions = selected._decisions(store, state[0])
    assert len(decisions) == 1
    assert controls.select(service, state, identity).result['revision'] == state[2]


def test_valid_large_unrelated_decision_preserves_inventory_admission_and_evidence(tmp_path):
    service, state, identity = prepared(tmp_path)
    record = AnalystDecision(op='review-note', prior='\U0001f600' * 1000, next='\U0001f600' * 1000,
                             reason='Authored valid general decision' * 4, created_at=controls.NOW)
    body = record.model_dump_json()
    assert len(body.encode('utf-8')) > selected.MAX_SELECTION_BODY_BYTES
    assert AnalystDecision.model_validate_json(body) == record
    with WorkspaceStore(service.root) as store:
        store.db.execute('INSERT INTO decisions(investigation_id,body) VALUES (?,?)', (state[0], body))
        before = tuple(store.db.execute('SELECT seq,body FROM decisions ORDER BY seq'))
    outcome = service.components(state[0], product=state[1], files=[])
    assert outcome.exit == 0 and outcome.result['state'] == 'COMPONENTS_READY'
    hint, = outcome.result['hints']
    assert hint['basename'] == 'review.sys'
    assert hint['inventory_refs'][0]['entry_id'] == identity[1]
    with WorkspaceStore(service.root) as store:
        assert tuple(store.db.execute('SELECT seq,body FROM decisions ORDER BY seq')) == before
        assert store.current_revision(state[0]).revision == state[2] + 1
        assert any(decision.op == 'inventory-select' for decision in store.decisions(state[0]))
    assert service.inventory_details(identity[0]).result['inventory']['import_id'] == identity[0]


@pytest.mark.parametrize('pointer', ['/' + '\U0001f9ed' * 4095, '/escaped\x00value'],
                         ids=['maximum-utf8-pointer', 'valid-escaped-nul'])
def test_large_unrelated_references_use_bounded_scalar_projection_without_a_body_cap(tmp_path, monkeypatch,
                                                                                   pointer):
    service, state, identity = prepared(tmp_path)
    monkeypatch.setattr(selected, 'MAX_SELECTIONS', 1)
    lengths = []

    def bounded_decode(raw):
        lengths.append(len(raw))
        assert len(raw) <= selected.MAX_DECISION_SCALAR_BYTES
        return raw.decode('utf-8')

    with WorkspaceStore(service.root) as store:
        ref = SourceRef(doc_id=store.sources()[0].doc_id, pointer=pointer, assertion='advisory_fact')
        record = AnalystDecision(op='review-note', prior='pending', next='reviewed', reason='Authored references',
                                 created_at=controls.NOW, refs=(ref,) * 80)
        body = record.model_dump_json()
        assert len(body.encode('utf-8')) > selected.MAX_SELECTION_BODY_BYTES
        assert AnalystDecision.model_validate_json(body) == record
        store.append_decision(state[0], record)
        store.db.text_factory = bounded_decode
        decision, = selected._decisions(store, state[0])
        assert (decision.import_id, decision.entry_id) == identity
    assert max(lengths) <= selected.MAX_DECISION_SCALAR_BYTES
    assert controls.select(service, state, identity).result['revision'] == state[2]


@pytest.mark.parametrize('corruption', ['raw-nul-tail', 'invalid-utf8', 'lone-surrogate', 'duplicate-ref-key'])
def test_large_unrelated_invalid_text_and_ambiguous_references_refuse_without_mutation(tmp_path, corruption):
    service, state, _identity = prepared(tmp_path)
    with WorkspaceStore(service.root) as store:
        refs = tuple(SourceRef(doc_id=store.sources()[0].doc_id, pointer=f'/{index}', assertion='advisory_fact')
                     for index in range(80))
        record = AnalystDecision(op='review-note', prior='pending', next='reviewed', reason='Authored references',
                                 created_at=controls.NOW, refs=refs)
        body = record.model_dump_json().encode('utf-8')
        assert len(body) > selected.MAX_SELECTION_BODY_BYTES
        if corruption == 'raw-nul-tail':
            body += b'\x00{"op":"inventory-select"}'
        elif corruption == 'invalid-utf8':
            body = body.replace(b'"pointer":"/0"', b'"pointer":"/\xff"')
        elif corruption == 'lone-surrogate':
            body = body.replace(b'"pointer":"/0"', b'"pointer":"\\ud800"')
        else:
            body = body.replace(b'"pointer":"/0"', b'"pointer":"/0","\\u0070ointer":"/other"')
        store.db.execute('INSERT INTO decisions(investigation_id,body) VALUES (?,CAST(? AS TEXT))',
                         (state[0], sqlite3.Binary(body)))
        before = tuple(store.db.execute('SELECT seq,CAST(body AS BLOB) FROM decisions ORDER BY seq'))
        revision = store.current_revision(state[0])
    with pytest.raises(KbcStoreError) as error:
        service.components(state[0], product=state[1], files=['other.sys'])
    assert error.value.code == 'PT-KBC-VERIFY'
    with WorkspaceStore(service.root) as store:
        assert tuple(store.db.execute('SELECT seq,CAST(body AS BLOB) FROM decisions ORDER BY seq')) == before
        assert store.current_revision(state[0]) == revision


@pytest.mark.parametrize('cause', ['deadline', 'cancel'])
def test_sqlite_scan_can_stop_before_the_first_row_and_clears_its_progress_callback(tmp_path, monkeypatch, cause):
    service, state, _identity = prepared(tmp_path)
    active, cancel = threading.Event(), threading.Event()
    observed = []
    monkeypatch.setattr(selected.time, 'monotonic', lambda: 61.0 if active.is_set() else 0.0)
    with WorkspaceStore(service.root) as store:
        store.db.execute('ALTER TABLE decisions RENAME TO stored_decisions')
        store.db.create_function('inventory_scan_probe', 1, lambda value: observed.append(value) or 'other')
        store.db.execute('CREATE VIEW decisions AS WITH RECURSIVE n(x) AS '
                         '(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) '
                         'SELECT x AS seq, inventory_scan_probe(x) AS investigation_id, '
                         '\'{"op":"inventory-select"}\' AS body FROM n')

        def started(statement):
            if statement.startswith('SELECT CASE'):
                (cancel if cause == 'cancel' else active).set()

        store.db.set_trace_callback(started)
        with pytest.raises(KbcStoreError) as error:
            selected._decisions(store, state[0], cancel=cancel)
        assert error.value.code == ('PT-KBC-CANCEL' if cause == 'cancel' else 'PT-KBC-LIMIT')
        assert 0 < len(observed) < 10000, 'the scan ran to completion without returning any row'
        store.db.set_trace_callback(None)
        # Leave the cancellation/deadline condition set. A leaked callback would
        # interrupt this later statement on the same still-owned connection.
        (total,) = store.db.execute('WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000) '
                                   'SELECT SUM(x) FROM n').fetchone()
        assert total == 50_005_000
