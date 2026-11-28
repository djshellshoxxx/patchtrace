"""Acquisition provenance through real local persistence and an authored, socket-denied provider."""
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import test_kbc_acquire_cli as acquire_cli
from kbc_k1_support import no_sockets  # noqa: F401
from test_acquisition_workflow import pair_and_rows
from test_kbc_acquire_cli import HOSTS, NET, SHA_N, SHA_O, plan_of

from patchtrace import owned_publication
from patchtrace.acquisition.workflow import Acquirer
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.kbcorrelation import acquire, wiring
from patchtrace.kbcorrelation.acquisition_evidence import (
    MAX_EVIDENCE_BYTES,
    MAX_REQUESTS,
    AcquisitionSource,
    EvidenceLimitError,
    canonical,
    plan_digest,
    read_evidence,
)
from patchtrace.kbcorrelation.contracts import domain_id
from patchtrace.kbcorrelation.store import KbcStoreError, WorkspaceStore
from patchtrace.owned_publication import OwnedPublicationError
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')
ready = acquire_cli.ready
staging_root = acquire_cli.staging_root


def _workspace_state(kb, inv):
    with WorkspaceStore(kb.workspace) as ws:
        return ws.revisions(inv), ws.decisions(inv), ws.attempts(inv), ws.journal_ops()


def _acquire(ready):
    kb, _server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', preview['plan_sha'])
    return code, doc, preview


def _pending(ready):
    kb, _server, _inv, _flags, _project = ready

    def interrupted(point):
        if point == 'after_sidecar_write':
            raise KbcStoreError('PT-KBC-STORAGE', 'authored failure after durable sidecars')

    kb.env = replace(kb.env, fault=interrupted)
    code, doc, preview = _acquire(ready)
    assert code == 3 and doc['result']['project']['state'] == 'context-pending'
    kb.env = replace(kb.env, fault=None)
    return doc, preview


def _stored_entry(project):
    with ProjectService.open(project, maintenance=False) as service:
        entries = EnrichmentStore(service.store).entries('kb-acquisition')
        assert len(entries) == 1
        return entries[0], service.project.revision


def test_acquired_project_retains_complete_proposal_window_and_delivery_rows(ready, staging_root):
    kb, _server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', preview['plan_sha'])
    assert code == 0, doc
    saved = list((project / 'kb' / 'acquisitions').glob('*.json'))
    assert len(saved) == 1, 'a completed acquisition must retain its source proposal and delivery entries'
    evidence = json.loads(saved[0].read_bytes())
    assert evidence['source'] == preview['source']
    assert evidence['source']['proposal']['pair_id'] == preview['pair_id']
    assert evidence['source']['proposal']['window']
    assert evidence['source']['older']['sha256'] == SHA_O
    assert evidence['source']['newer']['sha256'] == SHA_N
    assert evidence['verified_pair']['pair_id'] == doc['result']['pair']['pair_id']
    assert evidence['plan_sha'] == preview['plan_sha']
    assert evidence['downloads'] == doc['result']['acquisition']['downloads']
    record = read_evidence(saved[0].read_bytes())
    result = doc['result']['acquisition']
    assert result['evidence_id'] == record.evidence_id
    assert result['evidence_path'] == record.relative_path and result['evidence_state'] == 'attached'
    stored, revision = _stored_entry(project)
    assert stored.body == evidence and revision == doc['result']['project']['project_revision']
    assert evidence['verified_pair']['grade'] == 'B' and evidence['verified_pair']['tier'] == 'E'
    assert evidence['verified_pair']['lineage_state'] == 'user-asserted'
    assert evidence['verified_pair']['fix_boundary'] == 'unverified'
    assert evidence['source']['proposal']['bytes_state'] == 'pending'
    assert not any(staging_root.iterdir())


def test_same_binary_hashes_with_changed_source_entry_require_fresh_consent(ready, staging_root):
    kb, server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    before = _workspace_state(kb, inv)
    saved_index = kb.workspace / 'winbindex' / f'{NET}@2099-02-12.json'
    raw = json.loads(saved_index.read_bytes())
    # This changes upstream entry identity while leaving chronology, file bytes and requests identical.
    raw[SHA_O]['fileInfo']['description'] = 'Changed upstream documentary label'
    saved_index.write_text(json.dumps(raw), encoding='utf-8')
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', preview['plan_sha'])
    assert code == 2 and 'PT-KBC-CONSENT' in doc['error']
    assert doc['result']['plan']['pair_id'] == preview['pair_id']
    assert doc['result']['plan']['requests'] == preview['requests']
    assert doc['result']['plan']['plan_sha'] != preview['plan_sha']
    assert server.calls == [] and not project.exists() and not any(staging_root.iterdir())
    assert _workspace_state(kb, inv) == before


@pytest.mark.parametrize('change', ['window', 'source-date', 'entry-hash', 'heading'])
def test_consent_binds_full_claims_when_binary_pair_and_urls_are_identical(change):
    pair, older, newer = pair_and_rows()
    before = acquire.build_plan(pair, older, newer, Acquirer())
    if change == 'window':
        pair = pair.model_copy(update={'window': tuple(sorted((*pair.window, 'KB5999999'))),
                                       'window_complete': False})
    elif change == 'source-date':
        older['source'] = 'winbindex@2099-04-01'
    elif change == 'entry-hash':
        older['record_sha256'] = 'f' * 64
    else:
        older['heading'] = 'Changed source text'
    after = acquire.build_plan(pair, older, newer, Acquirer())
    assert after.pair_id == before.pair_id and after.requests == before.requests
    assert (after.older_sha, after.newer_sha) == (before.older_sha, before.newer_sha)
    assert after.plan_sha != before.plan_sha
    with pytest.raises(KbcStoreError, match='different plan'):
        acquire.verify_consent(after, consent_hosts=before.hosts, consent_plan=before.plan_sha, offline=False)


def test_caller_mutation_after_plan_is_refused_before_staging(tmp_path):
    pair, older, newer = pair_and_rows()
    plan = acquire.build_plan(pair, older, newer, Acquirer())
    older['heading'] = 'Changed after approval'

    class NeverStage:
        def stage(self, *args, **kwargs):
            pytest.fail('changed source must never reach staging')

    with pytest.raises(KbcStoreError, match='source changed'):
        acquire.acquire_pair(plan, older, newer, port=NeverStage(), import_pair=lambda *_: pytest.fail('imported'),
                             directory=str(tmp_path / 'project'), consent_hosts=plan.hosts,
                             consent_plan=plan.plan_sha)
    assert plan.source.older.heading != older['heading']
    assert not (tmp_path / 'project').exists()


def test_source_snapshot_budget_refuses_before_port_planning():
    pair, older, newer = pair_and_rows()
    older['heading'] = 'x' * (MAX_EVIDENCE_BYTES + 1)

    class NeverPlan:
        def plan(self, *_):
            pytest.fail('oversize evidence must never reach the port')

    with pytest.raises(KbcStoreError) as error:
        acquire.build_plan(pair, older, newer, NeverPlan())
    assert error.value.code == 'PT-KBC-LIMIT'
    with pytest.raises(EvidenceLimitError):
        read_evidence(b' ' * (MAX_EVIDENCE_BYTES + 1))


def test_request_budget_preserves_existing_provider_ceiling_and_freezes_nested_rows():
    pair, older, newer = pair_and_rows()
    request = ['HEAD', 'https://example.invalid/candidate']
    pending = [request] * MAX_REQUESTS

    class Planner:
        def plan(self, *_):
            return SimpleNamespace(hosts=('example.invalid',), requests=pending)

    plan = acquire.build_plan(pair, older, newer, Planner())
    assert len(plan.requests) == 2 * (256 + 1)
    request[1] = 'https://changed.invalid/candidate'
    assert all(target == 'https://example.invalid/candidate' for _method, target in plan.requests)
    pending.append(['GET', 'https://example.invalid/additional'])
    with pytest.raises(KbcStoreError) as error:
        acquire.build_plan(pair, older, newer, Planner())
    assert error.value.code == 'PT-KBC-LIMIT'


def test_repair_replays_frozen_evidence_without_index_then_backup_retains_it(ready, staging_root, monkeypatch,
                                                                          tmp_path):
    kb, server, inv, _flags, project = ready
    partial, preview = _pending(ready)
    evidence_path = project / partial['result']['acquisition']['evidence_path']
    captured_bytes = evidence_path.read_bytes()
    evidence_path.unlink()  # missing sidecar after an interruption; journal is still the authoritative intent
    for saved_index in (kb.workspace / 'winbindex').iterdir():
        saved_index.unlink()
    calls = tuple(server.calls)

    def no_index(*_):
        pytest.fail('repair must not resolve mutable Winbindex input')

    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'rows_for', no_index)
    code, repaired, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 0, repaired
    assert evidence_path.read_bytes() == captured_bytes
    evidence = read_evidence(captured_bytes)
    assert evidence.source.model_dump(mode='json') == preview['source']
    first, revision = _stored_entry(project)
    state = _workspace_state(kb, inv)
    assert kb('attach', str(project), '--investigation', inv, '--repair')[0] == 0
    again, again_revision = _stored_entry(project)
    assert again == first and again_revision == revision and _workspace_state(kb, inv) == state
    assert tuple(server.calls) == calls and not any(staging_root.iterdir())
    backup = tmp_path / 'backup'
    with ProjectService.open(project, maintenance=False) as service:
        service.store.backup(backup)
    assert (backup / evidence.relative_path).read_bytes() == captured_bytes
    backup_entry, backup_revision = _stored_entry(backup)
    assert backup_entry.body == first.body and backup_revision == revision


@pytest.mark.parametrize('replacement_receipt', [False, True])
def test_unfinished_acquisition_checks_operation_identity_before_interruption_writes(ready, staging_root,
                                                                                   replacement_receipt):
    kb, _server, inv, _flags, project = ready

    class AuthoredInterruption(BaseException):
        pass

    def interrupted(point):
        if point == 'after_sidecar_write':
            raise AuthoredInterruption()

    kb.env = replace(kb.env, fault=interrupted)
    with pytest.raises(AuthoredInterruption):
        _acquire(ready)
    kb.env = replace(kb.env, fault=None)
    assert not any(staging_root.iterdir())
    with WorkspaceStore(kb.workspace) as ws:
        op, state, body = ws.journal_ops()[0]
        assert state == 'created' and body['cas_created'] and not body['cas_final']
        evidence = body['acquisition_evidence']
        original = read_evidence(canonical(evidence))
        if replacement_receipt:
            evidence['downloads'][0]['retrieved_at'] = '2099-12-31T00:00:00Z'
            evidence['evidence_id'] = domain_id('kbc.acquisition', evidence['evidence_version'],
                                               {k: v for k, v in evidence.items() if k != 'evidence_id'})
            body['acquisition_id'] = evidence['evidence_id']
            read_evidence(canonical(evidence))  # valid pair, plan and receipt; only the operation binding changed
            ws.journal_put(op, state, body)
    before = _workspace_state(kb, inv)
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    if replacement_receipt:
        assert code == 3 and 'PT-KBC-VERIFY' in json.dumps(doc)
        assert _workspace_state(kb, inv) == before  # includes attempts and the interrupted journal flag
        assert not (project / f'kb/acquisitions/{evidence["evidence_id"]}.json').exists()
    else:
        assert code == 0, doc
        stored, _revision = _stored_entry(project)
        assert stored.body == original.model_dump(mode='json')
    assert (project / original.relative_path).read_bytes() == original.as_bytes()


@pytest.mark.parametrize('corruption', ['missing-payload', 'changed-window', 'foreign-investigation',
                                         'future-preview', 'foreign-scope', 'rewritten-source'])
def test_repair_refuses_malformed_or_foreign_journal_evidence_before_mutation(ready, staging_root, corruption):
    kb, _server, inv, _flags, project = ready
    _pending(ready)
    with WorkspaceStore(kb.workspace) as ws:
        op, state, body = ws.journal_ops()[0]
        evidence = body['acquisition_evidence']
        if corruption == 'missing-payload':
            del body['acquisition_evidence']
        elif corruption == 'changed-window':
            evidence['source']['proposal']['window'] = ['KB5999999']  # deliberately stale content digests
        else:
            if corruption == 'foreign-investigation':
                evidence['investigation_id'] = '11111111-1111-4111-8111-111111111111'
            elif corruption == 'future-preview':
                evidence['preview_revision'] = body['base'] + 1
            elif corruption == 'foreign-scope':
                for pair in (evidence['source']['proposal'], evidence['verified_pair']):
                    pair['scope_id'] = 'f' * 64
                    pair['pair_id'] = domain_id('kbc.pair', 1, {
                        'older': pair['older']['sha256'], 'newer': pair['newer']['sha256'],
                        'scope_id': pair['scope_id'], 'window_id': pair['window_id']})
                if 'replay' in evidence['source']:
                    replay = evidence['source']['replay']
                    replay['inputs']['scope']['scope_id'] = 'f' * 64
                    replay['selected_pair_id'] = evidence['source']['proposal']['pair_id']
            else:
                evidence['source']['older']['heading'] = 'Internally valid replacement claims'
            if corruption in {'foreign-scope', 'rewritten-source'}:
                source = AcquisitionSource.model_validate_json(json.dumps(evidence['source']))
                evidence['plan_sha'] = plan_digest(source, evidence['hosts'],
                                                  [(r['method'], r['target']) for r in evidence['requests']])
            payload = {key: value for key, value in evidence.items() if key != 'evidence_id'}
            evidence['evidence_id'] = domain_id('kbc.acquisition', evidence['evidence_version'], payload)
            body['acquisition_id'] = evidence['evidence_id']
            read_evidence(canonical(evidence))  # valid record; only the attachment ownership must reject it
        ws.journal_put(op, state, body)
    before = _workspace_state(kb, inv)
    files = {p.name: p.read_bytes() for p in (project / 'kb' / 'acquisitions').iterdir()}
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 3 and 'PT-KBC-VERIFY' in json.dumps(doc)
    assert _workspace_state(kb, inv) == before
    assert {p.name: p.read_bytes() for p in (project / 'kb' / 'acquisitions').iterdir()} == files
    with ProjectService.open(project, maintenance=False) as service:
        assert EnrichmentStore(service.store).entries('kb-acquisition') == []


def test_conflicting_immutable_sidecar_survives_failed_repair(ready, staging_root):
    kb, _server, inv, _flags, project = ready
    partial, _preview = _pending(ready)
    path = project / partial['result']['acquisition']['evidence_path']
    path.write_bytes(b'{"foreign":"preserve me"}')
    code, doc, _ = kb('attach', str(project), '--investigation', inv, '--repair')
    assert code == 3 and 'PT-KBC-STATE' in json.dumps(doc)
    assert path.read_bytes() == b'{"foreign":"preserve me"}'
    with ProjectService.open(project, maintenance=False) as service:
        assert EnrichmentStore(service.store).entries('kb-acquisition') == []


def test_unavailable_owned_publication_retains_project_and_captured_journal(ready, staging_root, monkeypatch):
    kb, _server, inv, _flags, project = ready
    publisher = owned_publication.publish_bytes

    def unavailable(target, *args, **kwargs):
        if target.is_relative_to(project):
            raise OwnedPublicationError('authored unavailable project ownership primitive')
        return publisher(target, *args, **kwargs)

    monkeypatch.setattr(owned_publication, 'publish_bytes', unavailable)
    code, doc, _ = _acquire(ready)
    assert code == 3 and doc['result']['project']['state'] == 'context-pending'
    assert (project / 'project.sqlite3').is_file() and not any(staging_root.iterdir())
    with WorkspaceStore(kb.workspace) as ws:
        body = ws.journal_ops()[0][2]
        record = read_evidence(canonical(body['acquisition_evidence']))
    assert not (project / record.relative_path).exists()
    monkeypatch.setattr(owned_publication, 'publish_bytes', publisher)
    assert kb('attach', str(project), '--investigation', inv, '--repair')[0] == 0
    assert (project / record.relative_path).read_bytes() == record.as_bytes()


def test_project_port_rejects_valid_evidence_for_different_artifacts(ready, staging_root):
    _kb, _server, _inv, _flags, project = ready
    assert _acquire(ready)[0] == 0
    examples = Path(__file__).resolve().parents[1] / 'docs' / 'schemas' / 'kbcorrelation' / 'examples.json'
    other = read_evidence(canonical(json.loads(examples.read_text())['AcquisitionEvidence']['valid']))
    port = wiring.RealProjectPort()
    project_id = port.open_project(str(project))
    before, revision = _stored_entry(project)
    with pytest.raises(KbcStoreError, match='identity or ownership'):
        port.put_row(project_id, 'kb-acquisition', other.evidence_id, other.as_bytes())
    with pytest.raises(KbcStoreError, match='identity or ownership'):
        port.write_acquisition_sidecar(project_id, other.as_bytes())
    assert not (project / other.relative_path).exists()
    after, later = _stored_entry(project)
    assert before == after and revision == later


def test_snapshot_project_port_remains_read_only_for_acquisition_evidence():
    port = wiring.SnapshotProjectPort('project', {})
    with pytest.raises(KbcStoreError, match='read-only'):
        port.write_acquisition_sidecar('project', b'{}')


def test_existing_acquisition_row_cannot_be_overwritten_by_republication(ready, staging_root):
    _kb, _server, _inv, _flags, project = ready
    code, doc, _ = _acquire(ready)
    assert code == 0
    evidence = read_evidence((project / doc['result']['acquisition']['evidence_path']).read_bytes())
    foreign = '{"foreign":"preserve this conflicting row"}'
    entry_id = f'kb-acquisition:{evidence.evidence_id}'
    with ProjectService.open(project, maintenance=False) as service:
        with service.store.connection:
            service.store.connection.execute('UPDATE enrichment_entries SET body=?,body_sha256=? WHERE id=?',
                                              (foreign, hashlib.sha256(foreign.encode()).hexdigest(), entry_id))
    port = wiring.RealProjectPort()
    project_id = port.open_project(str(project))
    with pytest.raises(KbcStoreError, match='identity or ownership'):
        port.put_row(project_id, 'kb-acquisition', evidence.evidence_id, evidence.as_bytes())
    with ProjectService.open(project, maintenance=False) as service:
        assert service.store.connection.execute('SELECT body FROM enrichment_entries WHERE id=?',
                                                 (entry_id,)).fetchone()[0] == foreign


@pytest.mark.parametrize('change', ['duplicate-key', 'unknown-field', 'receipt-hash', 'identity'])
def test_strict_persisted_evidence_rejects_malformed_records(ready, staging_root, change):
    _kb, _server, _inv, _flags, project = ready
    code, doc, _ = _acquire(ready)
    assert code == 0
    path = project / doc['result']['acquisition']['evidence_path']
    data = path.read_bytes()
    value = json.loads(data)
    if change == 'duplicate-key':
        data = data[:-1] + b',"evidence_version":1}'
    else:
        if change == 'unknown-field':
            value['unexpected'] = 'refuse'
        elif change == 'receipt-hash':
            value['downloads'][0]['sha256'] = SHA_N
        else:
            value['evidence_id'] = '0' * 64
        data = json.dumps(value).encode()
    with pytest.raises(ValueError):
        read_evidence(data)
