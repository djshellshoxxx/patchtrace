"""Retained CVRF -> pilot: authored real stores, exact native refs and negative controls.

No source is downloaded and no target or analyzer runs. A subprocess uses this
checkout explicitly; the shared environment can have another editable install.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import threading
import uuid
from pathlib import Path

import pytest
from kbc_k3_support import Kb
from kbc_k4a_support import analysed_project

from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore, Guard
from patchtrace.intelligence.storage import AdvisoryStore
from patchtrace.kbcorrelation import context, wiring
from patchtrace.kbcorrelation.contracts import Lead
from patchtrace.kbcorrelation.index import ReverseIndex
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kev import store as kev_store
from patchtrace.pilot import collect, keys, store
from patchtrace.pilot.limits import Budget, PilotError
from patchtrace.pilot.service import localize
from patchtrace.service import ProjectService

ROOT = Path(__file__).resolve().parents[1]
SRC = str(ROOT / 'src')
CVE, OTHER = 'CVE-2099-20001', 'CVE-2099-20002'
NOW = '2099-02-15T00:00:00Z'
CSAF = ROOT / 'tests/fixtures/pilot/synergy-1/sample-cwe125-advisory.json'


def denied(*_args, **_kwargs):
    raise AssertionError('this operation must not open another project or execute external work')


@pytest.fixture(autouse=True)
def offline(tmp_path, monkeypatch):
    monkeypatch.setattr(kev_store, 'default_kev_dir', lambda: tmp_path / 'kev')
    for name in ('socket', 'create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, denied)


@pytest.fixture
def case(tmp_path, capsys):
    return analysed_project(Kb(tmp_path, capsys), tmp_path, capsys)


def original(service):
    row, = EnrichmentStore(service.store).entries('kb-context')
    return context.ContextBundle.model_validate_json(row.body_json)


def revised(bundle, **changes):
    result = bundle.model_copy(update={'base_revision': bundle.base_revision + 1, **changes})
    key = context.context_key(
        investigation_id=result.investigation_id, base_revision=result.base_revision,
        edge_set_digest=result.edge_set_digest, sources=result.sources, rules_digest=result.rules_digest,
        lexicon_digest=result.lexicon_digest, older_sha=result.older_sha, newer_sha=result.newer_sha,
        scope_id=result.scope_id)
    return result.model_copy(update={'context_key': key})


def only(bundle, cves):
    return revised(bundle, context=bundle.context.model_copy(update={
        'cards': tuple(c for c in bundle.context.cards if c.cve in cves), 'intelligence': ()}),
        cwe_profiles=tuple(p for p in bundle.cwe_profiles if p.cve in cves),
        hypotheses=tuple(h for h in bundle.hypotheses if h.cve in cves),
        card_facts=tuple(r for r in bundle.card_facts if r.cve in cves))


def publish(service, bundle, *, body=None, project_id=None, status='ok', stale=False):
    body = bundle.model_dump(mode='json') if body is None else body
    raw = json.dumps(body).encode()
    entry_id = 'kb-context:' + body['context_key']
    guard = Guard(project_id or service.project.id, 'kb', hashlib.sha256(raw).hexdigest(), entry_id)
    current = Guard(service.project.id, 'kb', '0' * 64, entry_id) if stale else guard
    EnrichmentStore(service.store).publish('kb-context', guard, current, service.project.revision,
                                          status, body, entry_id)
    return entry_id


def captured(service):
    from patchtrace.pilot.sources.kb_context import capture
    return capture(service, EnrichmentStore(service.store), budget=Budget.after(None))


def gathered(service, **kwargs):
    return collect.collect(service, EnrichmentStore(service.store), cancel=threading.Event(),
                           unified=False, **kwargs)


def native_bundle(service):
    value = {
        'DocumentType': {'Value': 'Security Update'},
        'DocumentTracking': {'Identification': {'ID': {'Value': '2099-Mar'}}, 'Status': 2, 'Version': '1'},
        'ProductTree': {'FullProductName': [{'ProductID': 'P1', 'Value': 'Authored Server 2099 x64'}]},
        'Vulnerability': [{'CVE': CVE, 'Title': {'Value': 'Authored out-of-bounds read'},
                           'CWE': [{'ID': 'CWE-125'}],
                           'ProductStatuses': [{'Type': 3, 'ProductID': ['P1']}],
                           'Remediations': [{'Type': 2, 'Description': {'Value': '5099001'},
                                             'ProductID': ['P1']}]}]}
    raw = json.dumps(value).encode()
    doc = import_bytes(raw, now=NOW)
    index = ReverseIndex()
    index.add(doc)
    sides = {a.side: a.sha256 for a in service.project.artifacts}
    bundle = context.build_bundle(
        investigation_id=str(uuid.uuid4()), base_revision=1, lead=Lead(kind='cve', value=CVE, raw=CVE),
        cves=(CVE,), index=index, rules=wiring.IntelligenceRules(), now=NOW, coverage=(),
        scope_id=None, pair_id=None, older_sha=sides['older'], newer_sha=sides['newer'])
    return bundle, raw


def import_csaf(service, *, gate='applies', withdrawn=False):
    value = json.loads(CSAF.read_bytes())
    vuln = value['vulnerabilities'][0]
    vuln['cve'] = CVE
    if gate == 'not-applicable':
        vuln['product_status']['known_not_affected'] = vuln['product_status'].pop('known_affected')
    elif gate == 'conflict':
        vuln['product_status']['known_not_affected'] = list(vuln['product_status']['known_affected'])
    target = AdvisoryStore(service.root, EnrichmentStore(service.store), service.project.id,
                           service.project.revision)
    target.add(json.dumps(value).encode(), origin='local-import', uri=None, file_name='authored.json',
               retrieved_at=NOW)
    if withdrawn:
        value['vulnerabilities'] = []
        tracking = value['document']['tracking']
        tracking.update(version='2', current_release_date='2099-02-14T08:00:00.000Z')
        tracking['revision_history'].append({'number': '2', 'date': tracking['current_release_date'],
                                             'summary': 'Authored withdrawal control'})
        target.add(json.dumps(value).encode(), origin='local-import', uri=None, file_name='withdrawn.json',
                   retrieved_at=NOW)


def test_real_kb_journey_reaches_pilot_and_retains_uncertainty(case, capsys, monkeypatch):
    assert cli.main(['pilot', 'leads', str(case), '--cve', CVE, '--json']) == 0
    payload = json.loads(capsys.readouterr().out)['result']
    assert payload['stored'] and payload['cves'][0]['cve'] == CVE
    with ProjectService.open(case) as service:
        monkeypatch.setattr(ProjectService, 'open', denied)
        inputs = gathered(service, named=(CVE,))
        assessment = localize(inputs, keys.default_config(), threading.Event())
        cve = next(c for c in assessment.cves if c.cve == CVE)
        assert cve.gate == 'unverified'
        assert cve.applicability.older == cve.applicability.newer == 'unknown'
        assert cve.applicability.older_mapping == cve.applicability.newer_mapping == 'unknown'
        assert assessment.inputs.kb_link_digest == captured(service).digest
        assert any('raw source' in note.lower() and 'not reverified' in note.lower() for note in cve.limitations)
        leads = [lead for lead in assessment.leads if lead.cve == CVE]
        assert leads and all(lead.mechanism != 'moderate' for lead in leads)
        assert all(o.origins == ('D_vendor_text',) for o in inputs.advisory_observations[CVE])
        assert not inputs.advisory.report(CVE).anchors.anchors
        from patchtrace.ui_leads import load_stored
        loaded = load_stored(service, service.project).loaded
        assert loaded.assessment.result_id == payload['result_id']


def test_native_pointers_and_raw_digest_survive_without_fabricated_csaf(case):
    with ProjectService.open(case) as service:
        service.store._db.execute("DELETE FROM enrichment_entries WHERE kind='kb-context'")
        bundle, raw = native_bundle(service)
        publish(service, bundle)
        inputs = gathered(service, named=(CVE,))
        refs = inputs.advisory_observations[CVE]
        assert refs and {o.ref.sha256 for o in refs} == {hashlib.sha256(raw).hexdigest()}
        assert {o.ref.pointer for o in refs} == {'/Vulnerability/0/CWE/0/ID'}
        for obs in refs:
            value = json.loads(raw)
            for part in obs.ref.pointer.split('/')[1:]:
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value == 'CWE-125'
            assert obs.ref.kind == 'cvrf-card-fact' and obs.verification == 'advisory-claim'
        view = inputs.advisory.report(CVE)
        assert not hasattr(view, 'sources')
        assert view.hypotheses.hypotheses[0].basis == 'explicit-advisory-cwe'
        assert tuple(inputs.advisory.facts_ids()) == (hashlib.sha256(raw).hexdigest(),)


@pytest.mark.parametrize('gate,withdrawn', [('applies', False), ('not-applicable', False),
                                          ('conflict', False), ('applies', True)])
def test_csaf_gates_and_withdrawing_revision_take_precedence(case, gate, withdrawn):
    from patchtrace.intelligence.csaf.identity import project_identities
    from patchtrace.pilot.sources.advisory import StoredAdvisorySource, context_from_report
    with ProjectService.open(case) as service:
        import_csaf(service, gate=gate, withdrawn=withdrawn)
        enrichment = EnrichmentStore(service.store)
        docs, warnings = AdvisoryStore(service.root, enrichment, service.project.id,
                                       service.project.revision).advisories()
        baseline = StoredAdvisorySource(docs, *project_identities(service.project.artifacts, service.root),
                                        cves=(CVE,), warnings=warnings)
        expected = context_from_report(baseline.report(CVE), assume_applies=True)
        inputs = gathered(service, named=(CVE,), assume=(CVE,))
        actual = next(c for c in inputs.contexts if c.cve == CVE)
        assert actual.gate == expected.gate
        if not withdrawn:
            assert actual.gate == gate
        assert inputs.advisory.report(CVE) == baseline.report(CVE)
        assert inputs.advisory_observations[CVE] == expected.observations
        assert any('CSAF' in line and 'precedence' in line for line in actual.limitations)
        assert set(baseline.facts_ids()) <= set(inputs.advisory.facts_ids())
        assert not any(o.ref.kind == 'cvrf-card-fact' for o in inputs.advisory_observations[CVE])


def test_duplicate_context_does_not_add_rules_origins_or_lead_strength(case):
    with ProjectService.open(case) as service:
        a = gathered(service)
        before = localize(a, keys.default_config(), threading.Event())
        bundle = original(service)
        publish(service, revised(bundle, investigation_id=str(uuid.uuid4()), base_revision=1))
        b = gathered(service)
        after = localize(b, keys.default_config(), threading.Event())
        assert a.advisory_observations == b.advisory_observations
        assert a.advisory.facts_ids() == b.advisory.facts_ids()
        assert a.advisory.report(CVE).hypotheses == b.advisory.report(CVE).hypotheses
        assert [(l.cve, l.candidate_key, l.rank, l.mechanism, l.components) for l in before.leads] == [
            (l.cve, l.candidate_key, l.rank, l.mechanism, l.components) for l in after.leads]


def test_current_rules_are_recomputed_from_fields(case):
    with ProjectService.open(case) as service:
        bundle = original(service)
        sets = list(bundle.hypotheses)
        hypotheses = list(sets[0].hypotheses)
        hypotheses[0] = hypotheses[0].model_copy(update={'expected_operations': ('FORGED persisted rule',)})
        sets[0] = sets[0].model_copy(update={'hypotheses': tuple(hypotheses)})
        publish(service, revised(bundle, hypotheses=tuple(sets)))
        actual = gathered(service).advisory.report(CVE).hypotheses
        assert all('FORGED' not in op for h in actual.hypotheses for op in h.expected_operations)


@pytest.mark.parametrize('damage', ['legacy', 'missing-field', 'wrong-source', 'wrong-document',
                                  'wrong-pointer', 'wrong-owner', 'status', 'stale', 'corrupt', 'pair'])
def test_newest_invalid_context_never_resurrects_older_cards(case, damage):
    with ProjectService.open(case) as service:
        bundle = revised(original(service))
        body = bundle.model_dump(mode='json')
        kwargs = {}
        if damage == 'legacy':
            body.pop('card_facts')
        elif damage == 'missing-field':
            body['card_facts'] = [r for r in body['card_facts'] if r['field'] != 'stated_cwe']
        elif damage == 'wrong-source':
            body['card_facts'][0]['source_sha256'] = '0' * 64
        elif damage == 'wrong-document':
            old = body['sources'][0]['doc_id']
            body['sources'][0]['doc_id'] = 'f' * 64
            for ref in body['card_facts']:
                if ref['doc_id'] == old:
                    ref['doc_id'] = 'f' * 64
        elif damage == 'wrong-pointer':
            next(r for r in body['card_facts'] if r['field'] == 'cve')['pointer'] = '/not-a-cve-field'
        elif damage == 'wrong-owner':
            kwargs['project_id'] = str(uuid.uuid4())
        elif damage == 'status':
            kwargs['status'] = 'failed'
        elif damage == 'stale':
            kwargs['stale'] = True
        elif damage == 'pair':
            bundle = revised(bundle, older_sha=bundle.newer_sha, newer_sha=bundle.older_sha)
            body = bundle.model_dump(mode='json')
        entry_id = publish(service, bundle, body=body, **kwargs)
        if damage == 'corrupt':
            service.store._db.execute('UPDATE enrichment_entries SET body=? WHERE id=?', ('{}', entry_id))
        snapshot = captured(service)
        assert not snapshot.cves and snapshot.warnings
        with pytest.raises(PilotError) as error:
            gathered(service, named=(CVE,))
        assert error.value.code in ('PT-PILOT-STALE', 'PT-PILOT-NOTFOUND')


def test_withdrawal_changes_identity_without_reviving_another_old_copy(case):
    with ProjectService.open(case) as service:
        bundle = original(service)
        before = captured(service)
        publish(service, revised(bundle, investigation_id=str(uuid.uuid4()), base_revision=1))
        publish(service, only(bundle, (OTHER,)))
        after = captured(service)
        assert CVE not in after.cves and before.digest != after.digest
        assert OTHER in after.cves
        with pytest.raises(PilotError):
            gathered(service, named=(CVE,))


def test_revisions_are_ordered_within_investigation_not_globally(case):
    with ProjectService.open(case) as service:
        bundle = original(service)
        service.store._db.execute("DELETE FROM enrichment_entries WHERE kind='kb-context'")
        publish(service, revised(only(bundle, (CVE,)), base_revision=90))
        publish(service, revised(only(bundle, (OTHER,)), investigation_id=str(uuid.uuid4()), base_revision=1))
        assert captured(service).cves == (CVE, OTHER)


def test_same_revision_divergence_is_not_resolved_by_context_hash(case):
    with ProjectService.open(case) as service:
        bundle = original(service)
        publish(service, revised(bundle, base_revision=bundle.base_revision, edge_set_digest='f' * 64))
        snapshot = captured(service)
        assert not snapshot.cves and snapshot.warnings


def test_empty_store_keeps_existing_identity_and_source_behavior(tmp_path):
    with ProjectService.sample(tmp_path / 'plain') as service:
        snapshot = captured(service)
        assert snapshot.digest is None and not snapshot.cves and not snapshot.warnings
        result = localize(gathered(service), keys.default_config(), threading.Event())
        assert result.inputs.kb_link_digest is None and not result.inputs.advisory_facts_ids


@pytest.mark.parametrize('bound', ['MAX_ROWS', 'MAX_BYTES', 'MAX_NODES', 'MAX_DEPTH', 'MAX_CARDS', 'MAX_REFS'])
def test_capture_bounds_never_select_a_prefix(case, monkeypatch, bound):
    from patchtrace.pilot.sources import kb_context
    with ProjectService.open(case) as service:
        monkeypatch.setattr(kb_context, bound, 0)
        enrichment = EnrichmentStore(service.store)
        if bound in ('MAX_ROWS', 'MAX_BYTES'):
            monkeypatch.setattr(enrichment, 'entries', denied)
        snapshot = kb_context.capture(service, enrichment, budget=Budget.after(None))
        assert not snapshot.cves and snapshot.unavailable and snapshot.digest and snapshot.warnings


def test_cancelled_capture_reads_no_rows(case, monkeypatch):
    from patchtrace.pilot.sources import kb_context
    with ProjectService.open(case) as service:
        stop = threading.Event()
        stop.set()
        enrichment = EnrichmentStore(service.store)
        monkeypatch.setattr(enrichment, 'entries', denied)
        with pytest.raises(PilotError) as error:
            kb_context.capture(service, enrichment, budget=Budget.after(None, stop))
        assert error.value.code == 'PT-PILOT-CANCEL'


def test_current_source_cli_child_is_headless_and_uses_retained_context(case):
    child = '''import importlib.abc, sys
class NoQt(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith(('PySide6', 'shiboken6', 'patchtrace.ui')):
            raise AssertionError('headless CLI imported Qt/UI: ' + fullname)
sys.meta_path.insert(0, NoQt())
from patchtrace import cli
import socket
def denied(*a, **k): raise AssertionError('offline child attempted network')
socket.socket = socket.create_connection = socket.getaddrinfo = denied
raise SystemExit(cli.main(sys.argv[1:]))
'''
    done = subprocess.run([sys.executable, '-c', child, 'pilot', 'leads', str(case), '--cve', CVE,
                           '--json', '--dry-run'], env={**os.environ, 'PYTHONPATH': SRC}, cwd=case,
                          capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr + done.stdout
    document = json.loads(done.stdout)
    assert document['result']['cves'][0]['cve'] == CVE
    assert document['result']['cves'][0]['gate'] == 'unverified'


def test_identity_matches_stored_inputs_and_changes_on_removal(case):
    with ProjectService.open(case) as service:
        inputs = gathered(service)
        result = localize(inputs, keys.default_config(), threading.Event())
        assert result.inputs.kb_link_digest == captured(service).digest
        service.store._db.execute("DELETE FROM enrichment_entries WHERE kind='kb-context'")
        assert captured(service).digest is None
        assert store._changed(result.inputs, {'kb_link_digest': None}) == ('kb_link_digest',)
