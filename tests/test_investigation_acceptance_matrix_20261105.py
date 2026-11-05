"""Authored advisory acceptance through real parsers, workspace storage and service; never live evidence."""
from __future__ import annotations

import hashlib
import io
import threading
from dataclasses import dataclass
from pathlib import Path

import pytest
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation import cli_online, wiring
from patchtrace.kbcorrelation.cli_index import IndexPorts
from patchtrace.kbcorrelation.investigation_service import InvestigationRequest, execute_request
from patchtrace.kbcorrelation.sources import net_plan
from patchtrace.kbcorrelation.sources.cvrf import load_json
from patchtrace.kbcorrelation.sources.importer import import_bytes
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
FIXTURES = Path(__file__).parent / 'fixtures/kbcorrelation/acceptance-20261105'
NOW = '2099-02-15T00:00:00Z'
CVE = 'CVE-2099-70001'
KB = 'KB5099551'


@dataclass
class Clock:
    value: str = NOW

    def now_utc(self):
        return self.value


def request(operation, workspace, *, clock=None, **fields):
    result = execute_request(InvestigationRequest(operation, workspace, **fields), threading.Event(),
                             service_factory=lambda root: wiring.build_service(root, clock=clock or Clock()))
    assert result.success, result.text
    return result


def stored_raw(workspace):
    with WorkspaceStore(workspace, create=False) as store:
        return {source.doc_id: (source, store.read_object(source.sha256)) for source in store.sources()}


def test_authored_fixture_manifest_pins_strict_bytes_and_negative_obligations():
    manifest = load_json((FIXTURES / 'MANIFEST.json').read_bytes())
    listed = set()
    for item in manifest['fixtures']:
        raw = (FIXTURES / item['file']).read_bytes()
        listed.add(item['file'])
        assert len(raw) == item['bytes'] and hashlib.sha256(raw).hexdigest() == item['sha256']
        assert load_json(raw)['synthetic'] is True
        assert item['source_origin'] == 'authored-local' and item['source_uri'] is None
        doc = import_bytes(raw, now=NOW)
        assert doc.vulnerabilities == item['expected']['vulnerabilities']
        assert sum(edge.relation == 'vendor-remediation' for edge in doc.edges) == item['expected'][
            'remediation_edges']
        assert set(item['expected']['problems']) <= {problem.code for problem in doc.problems}
    assert listed == {path.name for path in FIXTURES.glob('advisory-*.json')}


def test_new_revision_without_product_evidence_removes_active_remediation_but_retains_history(tmp_path):
    workspace = tmp_path / 'workspace'
    request('import', workspace, source=FIXTURES / 'advisory-v1.json')
    found = request('search', workspace, lead=CVE)
    investigation = found.data['investigation_id']
    (scope,) = found.data['scopes']
    request('search', workspace, lead=CVE, investigation_id=investigation, scope_id=scope['scope_id'])
    with WorkspaceStore(workspace) as store:
        previous = store.current_revision(investigation)
    original = stored_raw(workspace)
    request('import', workspace, source=FIXTURES / 'advisory-v2-missing-product.json')
    fresh = request('search', workspace, lead=CVE)
    assert fresh.data['edges'] == [] and fresh.data['disputed'] == []
    assert fresh.data['investigation_id'] != investigation
    with WorkspaceStore(workspace, create=False) as store:
        assert store.current_revision(investigation) == previous
        index = store.load_index()
        old_id, = original
        assert old_id not in index.active_ids()
        lookup = index.lookup_cve(CVE, now=NOW)
        assert lookup.edges == ()
        assert {edge.ref.doc_id for edge in lookup.superseded} == {old_id}
        assert any(problem.code == 'UNKNOWN_PRODUCT_ID' for doc in index.documents
                   if doc.doc_id in index.active_ids() for problem in doc.problems)
    after = stored_raw(workspace)
    assert len(after) == 2 and after[old_id] == original[old_id]
    assert all(hashlib.sha256(raw).hexdigest() == source.sha256 for source, raw in after.values())


def test_stale_search_persists_new_coverage_without_refreshing_source_or_old_receipt(tmp_path):
    workspace, clock = tmp_path / 'workspace', Clock()
    request('import', workspace, clock=clock, source=FIXTURES / 'advisory-v1.json')
    first = request('search', workspace, clock=clock, lead=KB)
    original = stored_raw(workspace)
    old_coverage = first.data['coverage']['detail']['coverage_id']
    assert first.data['coverage']['state'] == 'complete_in_scope'
    clock.value = '2099-05-15T00:00:00Z'
    late = request('search', workspace, clock=clock, lead=KB, investigation_id=first.data['investigation_id'])
    assert late.data['coverage']['state'] == 'stale_cache'
    assert any(warning.startswith('STALE_CACHE') for warning in late.data['warnings'])
    assert late.data['edges'] == first.data['edges']  # stale documentary facts stay visible with the warning
    assert stored_raw(workspace) == original
    with WorkspaceStore(workspace, create=False, clock=clock) as store:
        assert store.get_coverage(old_coverage).state == 'complete_in_scope'
        revision = store.current_revision(first.data['investigation_id'])
        assert revision.coverage_ids != (old_coverage,)
        assert store.get_coverage(revision.coverage_ids[0]).state == 'stale_cache'
        assert all(source.retrieved_at == NOW for source in store.sources())


def test_ambiguous_type2_kb_text_stays_mention_only_after_workspace_reopen(tmp_path):
    workspace = tmp_path / 'workspace'
    request('import', workspace, source=FIXTURES / 'advisory-ambiguous-kb.json')
    before = stored_raw(workspace)
    for kb in (KB, 'KB5099552'):
        outcome = request('search', workspace, lead=kb)
        assert outcome.data['edges'] == []
        assert {edge['cve'] for edge in outcome.data['mention_only']} == {'CVE-2099-70002'}
        assert all(edge['relation'] == 'mention-only' for edge in outcome.data['mention_only'])
        for edge in outcome.data['mention_only']:
            assert edge['ref']['doc_id'] in before
            assert edge['ref']['pointer'] == '/vulnerabilities/0/remediations/0'
    assert stored_raw(workspace) == before


def test_failed_fake_refresh_preserves_prior_source_investigation_and_search(tmp_path):
    workspace = tmp_path / 'workspace'
    request('import', workspace, source=FIXTURES / 'advisory-v1.json')
    first = request('search', workspace, lead=KB)
    investigation = first.data['investigation_id']
    original = stored_raw(workspace)
    with WorkspaceStore(workspace) as store:
        revision = store.current_revision(investigation)
    plan = net_plan.build_plan(['2099-Feb'])
    calls = []

    def unavailable(method, url, headers, timeout):
        calls.append((method, url))
        raise ConnectionError('authored offline transport failure')

    output = io.StringIO()
    ports = cli_online.OnlinePorts(IndexPorts(clock=Clock()), {'opener': unavailable, 'sleep': lambda *args: None})
    code = cli_online.main(['--workspace', str(workspace), '--json', '--months', '2099-Feb',
                            '--consent-hosts', ','.join(plan.hosts), '--consent-plan', plan.plan_sha],
                           ports=ports, stdout=output)
    receipt = load_json(output.getvalue().encode())
    assert code == 3 and receipt['status'] == 'partial'
    assert receipt['result']['index_changed'] is False
    assert receipt['result']['months'][0]['state'] == 'failed'
    assert calls and {url for _, url in calls} == {plan.requests[0].url}
    assert stored_raw(workspace) == original
    with WorkspaceStore(workspace, create=False) as store:
        assert store.current_revision(investigation) == revision
    again = request('search', workspace, lead=KB)
    assert again.data['edges'] == first.data['edges']
    assert not list(tmp_path.rglob('project.sqlite3'))
