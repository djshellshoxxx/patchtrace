"""Acquisition completion recovery from c3868d8335a8f32f676905032dc1a6d0e9f22fd6.

Synthetic records and PE bytes, fake transport, denied sockets. These controls
exercise real local stores and project attachment, not live provider qualification.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import test_kbc_acquire_cli as acquire_cli
from kbc_k1_support import no_sockets  # noqa: F401
from kbc_k3_support import FixedClock
from test_kbc_acquire_cli import HOSTS, SHA_N, SHA_O, plan_of

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.store import WorkspaceStore
from patchtrace.sample import synthetic_pe

pytestmark = pytest.mark.usefixtures('no_sockets')
ready = acquire_cli.ready
staging_root = acquire_cli.staging_root


@pytest.mark.parametrize('previous_selection', [None, 'arm64', 'amd64'])
def test_acquisition_attaches_the_previewed_product_and_retains_pair_binding(ready, staging_root,
                                                                           previous_selection):
    kb, _server, inv, flags, project = ready
    scope = flags[1]
    if previous_selection:
        code, products, _ = kb('products', inv)
        assert code == 0
        other = next(p['scope_id'] for p in products['result']['products'] if p['architecture'] == previous_selection)
        code, _ = kb.search('CVE-2099-20001', '--investigation', inv, '--product', other)
        assert code == 0
    preview = plan_of(kb, inv, flags, project)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                     '--consent-plan', preview['plan_sha'])
    assert code == 0, doc
    with WorkspaceStore(kb.workspace) as ws:
        rev = ws.current_revision(inv)
        decisions = ws.decisions(inv)
    assert rev.selected_scope_id == scope
    svc = wiring.build_service(kb.workspace, clock=FixedClock())
    bundle = svc._project_bundles(str(project))[-1]
    assert bundle.scope_id == scope
    assert bundle.older_sha == SHA_O and bundle.newer_sha == SHA_N
    assert doc['result']['pair']['grade'] == 'B'
    assert doc['result']['pair']['tier'] == 'E'
    assert doc['result']['pair']['fix_boundary'] == 'unverified'
    assert doc['result']['pair']['lineage_state'] == 'user-asserted'
    assert doc['result']['pair']['pair_id'] != preview['pair_id']
    acquisition = doc['result']['acquisition']
    assert acquisition['source_pair_id'] == preview['pair_id']
    assert acquisition['verified_pair_id'] == bundle.pair_id == rev.selected_pair_id
    assert acquisition['scope_id'] == scope
    binding = next(d for d in decisions if d.op == 'acquisition-pair-binding')
    assert binding.prior == preview['pair_id'] and binding.next == bundle.pair_id
    assert all(value in binding.reason for value in (preview['plan_sha'], scope, SHA_O, SHA_N))
    assert not any(staging_root.iterdir())


@pytest.mark.parametrize('changed_product', [False, True])
def test_acquisition_rejects_a_revision_changed_during_staging_without_clobber(ready, staging_root, monkeypatch,
                                                                           changed_product):
    kb, _server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    svc = wiring.build_service(kb.workspace, clock=FixedClock())
    original = kb.env.acquirer.stage
    committed = {}

    def changed(_self, *args, **kwargs):
        staged = original(*args, **kwargs)
        with WorkspaceStore(kb.workspace) as ws:
            rev = ws.current_revision(inv)
        scope = flags[1]
        if changed_product:
            products = svc.products(inv).result['products']
            scope = next(p['scope_id'] for p in products if p['architecture'] == 'arm64')
        svc.search('CVE-2099-20001', product=scope, investigation=inv)
        with WorkspaceStore(kb.workspace) as ws:
            committed['revision'] = ws.current_revision(inv)
            committed['history'] = ws.revisions(inv)
            committed['decisions'] = ws.decisions(inv)
            committed['journal'] = tuple(ws.db.execute('SELECT * FROM journal'))
        assert committed['revision'].revision > rev.revision
        return staged

    monkeypatch.setattr(type(kb.env.acquirer), 'stage', changed)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                     '--consent-plan', preview['plan_sha'])
    assert code == 3 and 'PT-KBC-STALE' in doc['error']
    assert not project.exists() and not any(staging_root.iterdir())
    with WorkspaceStore(kb.workspace) as ws:
        assert ws.current_revision(inv) == committed['revision']
        assert ws.revisions(inv) == committed['history']
        assert ws.decisions(inv) == committed['decisions']
        assert tuple(ws.db.execute('SELECT * FROM journal')) == committed['journal']


@pytest.mark.parametrize('side', ['older', 'newer'])
def test_acquisition_rehash_refuses_staged_path_changed_after_verification(ready, staging_root, monkeypatch, side):
    kb, _server, inv, flags, project = ready
    preview = plan_of(kb, inv, flags, project)
    with WorkspaceStore(kb.workspace) as ws:
        before, history, decisions = ws.current_revision(inv), ws.revisions(inv), ws.decisions(inv)
    original = kb.env.acquirer.stage

    def changed(_self, *args, **kwargs):
        staged = original(*args, **kwargs)
        path = Path(getattr(staged, f'{side}_path'))
        path.chmod(0o600)
        path.write_bytes(synthetic_pe(7))
        return staged

    monkeypatch.setattr(type(kb.env.acquirer), 'stage', changed)
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags, '--consent-hosts', HOSTS,
                     '--consent-plan', preview['plan_sha'])
    assert code == 3 and 'PT-KBC-VERIFY' in doc['error']
    assert not project.exists() and not any(staging_root.iterdir())
    with WorkspaceStore(kb.workspace) as ws:
        assert ws.current_revision(inv) == before
        assert ws.revisions(inv) == history and ws.decisions(inv) == decisions
