"""Independent controls for captured acquisition claims and pre-attachment receipt admission."""
from __future__ import annotations

from dataclasses import replace

import pytest
import test_kbc_acquire_cli as cli_fixture
from kbc_k1_support import no_sockets  # noqa: F401

from patchtrace.kbcorrelation.acquisition_evidence import read_evidence
from patchtrace.kbcorrelation.store import WorkspaceStore

pytestmark = pytest.mark.usefixtures('no_sockets')
ready = cli_fixture.ready
staging_root = cli_fixture.staging_root


def _state(kb, investigation):
    with WorkspaceStore(kb.workspace) as store:
        return (store.revisions(investigation), store.decisions(investigation),
                store.attempts(investigation), store.journal_ops())


def _execute(kb, investigation, flags, project, preview):
    return kb('acquire', investigation, '--project', str(project), *flags,
              '--consent-hosts', cli_fixture.HOSTS, '--consent-plan', preview['plan_sha'])


def test_port_mutations_of_received_rows_cannot_rewrite_approved_source(ready, staging_root):
    kb, _server, investigation, flags, project = ready
    delegate = kb.env.acquirer
    mutations = []

    class MutatingPort:
        def plan(self, older, newer):
            planned = delegate.plan(older, newer)
            older['heading'] = 'Authored port planning mutation'
            older['other_versions'].append('port-plan-only')
            mutations.append('plan')
            return planned

        def stage(self, older, newer, **kwargs):
            staged = delegate.stage(older, newer, **kwargs)
            newer['heading'] = 'Authored port staging mutation'
            newer['other_versions'].append('port-stage-only')
            mutations.append('stage')
            return staged

    kb.env = replace(kb.env, acquirer=MutatingPort())
    preview = cli_fixture.plan_of(kb, investigation, flags, project)
    approved_source = preview['source']
    code, result, _ = _execute(kb, investigation, flags, project, preview)
    assert code == 0, result
    record_path = project / result['result']['acquisition']['evidence_path']
    evidence = read_evidence(record_path.read_bytes())
    assert evidence.source.model_dump(mode='json') == approved_source
    assert 'plan' in mutations and 'stage' in mutations
    assert evidence.verified_pair.fix_boundary == 'unverified'
    assert not any(staging_root.iterdir())


@pytest.mark.parametrize('changed_field, replacement', [
    ('winbindex_record_sha256', 'a' * 64),
    ('source_url', 'https://example.invalid/unapproved'),
])
def test_valid_file_bytes_with_inconsistent_receipt_create_no_attachment(
        ready, staging_root, changed_field, replacement):
    kb, server, investigation, flags, project = ready
    delegate = kb.env.acquirer

    class AlteredReceiptPort:
        def plan(self, *rows):
            return delegate.plan(*rows)

        def stage(self, *rows, **kwargs):
            staged = delegate.stage(*rows, **kwargs)
            provenance = staged.older.provenance.model_copy(update={changed_field: replacement})
            older = staged.older.model_copy(update={'provenance': provenance})
            return replace(staged, older=older)

    kb.env = replace(kb.env, acquirer=AlteredReceiptPort())
    preview = cli_fixture.plan_of(kb, investigation, flags, project)
    before = _state(kb, investigation)
    code, result, _ = _execute(kb, investigation, flags, project, preview)
    assert code == 3 and 'PT-KBC-VERIFY' in result['error']
    assert server.calls  # The authored transport really supplied both inspected PE byte sequences.
    assert _state(kb, investigation) == before
    assert not project.exists() and not any(staging_root.iterdir())


def test_repeated_preview_preserves_digest_and_has_no_persistence_effect(ready):
    kb, server, investigation, flags, project = ready
    before = _state(kb, investigation)
    first = cli_fixture.plan_of(kb, investigation, flags, project)
    second = cli_fixture.plan_of(kb, investigation, flags, project)
    assert first == second
    first['source']['older']['other_versions'].append('caller-only')
    first['source']['proposal']['window'].append('KB5999999')
    third = cli_fixture.plan_of(kb, investigation, flags, project)
    assert third == second
    assert _state(kb, investigation) == before
    assert server.calls == [] and not project.exists()
