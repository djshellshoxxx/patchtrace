"""Offline retained-source replay through the production CLI; synthetic inputs, sockets denied."""
from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import replace

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_acquire_cli import ready as ready
from test_kbc_raw_index_acquisition import complete, stored

from patchtrace.kbcorrelation import cli, wiring
from patchtrace.kbcorrelation.acquisition_evidence import AcquisitionSource, canonical, plan_digest
from patchtrace.kbcorrelation.contracts import domain_id
from patchtrace.sample import synthetic_pe
from patchtrace.service import ProjectService

pytestmark = pytest.mark.usefixtures('no_sockets')


def replay(kb, project, evidence_id, **kwargs):
    return kb('acquisition', 'replay', '--project', str(project), '--evidence', evidence_id, **kwargs)


def sidecars(project):
    return {path.relative_to(project).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (project / 'kb').rglob('*') if path.is_file()}


def test_cli_reproduces_source_without_mutable_workspace_or_network(ready):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    before, calls = sidecars(project), tuple(server.calls)
    with ProjectService.open(project, maintenance=False) as service:
        revision = service.project.revision
    shutil.rmtree(kb.workspace)
    kb.env = replace(kb.env, file_index=lambda *_: pytest.fail('replay consulted the mutable index'),
                     acquirer=None)
    code, doc, err = replay(kb, project, evidence.evidence_id)
    assert code == 0 and doc['status'] == 'complete' and not err
    result = doc['result']
    assert result['state'] == 'reproduced'
    assert result['evidence_id'] == evidence.evidence_id
    assert result['source_sha256'] == evidence.source.replay.source.sha256
    assert result['source_pair_id'] == evidence.source.proposal.pair_id
    assert result['older']['pointer'] == evidence.source.replay.older.pointer
    assert result['newer']['pointer'] == evidence.source.replay.newer.pointer
    assert result['skipped_rows'] == sum((evidence.source.replay.parser_skipped,
                                        evidence.source.replay.parser_skipped_bodies,
                                        evidence.source.replay.conversion_rejected))
    assert sidecars(project) == before and tuple(server.calls) == calls and not kb.workspace.exists()
    with ProjectService.open(project, maintenance=False) as service:
        assert service.project.revision == revision


def test_backup_is_sufficient_for_offline_raw_source_replay(ready, tmp_path):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    destination = tmp_path / 'backup'
    with ProjectService.open(project, maintenance=False) as service:
        service.store.backup(destination)
        originals = [project / artifact.relative_path for artifact in service.project.artifacts]
    source = evidence.source.replay.source
    assert (destination / source.relative_path).read_bytes() == (project / source.relative_path).read_bytes()
    calls = tuple(server.calls)
    shutil.rmtree(kb.workspace)
    # Windows requires the write bit before unlinking immutable fixture artifacts.
    for artifact in originals:
        artifact.chmod(0o600)
    shutil.rmtree(project)
    assert not project.exists()
    code, doc, _ = replay(kb, destination, evidence.evidence_id)
    assert code == 0 and doc['result']['state'] == 'reproduced'
    assert tuple(server.calls) == calls and not kb.workspace.exists()


def test_legacy_evidence_reports_missing_capability_without_inventing_provenance(ready, monkeypatch):
    kb, _server, _inv, _flags, project = ready
    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'capture', None)
    assert complete(ready)[0] == 0
    evidence = stored(project)
    assert evidence.evidence_version == 1 and evidence.source.replay is None
    before = sidecars(project)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 4 and doc['status'] == 'unavailable'
    assert doc['result']['state'] == 'unavailable'
    assert 'not retained' in doc['result']['reason']
    assert sidecars(project) == before


@pytest.mark.parametrize('problem', ['missing-source', 'damaged-source', 'damaged-evidence'])
def test_missing_or_damaged_project_evidence_is_an_explicit_failure(ready, problem):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    source_path = project / evidence.source.replay.source.relative_path
    if problem == 'missing-source':
        source_path.unlink()
    elif problem == 'damaged-source':
        source_path.write_bytes(b'corrupted original source')
    else:
        (project / evidence.relative_path).write_bytes(b'{"duplicate": 1, "duplicate": 2}')
    before, calls = sidecars(project), tuple(server.calls)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 3 and doc['status'] == 'failed'
    assert ('PT-KBC-STORAGE' if problem == 'missing-source' else 'PT-KBC-VERIFY') in doc['error']
    assert sidecars(project) == before and tuple(server.calls) == calls


@pytest.mark.parametrize('problem', ['input-digest', 'result-digest', 'normalized-delivery'])
def test_internally_consistent_replacement_manifest_must_still_reproduce_raw_source(ready, problem):
    kb, _server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    original = stored(project)
    body = original.model_dump(mode='json')
    if problem == 'normalized-delivery':
        body['source']['older']['heading'] = 'different normalized source claim'
    else:
        field = 'mapping_sha256' if problem == 'input-digest' else 'resolution_sha256'
        body['source']['replay'][field] = 'f' * 64
    source = AcquisitionSource.model_validate_json(json.dumps(body['source']))
    body['plan_sha'] = plan_digest(source, body['hosts'], [(r['method'], r['target']) for r in body['requests']])
    body['evidence_id'] = domain_id('kbc.acquisition', body['evidence_version'],
                                    {key: value for key, value in body.items() if key != 'evidence_id'})
    path = project / 'kb' / 'acquisitions' / f'{body["evidence_id"]}.json'
    path.write_bytes(canonical(body))
    before = sidecars(project)
    code, doc, _ = replay(kb, project, body['evidence_id'])
    assert code == 3 and 'PT-KBC-VERIFY' in doc['error']
    assert sidecars(project) == before


@pytest.mark.parametrize('component', ['evidence', 'parser', 'lineage', 'resolver'])
def test_future_contract_is_reported_unsupported(ready, component):
    kb, _server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    body = evidence.model_dump(mode='json')
    if component == 'evidence':
        body['evidence_version'] = 99
    else:
        body['source']['replay']['source'][f'{component}_version'] = f'future-{component}/99'
    path = project / evidence.relative_path
    path.write_bytes(canonical(body))
    before = sidecars(project)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 2 and 'PT-KBC-UNSUPPORTED' in doc['error']
    assert sidecars(project) == before


@pytest.mark.parametrize('identifier', ['../source', 'A' * 64, 'a' * 63, 'a' * 64 + '\n'])
def test_identifier_admission_precedes_project_open(identifier, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(wiring.RealProjectPort, 'open_project', lambda *_: pytest.fail('invalid id reached project'))
    assert cli.main(['acquisition', 'replay', '--project', str(tmp_path / 'absent'),
                     '--evidence', identifier, '--json']) == 2
    assert 'PT-KBC-INPUT' in capsys.readouterr().out


def test_replay_help_does_not_construct_ports_or_services(monkeypatch, capsys):
    monkeypatch.setattr(cli.Context, '_env', lambda *_: pytest.fail('help initialized ports'))
    assert cli.main(['acquisition', 'replay', '--help']) == 0
    text = capsys.readouterr().out
    assert '--evidence' in text and '--project' in text and 'offline' in text.lower()


def test_plain_replay_output_explains_the_reproduced_claim(ready):
    kb, _server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    code, text, err = replay(kb, project, evidence.evidence_id, as_json=False)
    assert code == 0 and not err
    assert evidence.source.replay.source.sha256 in text
    assert evidence.source.proposal.pair_id in text and 'reproduced' in text.lower()


def test_valid_retained_evidence_cannot_be_replayed_as_another_project_pair(ready, tmp_path):
    kb, _server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    older, newer = tmp_path / 'old.sys', tmp_path / 'new.sys'
    older.write_bytes(synthetic_pe(4))
    newer.write_bytes(synthetic_pe(5))
    foreign = tmp_path / 'different-project'
    with ProjectService.create(older, newer, 'Different pair', foreign):
        pass
    shutil.copytree(project / 'kb', foreign / 'kb')
    before = sidecars(foreign)
    code, doc, _ = replay(kb, foreign, evidence.evidence_id)
    assert code == 3 and 'PT-KBC-VERIFY' in doc['error']
    assert sidecars(foreign) == before
